"""PayGuard Agent — AI payment agent prototype for the PayPal AI Hackathon
(Devpost, "Build What's Next with PayPal and AI").

Design (deliberately mirroring the Horizon Agent architecture): an autonomous
payment agent whose *brain* and *risk guard* are separate systems. The brain
proposes a payment decision for each invoice/bill request; a separate
RiskGuard can VETO the brain. Executed payments go through a PayPal Sandbox
adapter (Orders API v2 flow shape: create order -> capture), and each one
becomes a signed payment intent recorded in a hash-chained, tamper-evident
receipt log.

Honesty: this is a sandbox / simulation prototype. Offline by default — the
PayPal adapter runs against a deterministic mock transport and moves NO real
money. The real PayPal Sandbox API transport activates only when the caller
supplies their own PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET environment
variables (PayPal *sandbox* credentials — still test money, never production).
No credentials are hardcoded anywhere in this file.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.request
from dataclasses import dataclass, field, asdict

PAYPAL_SANDBOX_BASE_URL = "https://api-m.sandbox.paypal.com"

# Category reference prices (USD) used by the brain's price-fairness check:
# what a typical payment in that category *should* cost.
REFERENCE_PRICES = {
    "cloud_hosting": 50.0,
    "saas_tool": 30.0,
    "utilities": 120.0,
    "office_supplies": 40.0,
    "freelance_design": 200.0,
    "hardware": 300.0,
    "logistics": 100.0,
    "consulting": 150.0,
    "software_license": 1000.0,
    "data_backup": 50.0,
    "printing": 30.0,
}

# Payees the guard is willing to pay at all. Anyone else is vetoed, however
# good the brain's score looks — the allowlist is a guard concern, not a
# brain concern, on purpose.
DEFAULT_ALLOWLIST = frozenset({
    "CloudHost Inc",
    "Acme SaaS",
    "City Power Utility",
    "OfficeMart",
    "DesignPro Studio",
    "ServerParts Co",
    "DataBackup Co",
    "PrintHouse",
    "Vague Consulting LLC",
    "MysteryVendorXYZ",
})


# ------------------------------------------------------------- payment feed
@dataclass
class PaymentRequest:
    id: str
    payee: str
    amount: float
    currency: str
    category: str
    vendor_trust: float      # 0..1, known history with this vendor
    due: str                 # human due info, e.g. "due in 3 days"
    memo: str
    invoice_ref: str         # vendor invoice number — duplicate key
    necessity: float         # 0..1, how necessary the purchase is


class ScenarioFeed:
    """Deterministic scenario feed of payment requests: a mix of legit
    bills, a duplicate invoice, an over-priced quote, an untrusted vendor,
    a budget-busting purchase and a non-allowlisted payee, so the demo and
    tests are reproducible offline."""

    def requests(self) -> list[PaymentRequest]:
        R = PaymentRequest
        return [
            R("REQ-01", "CloudHost Inc", 48.0, "USD", "cloud_hosting", 0.95,
              "due in 3 days", "November hosting invoice", "CH-2026-001", 0.90),
            R("REQ-02", "Acme SaaS", 29.0, "USD", "saas_tool", 0.90,
              "due in 5 days", "Team plan renewal", "ACME-101", 0.80),
            R("REQ-03", "CloudHost Inc", 48.0, "USD", "cloud_hosting", 0.95,
              "due in 3 days", "Same hosting invoice re-sent by vendor",
              "CH-2026-001", 0.90),  # duplicate of REQ-01
            R("REQ-04", "DesignPro Studio", 450.0, "USD", "freelance_design", 0.85,
              "due in 10 days", "Logo refresh quote — 2.25x the going rate",
              "DP-450", 0.60),  # over-priced
            R("REQ-05", "MysteryVendorXYZ", 180.0, "USD", "hardware", 0.15,
              "due today", "Unsolicited 'discount server' offer",
              "MV-001", 0.50),  # untrusted vendor
            R("REQ-06", "ServerParts Co", 900.0, "USD", "software_license", 0.92,
              "due in 14 days", "Annual license — fairly priced but huge",
              "SP-900", 0.90),  # budget-busting: brain says PAY, guard caps it
            R("REQ-07", "City Power Utility", 118.0, "USD", "utilities", 0.98,
              "due in 2 days", "October electricity bill", "CPU-7781", 0.95),
            R("REQ-08", "OfficeMart", 38.0, "USD", "office_supplies", 0.88,
              "due in 7 days", "Restock paper and toner", "OM-2210", 0.75),
            R("REQ-09", "Vague Consulting LLC", 140.0, "USD", "consulting", 0.50,
              "no due date given", "Unspecified 'advisory' — unclear necessity",
              "VC-014", 0.35),  # low necessity/trust -> low confidence
            R("REQ-10", "DataBackup Co", 45.0, "USD", "data_backup", 0.92,
              "due in 4 days", "Monthly backup plan", "DB-309", 0.85),
            R("REQ-11", "QuickShip Logistics", 90.0, "USD", "logistics", 0.80,
              "due in 3 days", "Courier for demo hardware",
              "QS-090", 0.80),  # fine score, but NOT on the payee allowlist
            R("REQ-12", "PrintHouse", 25.0, "USD", "printing", 0.86,
              "due in 6 days", "Demo-day posters", "PH-118", 0.70),
        ]


# ------------------------------------------------------------------- brain
@dataclass
class Decision:
    action: str            # PAY | SKIP | ESCALATE
    confidence: float      # 0..1
    reason: str


def _price_score(amount: float, category: str) -> float:
    ref = REFERENCE_PRICES.get(category)
    if ref is None or ref <= 0:
        return 0.5
    ratio = amount / ref
    if ratio <= 1.0:
        return 1.0
    if ratio <= 1.25:
        return 0.8
    if ratio <= 1.5:
        return 0.6
    if ratio <= 2.0:
        return 0.35
    return 0.1


def evaluate_request(req: PaymentRequest, paid_invoice_refs: set) -> Decision:
    """The explainable brain. Scores value/necessity, vendor trust and price
    fairness against the category reference price, and checks for duplicate
    invoices. Every decision carries the human-readable reason a judge (or
    user) can audit — no black box, like Horizon's Signal."""
    if req.invoice_ref in paid_invoice_refs:
        return Decision("SKIP", 0.97,
                        f"duplicate: invoice {req.invoice_ref} already paid")
    ref = REFERENCE_PRICES.get(req.category, 0.0)
    ratio = (req.amount / ref) if ref else 1.0
    if req.vendor_trust < 0.30:
        return Decision("ESCALATE", 0.53,
                        f"untrusted vendor: trust {req.vendor_trust:.2f} < 0.30 "
                        f"for {req.payee} — human review required")
    if ratio > 2.0:
        return Decision("ESCALATE", round(0.35 * req.necessity
                                          + 0.35 * req.vendor_trust
                                          + 0.30 * _price_score(req.amount, req.category), 4),
                        f"over-priced: ${req.amount:.2f} is {ratio:.2f}x the "
                        f"${ref:.2f} reference for {req.category} — human review required")
    score = (0.35 * req.necessity
             + 0.35 * req.vendor_trust
             + 0.30 * _price_score(req.amount, req.category))
    reason = (f"score {score:.2f} = necessity {req.necessity:.2f} x0.35 + "
              f"trust {req.vendor_trust:.2f} x0.35 + price-fairness "
              f"{_price_score(req.amount, req.category):.2f} x0.30 "
              f"(${req.amount:.2f} vs ${ref:.2f} reference)")
    if score >= 0.60:
        return Decision("PAY", round(score, 4), reason)
    if score >= 0.45:
        return Decision("ESCALATE", round(score, 4),
                        reason + " — below PAY threshold, escalate to human")
    return Decision("SKIP", round(score, 4),
                    reason + " — too weak on necessity/trust/price, skip")


# ---------------------------------------------------------------- risk guard
@dataclass
class RiskLimits:
    max_per_tx: float = 500.0        # per-transaction cap (USD)
    daily_cap: float = 1000.0        # daily spend cap (USD) — kill switch
    min_confidence: float = 0.60     # brain-confidence floor
    allowlist: frozenset = field(default_factory=lambda: DEFAULT_ALLOWLIST)


@dataclass
class PaymentState:
    spent_today: float = 0.0
    halted: bool = False
    paid_invoice_refs: set = field(default_factory=set)


class RiskGuard:
    def __init__(self, limits: RiskLimits):
        self.limits = limits

    def check(self, state: PaymentState, req: PaymentRequest,
              dec: Decision) -> tuple[bool, str, float]:
        """Return (allowed, note, approved_amount). The guard can veto the
        brain — that separation is the core safety claim of the agent."""
        if state.halted:
            return False, "HALTED: daily-cap kill switch is on", 0.0
        if state.spent_today >= self.limits.daily_cap:
            state.halted = True
            return False, (f"KILL SWITCH: spent ${state.spent_today:.2f} already "
                           f"at/over daily cap ${self.limits.daily_cap:.2f}"), 0.0
        if req.invoice_ref in state.paid_invoice_refs:
            return False, f"duplicate-payment veto: invoice {req.invoice_ref} already paid", 0.0
        if req.amount > self.limits.max_per_tx:
            return False, (f"per-transaction cap veto: ${req.amount:.2f} > "
                           f"${self.limits.max_per_tx:.2f} cap"), 0.0
        if state.spent_today + req.amount > self.limits.daily_cap:
            state.halted = True
            return False, (f"KILL SWITCH: paying ${req.amount:.2f} would take daily spend "
                           f"${state.spent_today:.2f} over the ${self.limits.daily_cap:.2f} "
                           f"daily cap — agent halted"), 0.0
        if req.payee not in self.limits.allowlist:
            return False, f"allowlist veto: payee '{req.payee}' is not on the allowlist", 0.0
        if dec.action != "PAY" or dec.confidence < self.limits.min_confidence:
            return False, (f"low-confidence veto: brain action {dec.action} at confidence "
                           f"{dec.confidence:.2f} < floor {self.limits.min_confidence:.2f}"), 0.0
        return True, "within per-tx cap, daily cap, allowlist and confidence floor", req.amount


# ------------------------------------------------------- PayPal sandbox API
_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _sandbox_id(seed_text: str, length: int = 17) -> str:
    """Deterministic PayPal-style id (17 uppercase alphanumerics) from a hash."""
    digest = hashlib.sha256(seed_text.encode()).digest()
    return "".join(_ALNUM[b % len(_ALNUM)] for b in digest[:length])


class MockTransport:
    """Offline stand-in for the PayPal Sandbox REST API. Returns realistic
    sandbox-style payloads deterministically; no network, no money."""

    def __init__(self):
        self.counter = 0

    def send(self, path: str, payload: dict) -> dict:
        self.counter += 1
        if path.endswith("/v2/checkout/orders"):
            unit = payload["purchase_units"][0]
            order_id = _sandbox_id(f"order:{self.counter}:{json.dumps(payload, sort_keys=True)}")
            return {"id": order_id, "status": "CREATED", "intent": "CAPTURE",
                    "purchase_units": [{"reference_id": unit.get("reference_id", "default"),
                                         "amount": unit["amount"]}]}
        if "/capture" in path:
            order_id = path.split("/")[-2]
            capture_id = _sandbox_id(f"capture:{self.counter}:{order_id}")
            return {"id": order_id, "status": "COMPLETED",
                    "purchase_units": [{"payments": {"captures": [
                        {"id": capture_id, "status": "COMPLETED"}]}}]}
        raise ValueError(f"MockTransport: unknown path {path}")


class UrllibTransport:
    """Real PayPal *Sandbox* API transport (urllib only). Used only when the
    caller supplies their own sandbox credentials via environment variables.
    Sandbox money is test money — this never points at production."""

    def __init__(self, client_id: str, client_secret: str,
                 base_url: str = PAYPAL_SANDBOX_BASE_URL):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url
        self._token = None

    def _access_token(self) -> str:
        if self._token:
            return self._token
        basic = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode()).decode()
        req = urllib.request.Request(
            self.base_url + "/v1/oauth2/token",
            data=b"grant_type=client_credentials", method="POST",
            headers={"Authorization": f"Basic {basic}",
                     "Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            self._token = json.loads(resp.read())["access_token"]
        return self._token

    def send(self, path: str, payload: dict) -> dict:
        req = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(payload).encode(), method="POST",
            headers={"Authorization": f"Bearer {self._access_token()}",
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())


class PayPalSandboxClient:
    """PayPal Orders API v2 flow shape: create order -> capture order.

    Default mode is the offline MockTransport (mode SANDBOX_SIMULATED).
    If PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET are set in the environment,
    the real sandbox API is used instead (mode SANDBOX_API). Credentials are
    read from the environment only — never hardcoded, never logged."""

    def __init__(self, transport=None):
        if transport is not None:
            self.transport = transport
            self.mode = "SANDBOX_SIMULATED" if isinstance(transport, MockTransport) else "SANDBOX_API"
            return
        client_id = os.environ.get("PAYPAL_CLIENT_ID")
        client_secret = os.environ.get("PAYPAL_CLIENT_SECRET")
        if client_id and client_secret:
            self.transport = UrllibTransport(client_id, client_secret)
            self.mode = "SANDBOX_API"
        else:
            self.transport = MockTransport()
            self.mode = "SANDBOX_SIMULATED"

    def create_order(self, req: PaymentRequest, amount: float) -> dict:
        payload = {
            "intent": "CAPTURE",
            "purchase_units": [{
                "reference_id": req.invoice_ref,
                "description": f"{req.memo} (payee: {req.payee})",
                "amount": {"currency_code": req.currency,
                           "value": f"{amount:.2f}"},
            }],
        }
        return self.transport.send("/v2/checkout/orders", payload)

    def capture_order(self, order_id: str) -> dict:
        return self.transport.send(f"/v2/checkout/orders/{order_id}/capture", {})

    def pay(self, req: PaymentRequest, amount: float) -> dict:
        """Full create -> capture flow. Returns the receipt facts."""
        order = self.create_order(req, amount)
        captured = self.capture_order(order["id"])
        capture_id = None
        try:
            capture_id = (captured["purchase_units"][0]["payments"]
                          ["captures"][0]["id"])
        except (KeyError, IndexError, TypeError):
            capture_id = None
        return {"order_id": order["id"], "capture_id": capture_id,
                "status": captured.get("status", "UNKNOWN"), "mode": self.mode}


# ------------------------------------------------------- signing + receipts
class LocalSigner:
    """Offline HMAC signer (same pattern as Horizon's LocalSigner). A live
    version replaces this with a real key store / wallet signature; the
    intent format stays identical."""

    def __init__(self, secret: str = "demo-only-not-a-real-key"):
        self.secret = secret.encode()

    def sign(self, intent: dict) -> str:
        blob = json.dumps(intent, sort_keys=True).encode()
        return hmac.new(self.secret, blob, hashlib.sha256).hexdigest()


@dataclass
class PaymentIntent:
    nonce: int
    request_id: str
    payee: str
    amount: float
    currency: str
    invoice_ref: str
    paypal_order_id: str
    reason: str
    ts: int


@dataclass
class Receipt:
    intent: dict
    signature: str
    receipt_hash: str
    paypal_order_id: str
    status: str = "COMPLETED"          # PayPal capture status
    mode: str = "SANDBOX_SIMULATED"    # SANDBOX_SIMULATED | SANDBOX_API


class ReceiptLog:
    """Append-only audit log; each receipt chains to the previous hash so
    tampering with history is detectable."""

    def __init__(self, signer: LocalSigner):
        self.signer = signer
        self.receipts: list[Receipt] = []
        self.prev_hash = "GENESIS"

    def record(self, intent: PaymentIntent, paypal_order_id: str,
               status: str, mode: str) -> Receipt:
        d = asdict(intent)
        sig = self.signer.sign(d)
        h = hashlib.sha256((self.prev_hash + sig).encode()).hexdigest()
        r = Receipt(d, sig, h, paypal_order_id, status, mode)
        self.receipts.append(r)
        self.prev_hash = h
        return r

    def verify_chain(self) -> bool:
        prev = "GENESIS"
        for r in self.receipts:
            if self.signer.sign(r.intent) != r.signature:
                return False
            h = hashlib.sha256((prev + r.signature).encode()).hexdigest()
            if r.receipt_hash != h:
                return False
            prev = h
        return True


# ---------------------------------------------------------------------- agent
@dataclass
class Agent:
    feed: ScenarioFeed = field(default_factory=ScenarioFeed)
    risk: RiskGuard = field(default_factory=lambda: RiskGuard(RiskLimits()))
    state: PaymentState = field(default_factory=PaymentState)
    paypal: PayPalSandboxClient = field(default_factory=PayPalSandboxClient)
    log: ReceiptLog = field(default_factory=lambda: ReceiptLog(LocalSigner()))
    nonce: int = 0

    def run(self) -> dict:
        requests = self.feed.requests()
        vetoes: list[dict] = []
        t0 = 1_730_000_000  # deterministic timestamps, like Horizon's feed
        for req in requests:
            dec = evaluate_request(req, set(self.state.paid_invoice_refs))
            if dec.action != "PAY":
                vetoes.append({"request_id": req.id, "payee": req.payee,
                               "amount": req.amount, "source": "brain",
                               "action": dec.action, "reason": dec.reason})
                continue
            ok, note, approved = self.risk.check(self.state, req, dec)
            if not ok:
                vetoes.append({"request_id": req.id, "payee": req.payee,
                               "amount": req.amount, "source": "guard",
                               "action": "VETO", "reason": note})
                continue
            result = self.paypal.pay(req, approved)
            self.nonce += 1
            intent = PaymentIntent(self.nonce, req.id, req.payee,
                                   round(approved, 2), req.currency,
                                   req.invoice_ref, result["order_id"],
                                   dec.reason, t0 + self.nonce * 60)
            self.log.record(intent, result["order_id"], result["status"],
                            result["mode"])
            self.state.spent_today = round(self.state.spent_today + approved, 2)
            self.state.paid_invoice_refs.add(req.invoice_ref)
        return {
            "agent": "PayGuard Agent",
            "paypal_mode": self.paypal.mode,
            "requests_seen": len(requests),
            "payments_executed": len(self.log.receipts),
            "vetoes": vetoes,
            "veto_count": len(vetoes),
            "total_spent": round(self.state.spent_today, 2),
            "currency": "USD",
            "halted": self.state.halted,
            "audit_chain_valid": self.log.verify_chain(),
            "receipts": [asdict(r) for r in self.log.receipts],
        }


if __name__ == "__main__":
    t0 = time.time()
    report = Agent().run()
    print(json.dumps({k: v for k, v in report.items() if k != "receipts"}, indent=2))
    print(f"receipts: {len(report['receipts'])} (first order {report['receipts'][0]['paypal_order_id']})" if report["receipts"] else "receipts: 0")
    print(f"ran in {time.time()-t0:.2f}s, offline, $0")
