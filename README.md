# PayGuard Agent — an AI payment agent whose risk guard can veto it

**PayPal AI Hackathon (Devpost) — "Build What's Next with PayPal and AI"**
Builder: Swarnnim Agnihotri (solo) · Status: working offline prototype, 10/10 tests passing

## What it is
An autonomous payment agent that pays invoices and bills via PayPal — with its
*brain* and *risk guard* as separate systems: the brain proposes, the guard
disposes. Every executed payment goes through the PayPal Sandbox (Orders API
v2: create order → capture) and becomes a signed payment intent recorded in a
hash-chained, tamper-evident receipt log.

- **Brain (explainable):** scores each payment request on necessity, vendor
  trust, and price fairness against a per-category reference price, and
  detects duplicate invoices. Every decision (PAY / SKIP / ESCALATE) carries a
  human-readable reason string and a confidence score — no black-box payments.
- **Risk guard (can veto the brain):** $500 per-transaction cap, $1,000 daily
  spend cap with a **kill switch** that halts the agent when a payment would
  breach it, a payee allowlist, a minimum-confidence floor, and a
  duplicate-payment veto.
- **PayPal Sandbox integration:** a `PayPalSandboxClient` implementing the
  Orders API v2 flow shape (create order → capture). By default it runs
  against a deterministic offline mock transport returning realistic
  sandbox-style order IDs and COMPLETED captures (receipts record mode
  `SANDBOX_SIMULATED`). With real PayPal *sandbox* credentials in the
  environment it switches to the live sandbox API (`SANDBOX_API`) — see below.
- **Receipt log:** each intent is signed (HMAC, the offline stand-in for a
  real key store) and hash-chained to the previous receipt, so any tampering
  with payment history is detectable via `verify_chain()`.

## PayPal sandbox: mock by default, real sandbox with env vars
No credentials are hardcoded or needed for the demo. To run against the real
PayPal Sandbox API instead of the mock, create a sandbox app at
developer.paypal.com and set:

```bash
export PAYPAL_CLIENT_ID=<your sandbox client id>
export PAYPAL_CLIENT_SECRET=<your sandbox secret>
python3 agent/engine.py   # receipts now record mode SANDBOX_API
```

The client then OAuth-authenticates and calls
`https://api-m.sandbox.paypal.com` (`/v2/checkout/orders`, then `.../capture`).
Sandbox money is test money — this code never points at PayPal production.

## Run it
```bash
python3 agent/engine.py        # demo run: 12 scenario requests, prints report + receipts count
~/workspace/trading-bot/.venv/bin/python -m pytest tests/ -q   # 10 tests (or any pytest)
```
Demo result (deterministic scenario feed): 12 requests seen → **6 payments
executed** via PayPal sandbox (mock), **$303.00 total spent**, **6 stopped**
(duplicate invoice, over-priced quote at 2.25× reference, untrusted vendor,
per-transaction-cap veto on a $900 license, low-confidence escalation,
allowlist veto), agent not halted, audit chain valid.

The scenario feed is a deliberate mix: legit bills (hosting, SaaS, utilities,
office supplies, backup, printing) plus the failure cases above, so a judge
can watch the brain and the guard each stop the payments they own.

## Going live (next steps)
1. Feed real invoices (email/OCR/manual entry) into `PaymentRequest` instead
   of the deterministic `ScenarioFeed` — the brain/guard interfaces don't change.
2. Point the agent at a funded PayPal account via the production API with
   credentials in a secrets manager, behind the same RiskGuard limits.
3. Replace `LocalSigner` (HMAC demo) with a real key store; keep the
   hash-chained receipt log as the audit trail and surface ESCALATE decisions
   in a human approval queue.

## Honesty notes
Sandbox/simulation only in this build: deterministic scenario data, mock
PayPal transport by default, no real money, no real credentials. The AI here
is a transparent scoring model chosen for auditability — every decision can be
explained in one sentence, which is the point of the design.

## Pattern credit
The brain/guard separation, signed-intent + hash-chained receipt log, and
stdlib-only offline discipline reuse the architecture of the builder's
Horizon Agent (HashKey Chain Horizon Hackathon), re-targeted from trade
intents on a chain to payment intents on PayPal.
