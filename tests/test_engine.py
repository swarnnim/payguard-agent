import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agent.engine import (Agent, Decision, PaymentRequest, PaymentState,
                          PayPalSandboxClient, ReceiptLog, LocalSigner,
                          PaymentIntent, RiskGuard, RiskLimits, ScenarioFeed,
                          evaluate_request)


def _req(**kw):
    base = dict(id="T-1", payee="CloudHost Inc", amount=48.0, currency="USD",
                category="cloud_hosting", vendor_trust=0.95,
                due="due in 3 days", memo="test invoice",
                invoice_ref="T-INV-1", necessity=0.90)
    base.update(kw)
    return PaymentRequest(**base)


def test_feed_deterministic():
    a, b = ScenarioFeed().requests(), ScenarioFeed().requests()
    assert len(a) == 12
    assert [(r.id, r.payee, r.amount, r.invoice_ref) for r in a] == \
           [(r.id, r.payee, r.amount, r.invoice_ref) for r in b]


def test_brain_duplicate_skip_and_guard_duplicate_veto():
    paid = {"CH-2026-001"}
    dup = _req(invoice_ref="CH-2026-001")
    dec = evaluate_request(dup, paid)
    assert dec.action == "SKIP" and "duplicate" in dec.reason
    state = PaymentState(paid_invoice_refs={"T-INV-1"})
    ok, note, amt = RiskGuard(RiskLimits()).check(
        state, _req(), Decision("PAY", 0.95, "x"))
    assert not ok and "duplicate" in note and amt == 0.0


def test_per_transaction_cap_veto():
    state = PaymentState()
    ok, note, amt = RiskGuard(RiskLimits(max_per_tx=500.0)).check(
        state, _req(amount=900.0), Decision("PAY", 0.95, "x"))
    assert not ok and "per-transaction cap" in note and amt == 0.0


def test_daily_kill_switch_halts():
    state = PaymentState(spent_today=990.0)
    ok, note, amt = RiskGuard(RiskLimits(daily_cap=1000.0)).check(
        state, _req(amount=50.0), Decision("PAY", 0.95, "x"))
    assert not ok and state.halted and "KILL SWITCH" in note and amt == 0.0
    # once halted, everything is refused
    ok2, note2, _ = RiskGuard(RiskLimits()).check(
        state, _req(amount=10.0), Decision("PAY", 0.95, "x"))
    assert not ok2 and "HALTED" in note2


def test_untrusted_vendor_and_allowlist_veto():
    # brain escalates a very-low-trust vendor
    dec = evaluate_request(_req(payee="MysteryVendorXYZ", vendor_trust=0.15), set())
    assert dec.action == "ESCALATE" and "untrusted vendor" in dec.reason
    # guard vetoes a payee that is not on the allowlist, however good the score
    ok, note, amt = RiskGuard(RiskLimits()).check(
        PaymentState(), _req(payee="QuickShip Logistics"),
        Decision("PAY", 0.90, "x"))
    assert not ok and "allowlist veto" in note and amt == 0.0


def test_low_confidence_veto():
    ok, note, amt = RiskGuard(RiskLimits(min_confidence=0.60)).check(
        PaymentState(), _req(), Decision("PAY", 0.30, "weak"))
    assert not ok and "low-confidence veto" in note and amt == 0.0


def test_brain_overpriced_escalates():
    dec = evaluate_request(
        _req(payee="DesignPro Studio", amount=450.0,
             category="freelance_design", vendor_trust=0.85, necessity=0.60),
        set())
    assert dec.action == "ESCALATE" and "over-priced" in dec.reason


def test_audit_chain_detects_tamper():
    client = PayPalSandboxClient()
    res = client.pay(_req(), 48.0)
    log = ReceiptLog(LocalSigner())
    log.record(PaymentIntent(1, "REQ-01", "CloudHost Inc", 48.0, "USD",
                             "CH-2026-001", res["order_id"], "r", 1),
               res["order_id"], res["status"], res["mode"])
    assert log.verify_chain()
    log.receipts[0].intent["amount"] = 9999.0
    assert not log.verify_chain()


def test_mock_paypal_order_flow_completes():
    client = PayPalSandboxClient()
    assert client.mode == "SANDBOX_SIMULATED"
    order = client.create_order(_req(), 48.0)
    assert order["status"] == "CREATED" and order["id"]
    captured = client.capture_order(order["id"])
    assert captured["status"] == "COMPLETED"
    res = client.pay(_req(), 48.0)
    assert res["status"] == "COMPLETED" and res["order_id"]
    assert res["mode"] == "SANDBOX_SIMULATED"


def test_full_run_reproducible_and_audited():
    r1, r2 = Agent().run(), Agent().run()
    assert r1["requests_seen"] == 12
    assert r1["payments_executed"] == r2["payments_executed"] == 6
    assert r1["veto_count"] == len(r1["vetoes"]) == 6
    assert r1["total_spent"] == r2["total_spent"] == 303.0
    assert r1["halted"] is False
    assert r1["audit_chain_valid"] is True
    assert r1["paypal_mode"] == "SANDBOX_SIMULATED"
    # totals consistent: total spent equals the sum of receipt amounts
    receipt_total = round(sum(r["intent"]["amount"] for r in r1["receipts"]), 2)
    assert receipt_total == r1["total_spent"]
    assert all(r["status"] == "COMPLETED" for r in r1["receipts"])
    # every veto carries a human-readable reason, from brain or guard
    assert all(v["reason"] for v in r1["vetoes"])
    assert {v["source"] for v in r1["vetoes"]} == {"brain", "guard"}
