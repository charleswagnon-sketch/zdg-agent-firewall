"""
PAY-01 — Stripe Payment Processing Integration suite.

Tests Stripe checkout, portal, and webhook flows with mocked Stripe SDK calls.
Internal licensing layer remains the source of truth after all sync operations.

Test coverage:
  PAY-001  _map_stripe_status — all Stripe statuses map to correct internal values
  PAY-002  _price_id_to_plan_code — known and unknown price IDs resolve correctly
  PAY-003  Checkout — admin token required (401 without token)
  PAY-004  Checkout — 404 on unknown account_id
  PAY-005  Checkout — returns checkout_url and session_id on success
  PAY-006  Checkout — 503 when Stripe is not configured
  PAY-007  Portal — admin token required (401 without token)
  PAY-008  Portal — 404 on unknown account_id
  PAY-009  Portal — 409 when account has no Stripe customer ID
  PAY-010  Portal — returns portal_url after Stripe subscription exists
  PAY-011  Webhook — 400 on missing Stripe-Signature header
  PAY-012  Webhook — 400 on invalid Stripe signature
  PAY-013  Webhook — 503 when STRIPE_WEBHOOK_SECRET not configured
  PAY-014  Webhook checkout.session.completed — activates license and seeds entitlements
  PAY-015  Webhook checkout.session.completed — idempotent on duplicate delivery
  PAY-016  Webhook customer.subscription.updated — updates license status and expires_at
  PAY-017  Webhook customer.subscription.updated — plan change re-seeds entitlements
  PAY-018  Webhook customer.subscription.deleted — expires license
  PAY-019  Webhook customer.subscription.deleted — idempotent if already expired
  PAY-020  Webhook invoice.payment_failed — records PAYMENT_FAILED event
  PAY-021  Internal licensing still enforces caps after webhook sync
  PAY-022  Billing endpoints require admin; webhook does not
"""
from __future__ import annotations

import types
from unittest.mock import MagicMock, patch

ADMIN = {"X-ZDG-Admin-Token": "integration-admin-token"}
STRIPE_SETTINGS = {
    "stripe_secret_key": "sk_test_testkey",
    "stripe_webhook_secret": "whsec_testsecret",
    "stripe_price_id_dev_monthly": "price_dev_monthly_test",
    "stripe_price_id_dev_annual": "price_dev_annual_test",
    "stripe_success_url": "http://localhost:8000/billing/success",
    "stripe_cancel_url": "http://localhost:8000/billing/cancel",
    "stripe_portal_return_url": "http://localhost:8000/billing",
}


# ── Event helpers ──────────────────────────────────────────────────────────────

def _make_checkout_event(
    subscription_id="sub_test_001",
    customer_id="cus_test_001",
    account_id=None,
    email="test@example.com",
    plan_code="dev_monthly",
):
    cs = types.SimpleNamespace(
        client_reference_id=account_id,
        customer=customer_id,
        subscription=subscription_id,
        customer_email=email,
        metadata={"plan_code": plan_code},
        payment_status="paid",
    )
    return types.SimpleNamespace(
        type="checkout.session.completed",
        id="evt_checkout_001",
        data=types.SimpleNamespace(object=cs),
    )


def _make_subscription_event(
    event_type="customer.subscription.updated",
    subscription_id="sub_test_001",
    customer_id="cus_test_001",
    status="active",
    current_period_end=2000000000,
    price_id="price_dev_monthly_test",
):
    sub = types.SimpleNamespace(
        id=subscription_id,
        customer=customer_id,
        status=status,
        current_period_end=current_period_end,
        items=types.SimpleNamespace(
            data=[types.SimpleNamespace(price=types.SimpleNamespace(id=price_id))]
        ),
    )
    return types.SimpleNamespace(
        type=event_type,
        id=f"evt_{event_type.replace('.', '_')}_001",
        data=types.SimpleNamespace(object=sub),
    )


def _make_invoice_event(subscription_id="sub_test_001", invoice_id="in_test_001"):
    inv = types.SimpleNamespace(id=invoice_id, subscription=subscription_id, status="open")
    return types.SimpleNamespace(
        type="invoice.payment_failed",
        id="evt_invoice_001",
        data=types.SimpleNamespace(object=inv),
    )


def _activate(client, *, plan_code="dev_monthly", email="dev@example.com"):
    """Helper: activate a license and return response JSON."""
    r = client.post("/v1/license/activate", json={
        "email": email,
        "plan_code": plan_code,
        "entitlements": [],
    }, headers=ADMIN)
    assert r.status_code == 201, f"activate failed: {r.status_code} {r.text}"
    return r.json()


def _post_webhook(client, event, *, sig="valid-sig"):
    """Helper: POST to /v1/billing/webhook with mocked signature verification."""
    with patch("core.stripe_sync.construct_webhook_event", return_value=event):
        return client.post(
            "/v1/billing/webhook",
            content=b'{"type":"test"}',
            headers={"Stripe-Signature": sig, "Content-Type": "application/json"},
        )


def _db_session():
    """Return a SQLModel Session for direct DB inspection in tests."""
    from sqlmodel import Session
    from db.sqlite import get_engine
    return Session(get_engine())


# ── PAY-001: _map_stripe_status ────────────────────────────────────────────────

def test_map_stripe_status_all_cases():
    """PAY-001: All Stripe statuses map to the correct internal license status."""
    from core.stripe_sync import _map_stripe_status

    assert _map_stripe_status("active") == "active"
    assert _map_stripe_status("trialing") == "trialing"
    assert _map_stripe_status("past_due") == "active"     # grace period
    assert _map_stripe_status("unpaid") == "expired"
    assert _map_stripe_status("canceled") == "expired"
    assert _map_stripe_status("incomplete") == "active"
    assert _map_stripe_status("incomplete_expired") == "expired"
    assert _map_stripe_status("paused") == "expired"
    assert _map_stripe_status("unknown_future_status") == "expired"  # safe default


# ── PAY-002: _price_id_to_plan_code ───────────────────────────────────────────

def test_price_id_to_plan_code():
    """PAY-002: Known price IDs resolve to plan codes; unknown returns None."""
    from core.stripe_sync import _price_id_to_plan_code

    settings = types.SimpleNamespace(
        stripe_price_id_dev_monthly="price_monthly",
        stripe_price_id_dev_annual="price_annual",
    )
    assert _price_id_to_plan_code("price_monthly", settings) == "dev_monthly"
    assert _price_id_to_plan_code("price_annual", settings) == "dev_annual"
    assert _price_id_to_plan_code("price_unknown", settings) is None
    assert _price_id_to_plan_code("", settings) is None


# ── PAY-003: Checkout auth required ───────────────────────────────────────────

def test_checkout_requires_admin(make_client):
    """PAY-003: Checkout endpoint requires admin token."""
    with make_client(**STRIPE_SETTINGS) as client:
        r = client.post("/v1/billing/checkout", json={"account_id": "acc_x", "plan_code": "dev_monthly"})
        assert r.status_code == 401


# ── PAY-004: Checkout 404 on unknown account ──────────────────────────────────

def test_checkout_404_on_unknown_account(make_client):
    """PAY-004: Checkout returns 404 when account_id is not found."""
    with make_client(**STRIPE_SETTINGS) as client:
        r = client.post("/v1/billing/checkout", headers=ADMIN, json={
            "account_id": "acc_does_not_exist",
            "plan_code": "dev_monthly",
        })
        assert r.status_code == 404


# ── PAY-005: Checkout success ─────────────────────────────────────────────────

def test_checkout_returns_url_and_session_id(make_client):
    """PAY-005: Checkout returns checkout_url and session_id on success."""
    mock_session = MagicMock()
    mock_session.url = "https://checkout.stripe.com/pay/cs_test_abc"
    mock_session.id = "cs_test_abc"

    with make_client(**STRIPE_SETTINGS) as client:
        activated = _activate(client)
        account_id = activated["account_id"]

        with patch("core.stripe_sync.create_checkout_session", return_value=mock_session):
            r = client.post("/v1/billing/checkout", headers=ADMIN, json={
                "account_id": account_id,
                "plan_code": "dev_monthly",
            })

        assert r.status_code == 200
        data = r.json()
        assert data["checkout_url"] == "https://checkout.stripe.com/pay/cs_test_abc"
        assert data["session_id"] == "cs_test_abc"


# ── PAY-006: Checkout 503 when Stripe unconfigured ────────────────────────────

def test_checkout_503_when_stripe_not_configured(make_client):
    """PAY-006: Checkout returns 503 when Stripe secret key is missing."""
    with make_client() as client:  # no STRIPE_SETTINGS
        activated = _activate(client)
        r = client.post("/v1/billing/checkout", headers=ADMIN, json={
            "account_id": activated["account_id"],
            "plan_code": "dev_monthly",
        })
        assert r.status_code == 503


# ── PAY-007: Portal auth required ─────────────────────────────────────────────

def test_portal_requires_admin(make_client):
    """PAY-007: Portal endpoint requires admin token."""
    with make_client(**STRIPE_SETTINGS) as client:
        r = client.post("/v1/billing/portal", json={"account_id": "acc_x"})
        assert r.status_code == 401


# ── PAY-008: Portal 404 on unknown account ────────────────────────────────────

def test_portal_404_on_unknown_account(make_client):
    """PAY-008: Portal returns 404 when account_id is not found."""
    with make_client(**STRIPE_SETTINGS) as client:
        r = client.post("/v1/billing/portal", headers=ADMIN, json={"account_id": "acc_nope"})
        assert r.status_code == 404


# ── PAY-009: Portal 409 without Stripe customer ───────────────────────────────

def test_portal_409_without_stripe_customer(make_client):
    """PAY-009: Portal returns 409 when account has no Stripe subscription yet."""
    with make_client(**STRIPE_SETTINGS) as client:
        activated = _activate(client)
        r = client.post("/v1/billing/portal", headers=ADMIN, json={
            "account_id": activated["account_id"],
        })
        assert r.status_code == 409
        assert "checkout" in r.json()["detail"]["reason"].lower()


# ── PAY-010: Portal success after Stripe subscription exists ──────────────────

def test_portal_returns_url_after_subscription(make_client):
    """PAY-010: Portal returns portal_url once account has stripe_customer_id."""
    mock_portal = MagicMock()
    mock_portal.url = "https://billing.stripe.com/p/session/test"

    with make_client(**STRIPE_SETTINGS) as client:
        activated = _activate(client)
        account_id = activated["account_id"]

        # Simulate webhook setting stripe_customer_id on the account
        event = _make_checkout_event(account_id=account_id, email="dev@example.com")
        _post_webhook(client, event)

        # Now portal should work
        with patch("core.stripe_sync.create_portal_session", return_value=mock_portal):
            r = client.post("/v1/billing/portal", headers=ADMIN, json={"account_id": account_id})

        assert r.status_code == 200
        assert r.json()["portal_url"] == "https://billing.stripe.com/p/session/test"


# ── PAY-011: Webhook missing signature ────────────────────────────────────────

def test_webhook_missing_signature(make_client):
    """PAY-011: Webhook returns 400 when Stripe-Signature header is missing."""
    with make_client(**STRIPE_SETTINGS) as client:
        r = client.post(
            "/v1/billing/webhook",
            content=b'{"type":"test"}',
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400
        assert "Stripe-Signature" in r.json()["detail"]["reason"]


# ── PAY-012: Webhook invalid signature ────────────────────────────────────────

def test_webhook_invalid_signature(make_client):
    """PAY-012: Webhook returns 400 on invalid Stripe signature."""
    from core.stripe_sync import StripeWebhookSignatureError

    with make_client(**STRIPE_SETTINGS) as client:
        with patch("core.stripe_sync.construct_webhook_event",
                   side_effect=StripeWebhookSignatureError("bad sig")):
            r = client.post(
                "/v1/billing/webhook",
                content=b'{"type":"test"}',
                headers={"Stripe-Signature": "invalid", "Content-Type": "application/json"},
            )
        assert r.status_code == 400
        assert "signature" in r.json()["detail"]["reason"].lower()


# ── PAY-013: Webhook 503 when secret not configured ───────────────────────────

def test_webhook_503_when_secret_not_configured(make_client):
    """PAY-013: Webhook returns 503 when STRIPE_WEBHOOK_SECRET is not configured."""
    with make_client() as client:  # no STRIPE_SETTINGS
        r = client.post(
            "/v1/billing/webhook",
            content=b'{"type":"test"}',
            headers={"Stripe-Signature": "sig", "Content-Type": "application/json"},
        )
        assert r.status_code == 503


# ── PAY-014: Webhook activates license on checkout completion ─────────────────

def test_webhook_checkout_activates_license(make_client):
    """PAY-014: checkout.session.completed creates a license with correct plan and seeds entitlements."""
    from sqlmodel import Session, select
    from db.models import Entitlement, License, LicenseAccount
    from db.sqlite import get_engine

    with make_client(**STRIPE_SETTINGS) as client:
        activated = _activate(client, email="buyer@example.com")
        account_id = activated["account_id"]

        event = _make_checkout_event(
            subscription_id="sub_new_001",
            customer_id="cus_new_001",
            account_id=account_id,
            email="buyer@example.com",
            plan_code="dev_monthly",
        )
        r = _post_webhook(client, event)
        assert r.status_code == 200
        data = r.json()
        assert data["received"] is True
        assert data["action"] == "license_activated"
        license_id = data["license_id"]

        with Session(get_engine()) as session:
            lic = session.exec(select(License).where(License.license_id == license_id)).first()
            assert lic is not None
            assert lic.plan_code == "dev_monthly"
            assert lic.status == "active"
            assert lic.stripe_subscription_id == "sub_new_001"

            acc = session.exec(select(LicenseAccount).where(LicenseAccount.account_id == account_id)).first()
            assert acc.stripe_customer_id == "cus_new_001"

            ents = session.exec(select(Entitlement).where(Entitlement.license_id == license_id)).all()
            assert len(ents) > 0
            feat_codes = {e.feature_code for e in ents}
            assert "debug_bundle_export" in feat_codes
            assert "max_monthly_runs" in feat_codes


# ── PAY-015: Webhook idempotent on duplicate checkout ─────────────────────────

def test_webhook_checkout_idempotent(make_client):
    """PAY-015: Duplicate checkout.session.completed delivery is safely ignored."""
    from sqlmodel import Session, func, select
    from db.models import License
    from db.sqlite import get_engine

    with make_client(**STRIPE_SETTINGS) as client:
        activated = _activate(client, email="buyer2@example.com")
        event = _make_checkout_event(
            subscription_id="sub_dup_001",
            account_id=activated["account_id"],
        )

        r1 = _post_webhook(client, event)
        assert r1.json()["action"] == "license_activated"

        r2 = _post_webhook(client, event)
        assert r2.status_code == 200
        assert r2.json()["action"] == "duplicate_skipped"

        with Session(get_engine()) as session:
            count = session.exec(
                select(func.count()).where(License.stripe_subscription_id == "sub_dup_001")
            ).one()
            assert count == 1


# ── PAY-016: Webhook subscription.updated syncs status and expires_at ─────────

def test_webhook_subscription_updated(make_client):
    """PAY-016: customer.subscription.updated syncs license status and expires_at."""
    from sqlmodel import Session, select
    from db.models import License
    from db.sqlite import get_engine

    with make_client(**STRIPE_SETTINGS) as client:
        activated = _activate(client, email="updater@example.com")
        checkout_event = _make_checkout_event(
            subscription_id="sub_upd_001",
            account_id=activated["account_id"],
        )
        _post_webhook(client, checkout_event)

        # past_due → grace period → still active
        update_event = _make_subscription_event(
            event_type="customer.subscription.updated",
            subscription_id="sub_upd_001",
            status="past_due",
            current_period_end=2000000000,
        )
        r = _post_webhook(client, update_event)
        assert r.status_code == 200
        assert r.json()["action"] == "license_updated"
        assert r.json()["status"] == "active"

        with Session(get_engine()) as session:
            lic = session.exec(
                select(License).where(License.stripe_subscription_id == "sub_upd_001")
            ).first()
            assert lic.status == "active"
            assert lic.expires_at is not None


# ── PAY-017: Webhook subscription.updated handles plan change ─────────────────

def test_webhook_subscription_updated_plan_change(make_client):
    """PAY-017: Plan change during subscription.updated re-seeds entitlements."""
    from sqlmodel import Session, select
    from db.models import Entitlement, License
    from db.sqlite import get_engine

    with make_client(**STRIPE_SETTINGS) as client:
        activated = _activate(client, email="upgrader@example.com", plan_code="dev_monthly")

        checkout_event = _make_checkout_event(
            subscription_id="sub_plan_chg",
            account_id=activated["account_id"],
            plan_code="dev_monthly",
        )
        _post_webhook(client, checkout_event)

        update_event = _make_subscription_event(
            event_type="customer.subscription.updated",
            subscription_id="sub_plan_chg",
            status="active",
            price_id="price_dev_annual_test",
        )
        r = _post_webhook(client, update_event)
        assert r.status_code == 200
        assert r.json()["plan_changed"] is True

        with Session(get_engine()) as session:
            lic = session.exec(
                select(License).where(License.stripe_subscription_id == "sub_plan_chg")
            ).first()
            assert lic.plan_code == "dev_annual"
            ents = session.exec(select(Entitlement).where(Entitlement.license_id == lic.license_id)).all()
            feat_codes = [e.feature_code for e in ents]
            assert len(feat_codes) == len(set(feat_codes))  # no duplicates
            assert len(ents) > 0


# ── PAY-018: Webhook subscription.deleted expires license ─────────────────────

def test_webhook_subscription_deleted(make_client):
    """PAY-018: customer.subscription.deleted expires the license."""
    from sqlmodel import Session, select
    from db.models import License
    from db.sqlite import get_engine

    with make_client(**STRIPE_SETTINGS) as client:
        activated = _activate(client, email="canceler@example.com")
        checkout_event = _make_checkout_event(
            subscription_id="sub_cancel_001",
            account_id=activated["account_id"],
        )
        _post_webhook(client, checkout_event)

        delete_event = _make_subscription_event(
            event_type="customer.subscription.deleted",
            subscription_id="sub_cancel_001",
        )
        r = _post_webhook(client, delete_event)
        assert r.status_code == 200
        assert r.json()["action"] == "license_expired"

        with Session(get_engine()) as session:
            lic = session.exec(
                select(License).where(License.stripe_subscription_id == "sub_cancel_001")
            ).first()
            assert lic.status == "expired"


# ── PAY-019: Webhook subscription.deleted idempotent ─────────────────────────

def test_webhook_subscription_deleted_idempotent(make_client):
    """PAY-019: Duplicate subscription.deleted is handled as a no_op."""
    with make_client(**STRIPE_SETTINGS) as client:
        activated = _activate(client, email="cancel2@example.com")
        checkout_event = _make_checkout_event(
            subscription_id="sub_cancel_002",
            account_id=activated["account_id"],
        )
        _post_webhook(client, checkout_event)

        delete_event = _make_subscription_event(
            event_type="customer.subscription.deleted",
            subscription_id="sub_cancel_002",
        )
        r1 = _post_webhook(client, delete_event)
        assert r1.json()["action"] == "license_expired"

        r2 = _post_webhook(client, delete_event)
        assert r2.status_code == 200
        assert r2.json()["action"] == "no_op"
        assert r2.json().get("reason") == "already_expired"


# ── PAY-020: Webhook invoice.payment_failed records event ─────────────────────

def test_webhook_invoice_payment_failed(make_client):
    """PAY-020: invoice.payment_failed records a PAYMENT_FAILED license event."""
    from sqlmodel import Session, select
    from db.models import LicenseEvent
    from db.sqlite import get_engine

    with make_client(**STRIPE_SETTINGS) as client:
        activated = _activate(client, email="payer@example.com")
        checkout_event = _make_checkout_event(
            subscription_id="sub_pay_fail",
            account_id=activated["account_id"],
        )
        _post_webhook(client, checkout_event)

        invoice_event = _make_invoice_event(
            subscription_id="sub_pay_fail",
            invoice_id="in_fail_001",
        )
        r = _post_webhook(client, invoice_event)
        assert r.status_code == 200
        assert r.json()["action"] == "payment_failed_recorded"

        with Session(get_engine()) as session:
            events = session.exec(
                select(LicenseEvent).where(LicenseEvent.event_type == "PAYMENT_FAILED")
            ).all()
            assert len(events) >= 1
            payloads = [e.event_payload for e in events]
            assert any("in_fail_001" in (p or "") for p in payloads)


# ── PAY-021: Internal licensing enforces caps after webhook sync ───────────────

def test_internal_licensing_enforces_after_webhook_sync(make_client):
    """PAY-021: Runtime feature gates still use internal license after webhook sync."""
    with make_client(**STRIPE_SETTINGS) as client:
        activated = _activate(client, email="enforced@example.com", plan_code="dev_monthly")

        # Activate via checkout (gets full dev_monthly entitlements)
        checkout_event = _make_checkout_event(
            subscription_id="sub_enforce_001",
            account_id=activated["account_id"],
            plan_code="dev_monthly",
        )
        _post_webhook(client, checkout_event)

        # Export should be allowed (dev_monthly has debug_bundle_export=enabled)
        r = client.get("/v1/audit/export?chain_id=zdg-local-chain-01&format=json", headers=ADMIN)
        assert r.status_code == 200

        # Cancel via webhook
        delete_event = _make_subscription_event(
            event_type="customer.subscription.deleted",
            subscription_id="sub_enforce_001",
        )
        _post_webhook(client, delete_event)

        # Export should now be blocked (license expired)
        r2 = client.get("/v1/audit/export?chain_id=zdg-local-chain-01&format=json", headers=ADMIN)
        assert r2.status_code == 402


# ── PAY-022: Billing route auth model ────────────────────────────────────────

def test_billing_route_auth_model(make_client):
    """PAY-022: Checkout and portal require admin token; webhook does not."""
    with make_client(**STRIPE_SETTINGS) as client:
        # Checkout: 401 without token
        r = client.post("/v1/billing/checkout", json={"account_id": "acc_x", "plan_code": "dev_monthly"})
        assert r.status_code == 401

        # Portal: 401 without token
        r = client.post("/v1/billing/portal", json={"account_id": "acc_x"})
        assert r.status_code == 401

        # Webhook: 400 for missing signature (not 401) — Stripe-signed, no admin auth
        r = client.post("/v1/billing/webhook", content=b"test",
                        headers={"Content-Type": "application/json"})
        assert r.status_code == 400
        assert "Stripe-Signature" in r.json()["detail"]["reason"]
