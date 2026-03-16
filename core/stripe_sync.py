"""
core/stripe_sync.py — Stripe billing integration for PAY-01.

Design principles:
  - All Stripe SDK calls are isolated here so routes never import stripe directly.
  - Custom exceptions (StripeConfigError, StripeWebhookSignatureError, StripeAPIError)
    keep billing routes free of stripe-specific imports.
  - handle_webhook_event adds DB mutations to session but does NOT commit.
    The caller (billing route) commits after the handler returns.
  - All webhook handlers are idempotent: duplicate event delivery is safe.

Supported webhook events:
  checkout.session.completed      — create/activate license after successful payment
  customer.subscription.updated   — sync license status, plan, and expiry on renewal/change
  customer.subscription.deleted   — expire license on cancellation
  invoice.payment_failed          — record payment failure event
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlmodel import Session
    from api.config import Settings

logger = logging.getLogger(__name__)


# ── Custom exceptions (keeps billing.py clean of stripe imports) ───────────────

class StripeConfigError(Exception):
    """Stripe is not configured (missing secret key or price ID)."""


class StripeWebhookSignatureError(Exception):
    """Webhook signature verification failed."""


class StripeAPIError(Exception):
    """Stripe API call failed."""
    def __init__(self, message: str, user_message: str = ""):
        self.user_message = user_message or message
        super().__init__(message)


# ── Status mapping ─────────────────────────────────────────────────────────────

# Stripe subscription status → internal License.status
_STRIPE_STATUS_MAP: dict[str, str] = {
    "active":             "active",
    "trialing":           "trialing",
    "past_due":           "active",        # grace period — do not block yet
    "unpaid":             "expired",       # dunning exhausted
    "canceled":           "expired",
    "incomplete":         "active",        # initial payment window open
    "incomplete_expired": "expired",
    "paused":             "expired",
}


def _map_stripe_status(stripe_status: str) -> str:
    """Map a Stripe subscription status to an internal License.status value."""
    return _STRIPE_STATUS_MAP.get(stripe_status, "expired")


def _price_id_to_plan_code(price_id: str, settings: "Settings") -> str | None:
    """Map a Stripe price ID to a local plan_code. Returns None if unknown."""
    if price_id and settings.stripe_price_id_dev_monthly and price_id == settings.stripe_price_id_dev_monthly:
        return "dev_monthly"
    if price_id and settings.stripe_price_id_dev_annual and price_id == settings.stripe_price_id_dev_annual:
        return "dev_annual"
    return None


# ── Attribute access helper ────────────────────────────────────────────────────

def _get_obj_attr(obj: Any, key: str, default: Any = None) -> Any:
    """Get an attribute from either a dict or an object (Stripe SDK / SimpleNamespace)."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _get_subscription_price_id(sub_obj: Any) -> str | None:
    """Extract the price ID from a Stripe subscription's first line item."""
    try:
        items = _get_obj_attr(sub_obj, "items")
        data = _get_obj_attr(items, "data") if items is not None else None
        if not data:
            return None
        price = _get_obj_attr(data[0], "price")
        return _get_obj_attr(price, "id")
    except (IndexError, AttributeError, TypeError):
        return None


# ── Stripe API wrappers ────────────────────────────────────────────────────────

def get_stripe_client(settings: "Settings") -> Any:
    """Return a configured Stripe client. Raises StripeConfigError if key is missing."""
    import stripe
    if not settings.stripe_secret_key.strip():
        raise StripeConfigError(
            "STRIPE_SECRET_KEY is not configured. "
            "Set STRIPE_SECRET_KEY in your .env or environment."
        )
    return stripe.StripeClient(api_key=settings.stripe_secret_key)


def create_checkout_session(
    *,
    settings: "Settings",
    account_id: str,
    email: str,
    plan_code: str,
    stripe_customer_id: str | None,
) -> Any:
    """Create a Stripe Checkout session for the given plan.

    Sets client_reference_id=account_id so the webhook can resolve the account.
    Sets metadata.plan_code so the webhook knows which internal plan was purchased.

    Returns the Stripe Session object (has .url and .id).
    Raises StripeConfigError if Stripe is not configured or the plan has no price ID.
    Raises StripeAPIError on Stripe API failure.
    """
    import stripe

    price_map = {
        "dev_monthly": settings.stripe_price_id_dev_monthly,
        "dev_annual": settings.stripe_price_id_dev_annual,
    }
    price_id = price_map.get(plan_code, "")
    if not price_id:
        raise StripeConfigError(
            f"No Stripe price ID configured for plan {plan_code!r}. "
            "Set STRIPE_PRICE_ID_DEV_MONTHLY or STRIPE_PRICE_ID_DEV_ANNUAL."
        )

    client = get_stripe_client(settings)
    params: dict[str, Any] = {
        "mode": "subscription",
        "line_items": [{"price": price_id, "quantity": 1}],
        "client_reference_id": account_id,
        "metadata": {"plan_code": plan_code},
        "success_url": settings.stripe_success_url,
        "cancel_url": settings.stripe_cancel_url,
    }
    if stripe_customer_id:
        params["customer"] = stripe_customer_id
    else:
        params["customer_email"] = email

    try:
        return client.checkout.sessions.create(params=params)
    except stripe.StripeError as exc:
        raise StripeAPIError(str(exc), user_message=getattr(exc, "user_message", str(exc))) from exc


def create_portal_session(
    *,
    settings: "Settings",
    stripe_customer_id: str,
) -> Any:
    """Create a Stripe Customer Portal session for subscription management.

    Returns the portal Session object (has .url).
    Raises StripeConfigError if Stripe is not configured.
    Raises StripeAPIError on Stripe API failure.
    """
    import stripe

    if not stripe_customer_id:
        raise StripeConfigError("stripe_customer_id is required to create a portal session.")

    client = get_stripe_client(settings)
    try:
        return client.billing_portal.sessions.create(params={
            "customer": stripe_customer_id,
            "return_url": settings.stripe_portal_return_url,
        })
    except stripe.StripeError as exc:
        raise StripeAPIError(str(exc), user_message=getattr(exc, "user_message", str(exc))) from exc


def construct_webhook_event(
    *,
    payload: bytes,
    sig_header: str,
    webhook_secret: str,
) -> Any:
    """Validate Stripe webhook signature and return the event object.

    Raises StripeWebhookSignatureError on invalid or missing signature.
    This is the single point where raw bytes become a trusted event.
    """
    import stripe

    try:
        return stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except stripe.SignatureVerificationError as exc:
        raise StripeWebhookSignatureError(str(exc)) from exc
    except Exception as exc:
        raise StripeWebhookSignatureError(f"Webhook event construction failed: {exc}") from exc


# ── Webhook dispatch ───────────────────────────────────────────────────────────

def handle_webhook_event(
    *,
    session: "Session",
    event: Any,
    settings: "Settings",
) -> dict:
    """Dispatch a verified Stripe event to the correct handler.

    All DB mutations are added to session but NOT committed — the caller commits.
    Unknown event types are silently ignored.
    Returns a dict: {"action": str, ...}.
    """
    event_type = _get_obj_attr(event, "type") or event.get("type", "") if isinstance(event, dict) else getattr(event, "type", "")

    handlers = {
        "checkout.session.completed": _handle_checkout_completed,
        "customer.subscription.updated": _handle_subscription_updated,
        "customer.subscription.deleted": _handle_subscription_deleted,
        "invoice.payment_failed": _handle_invoice_payment_failed,
    }

    handler = handlers.get(event_type)
    if handler is None:
        logger.debug("stripe_sync: ignoring unhandled event type %r", event_type)
        return {"action": "ignored", "event_type": event_type}

    return handler(session, event, settings)


# ── Internal event handlers ────────────────────────────────────────────────────

def _handle_checkout_completed(
    session: "Session",
    event: Any,
    settings: "Settings",
) -> dict:
    """Handle checkout.session.completed — activate license after successful purchase.

    Idempotent: duplicate delivery is detected via stripe_subscription_id lookup.
    """
    from sqlmodel import select
    from db.models import License, LicenseAccount
    from core.licensing import (
        apply_plan_defaults,
        create_account,
        create_license,
        expire_license,
        record_license_event,
    )

    cs_obj = _get_obj_attr(event, "data")
    cs_obj = _get_obj_attr(cs_obj, "object")

    account_id = _get_obj_attr(cs_obj, "client_reference_id")
    customer_id = _get_obj_attr(cs_obj, "customer")
    subscription_id = _get_obj_attr(cs_obj, "subscription")
    customer_email = _get_obj_attr(cs_obj, "customer_email") or ""
    metadata = _get_obj_attr(cs_obj, "metadata") or {}
    plan_code = _get_obj_attr(metadata, "plan_code") or "dev_monthly"

    # Idempotency: if a license with this subscription_id already exists, skip.
    if subscription_id:
        existing = session.exec(
            select(License).where(License.stripe_subscription_id == subscription_id)
        ).first()
        if existing is not None:
            logger.info("stripe_sync: duplicate checkout.session.completed for sub %s — skipped", subscription_id)
            return {"action": "duplicate_skipped", "license_id": existing.license_id}

    # Find or create the LicenseAccount
    account = None
    if account_id:
        account = session.exec(
            select(LicenseAccount).where(LicenseAccount.account_id == account_id)
        ).first()
    if account is None and customer_email:
        account = session.exec(
            select(LicenseAccount).where(LicenseAccount.email == customer_email)
        ).first()
    if account is None:
        # Customer paid without going through our admin API — create account inline.
        placeholder_email = customer_email or f"stripe_{customer_id or 'unknown'}@unknown"
        account = create_account(session, email=placeholder_email, display_name="")
        session.flush()

    # Write stripe_customer_id onto the account
    if customer_id:
        account.stripe_customer_id = customer_id
        session.add(account)

    # Expire any existing active license for this account before creating the new one
    existing_active = session.exec(
        select(License)
        .where(License.account_id == account.account_id)
        .where(License.status.in_(["active", "trialing"]))
    ).first()
    if existing_active is not None:
        expire_license(session, existing_active.license_id)

    session.flush()

    # Create the new license
    license = create_license(
        session,
        account_id=account.account_id,
        plan_code=plan_code,
        status="active",
    )
    license.stripe_subscription_id = subscription_id
    session.add(license)
    session.flush()

    # Seed plan entitlements
    apply_plan_defaults(session, license.license_id, plan_code)

    record_license_event(
        session,
        license_id=license.license_id,
        event_type="SUBSCRIPTION_ACTIVATED",
        event_payload={
            "stripe_subscription_id": subscription_id,
            "stripe_customer_id": customer_id,
            "plan_code": plan_code,
            "source": "stripe_checkout",
        },
    )

    logger.info(
        "stripe_sync: activated license %s for account %s (plan=%s sub=%s)",
        license.license_id, account.account_id, plan_code, subscription_id,
    )
    return {"action": "license_activated", "license_id": license.license_id}


def _handle_subscription_updated(
    session: "Session",
    event: Any,
    settings: "Settings",
) -> dict:
    """Handle customer.subscription.updated — sync status, plan, and expiry.

    Updates expires_at on every call so renewals extend the license automatically.
    If plan_code changes: replaces entitlements with new plan defaults.
    Idempotent: applying the same state twice is a no-op for DB content.
    """
    from sqlmodel import select
    from db.models import Entitlement, License
    from core.licensing import apply_plan_defaults, record_license_event

    sub_obj = _get_obj_attr(event, "data")
    sub_obj = _get_obj_attr(sub_obj, "object")

    subscription_id = _get_obj_attr(sub_obj, "id")
    stripe_status = _get_obj_attr(sub_obj, "status") or "active"
    current_period_end = _get_obj_attr(sub_obj, "current_period_end")
    price_id = _get_subscription_price_id(sub_obj)

    license = session.exec(
        select(License).where(License.stripe_subscription_id == subscription_id)
    ).first()

    if license is None:
        logger.warning("stripe_sync: subscription.updated for unknown sub %s — ignored", subscription_id)
        return {"action": "license_not_found", "stripe_subscription_id": subscription_id}

    new_status = _map_stripe_status(stripe_status)
    plan_code = _price_id_to_plan_code(price_id or "", settings) if price_id else None
    plan_changed = plan_code is not None and plan_code != license.plan_code

    # Update expires_at from Stripe's current_period_end (Unix timestamp)
    expires_at = None
    if current_period_end:
        expires_at = datetime.fromtimestamp(int(current_period_end), tz=timezone.utc).replace(tzinfo=None)

    license.status = new_status
    if expires_at is not None:
        license.expires_at = expires_at
    if plan_code is not None:
        license.plan_code = plan_code
    session.add(license)
    session.flush()

    # Re-seed entitlements if plan changed
    if plan_changed:
        existing_ents = session.exec(
            select(Entitlement).where(Entitlement.license_id == license.license_id)
        ).all()
        for ent in existing_ents:
            session.delete(ent)
        session.flush()
        apply_plan_defaults(session, license.license_id, license.plan_code)

    record_license_event(
        session,
        license_id=license.license_id,
        event_type="SUBSCRIPTION_UPDATED",
        event_payload={
            "stripe_subscription_id": subscription_id,
            "stripe_status": stripe_status,
            "internal_status": new_status,
            "plan_code": license.plan_code,
            "plan_changed": plan_changed,
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
    )

    logger.info(
        "stripe_sync: updated license %s (status=%s plan=%s expires=%s)",
        license.license_id, new_status, license.plan_code, expires_at,
    )
    return {
        "action": "license_updated",
        "license_id": license.license_id,
        "status": new_status,
        "plan_changed": plan_changed,
    }


def _handle_subscription_deleted(
    session: "Session",
    event: Any,
    settings: "Settings",
) -> dict:
    """Handle customer.subscription.deleted — expire the license on cancellation.

    Idempotent: if license is already expired, returns no_op.
    """
    from sqlmodel import select
    from db.models import License
    from core.licensing import expire_license

    sub_obj = _get_obj_attr(event, "data")
    sub_obj = _get_obj_attr(sub_obj, "object")

    subscription_id = _get_obj_attr(sub_obj, "id")

    license = session.exec(
        select(License).where(License.stripe_subscription_id == subscription_id)
    ).first()

    if license is None:
        logger.warning("stripe_sync: subscription.deleted for unknown sub %s — ignored", subscription_id)
        return {"action": "license_not_found", "stripe_subscription_id": subscription_id}

    if license.status == "expired":
        return {"action": "no_op", "license_id": license.license_id, "reason": "already_expired"}

    expire_license(session, license.license_id)
    logger.info("stripe_sync: expired license %s on subscription cancellation", license.license_id)
    return {"action": "license_expired", "license_id": license.license_id}


def _handle_invoice_payment_failed(
    session: "Session",
    event: Any,
    settings: "Settings",
) -> dict:
    """Handle invoice.payment_failed — record payment failure event.

    Records a PAYMENT_FAILED license event for audit purposes.
    Status transitions (e.g., to expired on final dunning failure) are handled
    by customer.subscription.updated with status=unpaid.
    """
    from sqlmodel import select
    from db.models import License
    from core.licensing import record_license_event

    inv_obj = _get_obj_attr(event, "data")
    inv_obj = _get_obj_attr(inv_obj, "object")

    subscription_id = _get_obj_attr(inv_obj, "subscription")
    invoice_id = _get_obj_attr(inv_obj, "id")

    if not subscription_id:
        return {"action": "no_subscription", "invoice_id": invoice_id}

    license = session.exec(
        select(License).where(License.stripe_subscription_id == subscription_id)
    ).first()

    if license is None:
        logger.warning("stripe_sync: payment_failed for unknown sub %s — ignored", subscription_id)
        return {"action": "license_not_found", "stripe_subscription_id": subscription_id}

    record_license_event(
        session,
        license_id=license.license_id,
        event_type="PAYMENT_FAILED",
        event_payload={
            "stripe_subscription_id": subscription_id,
            "stripe_invoice_id": invoice_id,
        },
    )

    logger.warning("stripe_sync: payment failed for license %s (invoice %s)", license.license_id, invoice_id)
    return {"action": "payment_failed_recorded", "license_id": license.license_id}
