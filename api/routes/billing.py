"""
api/routes/billing.py — Stripe billing routes for PAY-01.

Endpoints:
  POST /v1/billing/checkout  — create a Stripe Checkout session (admin-only)
  POST /v1/billing/portal    — create a Stripe Customer Portal session (admin-only)
  POST /v1/billing/webhook   — receive Stripe webhook events (Stripe-signed, no admin auth)

Design:
  - Routes never import stripe directly. All Stripe SDK calls are in core.stripe_sync.
  - The webhook endpoint authenticates via Stripe signature, not ZDG_ADMIN_TOKEN.
  - All session commits happen here (after stripe_sync adds mutations).
  - Missing Stripe config → 503. Stripe API failure → 502.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlmodel import Session, select

import core.stripe_sync as stripe_sync
from api.auth import require_admin
from core.stripe_sync import StripeAPIError, StripeConfigError, StripeWebhookSignatureError
from db.models import LicenseAccount
from db.sqlite import get_session

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Request schemas ────────────────────────────────────────────────────────────

class CheckoutRequest(BaseModel):
    """Create a Stripe Checkout session for a plan purchase."""
    account_id: str
    plan_code: str   # dev_monthly | dev_annual


class PortalRequest(BaseModel):
    """Create a Stripe Customer Portal session for self-serve billing management."""
    account_id: str


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/billing/checkout", dependencies=[Depends(require_admin)])
def create_checkout(
    body: CheckoutRequest,
    request: Request,
    session: Session = Depends(get_session),
) -> dict:
    """Create a Stripe Checkout session for the given account and plan.

    The developer is redirected to the Stripe-hosted checkout page to complete
    payment. On success Stripe fires checkout.session.completed which activates
    the internal license via POST /v1/billing/webhook.

    Returns: {"checkout_url": str, "session_id": str}
    """
    settings = request.app.state.zdg.settings

    account = session.exec(
        select(LicenseAccount).where(LicenseAccount.account_id == body.account_id)
    ).first()
    if account is None:
        raise HTTPException(status_code=404, detail={"reason": f"Account not found: {body.account_id!r}"})

    try:
        checkout_session = stripe_sync.create_checkout_session(
            settings=settings,
            account_id=account.account_id,
            email=account.email,
            plan_code=body.plan_code,
            stripe_customer_id=account.stripe_customer_id,
        )
    except StripeConfigError as exc:
        raise HTTPException(status_code=503, detail={"reason": str(exc)}) from exc
    except StripeAPIError as exc:
        raise HTTPException(status_code=502, detail={"reason": exc.user_message}) from exc

    return {
        "checkout_url": checkout_session.url,
        "session_id": checkout_session.id,
    }


@router.post("/billing/portal", dependencies=[Depends(require_admin)])
def create_portal(
    body: PortalRequest,
    request: Request,
    session: Session = Depends(get_session),
) -> dict:
    """Create a Stripe Customer Portal session for self-serve billing management.

    The customer is redirected to the Stripe-hosted portal to update payment
    method, view invoices, cancel subscriptions, etc.

    Returns: {"portal_url": str}
    Raises 409 if the account has no Stripe subscription yet.
    """
    settings = request.app.state.zdg.settings

    account = session.exec(
        select(LicenseAccount).where(LicenseAccount.account_id == body.account_id)
    ).first()
    if account is None:
        raise HTTPException(status_code=404, detail={"reason": f"Account not found: {body.account_id!r}"})
    if not account.stripe_customer_id:
        raise HTTPException(
            status_code=409,
            detail={
                "reason": "Account has no Stripe subscription. "
                "Complete a checkout first to create a billing relationship.",
            },
        )

    try:
        portal_session = stripe_sync.create_portal_session(
            settings=settings,
            stripe_customer_id=account.stripe_customer_id,
        )
    except StripeConfigError as exc:
        raise HTTPException(status_code=503, detail={"reason": str(exc)}) from exc
    except StripeAPIError as exc:
        raise HTTPException(status_code=502, detail={"reason": exc.user_message}) from exc

    return {"portal_url": portal_session.url}


@router.post("/billing/webhook", include_in_schema=False)
async def stripe_webhook(
    request: Request,
    stripe_signature: str | None = Header(default=None, alias="Stripe-Signature"),
    session: Session = Depends(get_session),
) -> dict:
    """Receive and process Stripe webhook events.

    Authentication: Stripe-Signature header (not ZDG_ADMIN_TOKEN).
    The raw request body is read as bytes to preserve the exact payload Stripe signed.

    Returns: {"received": True, "action": str}
    """
    settings = request.app.state.zdg.settings

    if not settings.stripe_webhook_secret.strip():
        raise HTTPException(
            status_code=503,
            detail={"reason": "STRIPE_WEBHOOK_SECRET is not configured."},
        )
    if not stripe_signature:
        raise HTTPException(
            status_code=400,
            detail={"reason": "Missing Stripe-Signature header."},
        )

    payload = await request.body()

    try:
        event = stripe_sync.construct_webhook_event(
            payload=payload,
            sig_header=stripe_signature,
            webhook_secret=settings.stripe_webhook_secret,
        )
    except StripeWebhookSignatureError as exc:
        logger.warning("stripe_webhook: signature verification failed: %s", exc)
        raise HTTPException(status_code=400, detail={"reason": "Invalid Stripe webhook signature."}) from exc

    try:
        result = stripe_sync.handle_webhook_event(
            session=session,
            event=event,
            settings=settings,
        )
        session.commit()
    except Exception as exc:
        session.rollback()
        logger.exception("stripe_webhook: handler error for event %s: %s", getattr(event, "type", "?"), exc)
        raise HTTPException(status_code=500, detail={"reason": "Webhook handler error."}) from exc

    return {"received": True, **result}
