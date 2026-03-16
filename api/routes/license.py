"""api/routes/license.py — License management and status for ZDG-FR Developer Edition."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session

from api.auth import require_admin
from core.licensing import (
    PLAN_CATALOG,
    LicenseError,
    add_entitlement,
    apply_plan_defaults,
    create_account,
    create_license,
    enforce_installation_limit,
    expire_license,
    get_license_status,
    record_license_event,
    register_installation,
    revoke_license,
)
from db.sqlite import get_session

router = APIRouter(dependencies=[Depends(require_admin)])


# ── Request schemas ───────────────────────────────────────────────────────────

class EntitlementInput(BaseModel):
    feature_code: str
    enabled: bool = True
    limit_value: int | None = None


class LicenseActivateRequest(BaseModel):
    """Activate a new license for this installation.

    Creates a LicenseAccount, License, and optional Entitlements + Installation
    in one call. All fields are optional except email and plan_code.

    plan_code: free | dev_monthly | dev_annual (canonical) or any string.
      Canonical plan codes automatically seed default entitlement rows when no
      explicit entitlements are supplied. Unknown plan_code with no entitlements
      → no rows created (all features accessible, unmanaged semantics preserved).
    status: active | trialing | expired | revoked (default: active)
    entitlements: explicit list of feature entitlements. If non-empty, these
      override plan defaults entirely (no merging). If empty, plan defaults apply.
    device_label: if provided, registers this as an installation against the license
    """

    email: str
    display_name: str = ""
    plan_code: str
    status: str = "active"
    expires_at: str | None = None       # ISO datetime string or None (no expiry)
    trial_ends_at: str | None = None    # ISO datetime string or None
    max_installations: int = Field(default=1, ge=1)
    notes: str | None = None
    entitlements: list[EntitlementInput] = Field(default_factory=list)
    # Optional installation registration
    device_label: str | None = None
    device_fingerprint: str | None = None
    platform: str | None = None
    app_version: str | None = None


class LicenseRevokeRequest(BaseModel):
    license_id: str
    reason: str


class LicenseExpireRequest(BaseModel):
    license_id: str


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/license")
def get_license(session: Session = Depends(get_session)):
    """Return the current license status for this installation.

    Returns unmanaged_mode=True when no license is registered.
    Returns the active/most recent license + entitlements + installations otherwise.
    """
    return get_license_status(session)


@router.post("/license/activate", status_code=201)
def activate_license(
    body: LicenseActivateRequest,
    session: Session = Depends(get_session),
):
    """Register a new license for this installation.

    Creates: LicenseAccount + License + Entitlements + optional Installation.
    Emits a LICENSE_ACTIVATED license event.
    """
    # Parse optional ISO datetime fields
    expires_at: datetime | None = None
    trial_ends_at: datetime | None = None
    if body.expires_at:
        try:
            expires_at = datetime.fromisoformat(body.expires_at)
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail={"reason": f"Invalid expires_at: {exc}"},
            ) from exc
    if body.trial_ends_at:
        try:
            trial_ends_at = datetime.fromisoformat(body.trial_ends_at)
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail={"reason": f"Invalid trial_ends_at: {exc}"},
            ) from exc

    display_name = body.display_name or body.email.split("@")[0]
    account = create_account(session, email=body.email, display_name=display_name)
    session.flush()  # write account so license FK resolves
    license = create_license(
        session,
        account_id=account.account_id,
        plan_code=body.plan_code,
        status=body.status,
        expires_at=expires_at,
        trial_ends_at=trial_ends_at,
        max_installations=body.max_installations,
        notes=body.notes,
    )
    session.flush()  # write license so entitlement/installation FKs resolve

    if body.entitlements:
        # Explicit entitlements supplied — use them as-is (no merging with plan defaults).
        for ent_input in body.entitlements:
            add_entitlement(
                session,
                license_id=license.license_id,
                feature_code=ent_input.feature_code,
                enabled=ent_input.enabled,
                limit_value=ent_input.limit_value,
            )
        entitlements_added = len(body.entitlements)
    else:
        # No explicit entitlements — seed defaults from the plan catalog if plan_code is known.
        seeded = apply_plan_defaults(session, license.license_id, body.plan_code)
        entitlements_added = len(seeded)

    installation = None
    if body.device_label:
        try:
            enforce_installation_limit(session, account.account_id)
        except LicenseError as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason": str(exc), "feature": exc.feature_code},
            ) from exc
        installation = register_installation(
            session,
            account_id=account.account_id,
            license_id=license.license_id,
            device_label=body.device_label,
            device_fingerprint=body.device_fingerprint,
            platform=body.platform,
            app_version=body.app_version,
        )
        record_license_event(
            session,
            license_id=license.license_id,
            event_type="INSTALLATION_REGISTERED",
            event_payload={
                "installation_id": installation.installation_id,
                "device_label": body.device_label,
            },
        )

    record_license_event(
        session,
        license_id=license.license_id,
        event_type="LICENSE_ACTIVATED",
        event_payload={
            "license_id": license.license_id,
            "account_id": account.account_id,
            "plan_code": body.plan_code,
            "status": body.status,
        },
    )
    session.commit()

    return {
        "account_id": account.account_id,
        "license_id": license.license_id,
        "plan_code": license.plan_code,
        "status": license.status,
        "installation_id": installation.installation_id if installation else None,
        "entitlements_added": entitlements_added,
    }


@router.post("/license/expire")
def expire_license_route(
    body: LicenseExpireRequest,
    session: Session = Depends(get_session),
):
    """Transition a license to expired status."""
    try:
        expire_license(session, body.license_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail={"reason": str(exc)}) from exc
    session.commit()
    return {"license_id": body.license_id, "status": "expired"}


@router.post("/license/revoke")
def revoke_license_route(
    body: LicenseRevokeRequest,
    session: Session = Depends(get_session),
):
    """Revoke a license. All gated features are immediately blocked."""
    try:
        revoke_license(session, body.license_id, reason=body.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail={"reason": str(exc)}) from exc
    session.commit()
    return {"license_id": body.license_id, "status": "revoked"}


@router.get("/license/plans")
def list_license_plans():
    """Return all canonical plan definitions with their default entitlements.

    Useful for onboarding: shows what each plan enables/restricts before activation.
    Returns: {"plans": [{"plan_code": ..., "description": ..., "entitlements": [...]}]}
    """
    return {
        "plans": [
            {
                "plan_code": code,
                "description": definition["description"],
                "entitlements": definition["entitlements"],
            }
            for code, definition in PLAN_CATALOG.items()
        ]
    }
