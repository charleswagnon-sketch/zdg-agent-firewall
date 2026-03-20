"""
core/licensing.py — Lightweight licensing and entitlements service for ZDG-FR Developer Edition.

Enforcement model:
  No license registered  → evaluation mode — UNMANAGED_LIMITS apply (stricter than Free).
  License active/trialing → enforce entitlements from DB (opt-in per feature).
  License expired/revoked → gated features blocked (raises LicenseError → HTTP 402).

"Server-authoritative" means license state lives in this installation's DB.
The DB record is the truth; no JWT or client-side token is the authority.

Entitlement semantics (opt-in gating):
  If no Entitlement row exists for a feature → feature is accessible.
  If Entitlement.enabled = False → feature is blocked.
  If Entitlement.limit_value is set → numeric cap applies (None = unlimited).

Commercial ladder: evaluation mode < free < dev_monthly / dev_annual.
Evaluation mode is intentionally more restrictive than Free to encourage
activation. No license activation is required for a first run.

Feature codes used by enforcement hooks:
  debug_bundle_export   — governs GET /v1/audit/export
  replay_history_days   — governs GET /v1/audit/replay (age-based retention)
  max_monthly_runs      — governs POST /v1/action (monthly governed run cap)
  max_monthly_exports   — governs GET /v1/audit/export (monthly export call cap)
  spend_analytics       — informational; not yet enforced at a route
  advanced_filters      — informational; not yet enforced at a route
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from uuid import uuid4

if TYPE_CHECKING:
    from sqlmodel import Session

from db.models import Entitlement, Installation, License, LicenseAccount, LicenseEvent, LicenseUsage


# ── Plan catalog ──────────────────────────────────────────────────────────────
#
# Canonical plan definitions for ZDG-FR Developer Edition.
# Each entry defines default entitlement rows seeded at activation time when no
# explicit entitlements are supplied in the activate request.
#
# Keys match the plan_code values expected by POST /v1/license/activate.
# Entitlement semantics:
#   enabled=False  → feature blocked for this plan
#   limit_value    → numeric cap (None = unlimited)

PLAN_CATALOG: dict[str, dict] = {
    "free": {
        "description": "Free tier — local dev and evaluation. Core governance active; exports and analytics gated.",
        "entitlements": [
            {"feature_code": "debug_bundle_export",  "enabled": False, "limit_value": None},
            {"feature_code": "replay_history_days",  "enabled": True,  "limit_value": 7},
            {"feature_code": "max_monthly_runs",     "enabled": True,  "limit_value": 500},
            {"feature_code": "spend_analytics",      "enabled": False, "limit_value": None},
            {"feature_code": "advanced_filters",     "enabled": False, "limit_value": None},
            {"feature_code": "max_monthly_exports",  "enabled": True,  "limit_value": 0},
        ],
    },
    "dev_monthly": {
        "description": "Developer monthly — full feature access for active development and integration testing.",
        "entitlements": [
            {"feature_code": "debug_bundle_export",  "enabled": True,  "limit_value": None},
            {"feature_code": "replay_history_days",  "enabled": True,  "limit_value": 90},
            {"feature_code": "max_monthly_runs",     "enabled": True,  "limit_value": 10_000},
            {"feature_code": "spend_analytics",      "enabled": True,  "limit_value": None},
            {"feature_code": "advanced_filters",     "enabled": True,  "limit_value": None},
            {"feature_code": "max_monthly_exports",  "enabled": True,  "limit_value": 100},
        ],
    },
    "dev_annual": {
        "description": "Developer annual — same features as dev_monthly, annual billing cycle.",
        "entitlements": [
            {"feature_code": "debug_bundle_export",  "enabled": True,  "limit_value": None},
            {"feature_code": "replay_history_days",  "enabled": True,  "limit_value": 90},
            {"feature_code": "max_monthly_runs",     "enabled": True,  "limit_value": 10_000},
            {"feature_code": "spend_analytics",      "enabled": True,  "limit_value": None},
            {"feature_code": "advanced_filters",     "enabled": True,  "limit_value": None},
            {"feature_code": "max_monthly_exports",  "enabled": True,  "limit_value": 100},
        ],
    },
}


# ── Unmanaged evaluation limits ───────────────────────────────────────────────
#
# Applied when no license has ever been registered (truly unmanaged / evaluation
# mode). These limits are intentionally stricter than the Free plan so the
# commercial ladder is: evaluation < free < dev_monthly / dev_annual.
#
# Compared to Free plan:
#   replay_history_days : 3 days  (Free: 7)
#   max_monthly_runs    : 25      (Free: 500)
#   max_monthly_exports : 0       (Free: 0  — same; both block export)
#   advanced_filters    : False   (Free: False — same)
#   spend_analytics     : False   (Free: False — same)

UNMANAGED_LIMITS: dict[str, dict] = {
    "replay_history_days": {"enabled": True,  "limit_value": 3},
    "max_monthly_runs":    {"enabled": True,  "limit_value": 25},
    "max_monthly_exports": {"enabled": True,  "limit_value": 0},
    "advanced_filters":    {"enabled": False, "limit_value": None},
    "spend_analytics":     {"enabled": False, "limit_value": None},
}


def get_plan_definition(plan_code: str) -> dict | None:
    """Return the canonical plan definition for plan_code, or None if unknown."""
    return PLAN_CATALOG.get(plan_code)


def apply_plan_defaults(
    session: "Session",
    license_id: str,
    plan_code: str,
) -> list[Entitlement]:
    """Seed default entitlement rows for a known plan code.

    Called during activation when no explicit entitlements are supplied.
    Unknown plan_code → no rows created (permissive default preserved).
    Returns the list of Entitlement objects added to the session (not yet committed).
    """
    plan = PLAN_CATALOG.get(plan_code)
    if plan is None:
        return []
    created: list[Entitlement] = []
    for ent_def in plan["entitlements"]:
        ent = add_entitlement(
            session,
            license_id=license_id,
            feature_code=ent_def["feature_code"],
            enabled=ent_def["enabled"],
            limit_value=ent_def.get("limit_value"),
        )
        created.append(ent)
    return created


class LicenseError(Exception):
    """Raised when a license check blocks access to a gated feature.

    Route handlers catch this and return HTTP 402 with detail.reason.
    """

    def __init__(self, feature_code: str, reason: str):
        self.feature_code = feature_code
        self.reason = reason
        super().__init__(f"Feature {feature_code!r} not accessible: {reason}")


# ── Read-side helpers ─────────────────────────────────────────────────────────

def get_active_license(session: "Session") -> License | None:
    """Return the most recently issued active or trialing license, or None.

    "Most recently issued" is deterministic: pick the license with the latest
    issued_at. If multiple licenses are active (unusual), the most recent wins.
    Returns None when no license is registered (unmanaged mode).
    """
    from sqlmodel import select

    return session.exec(
        select(License)
        .where(License.status.in_(["active", "trialing"]))
        .order_by(License.issued_at.desc())
        .limit(1)
    ).first()


def get_entitlements(session: "Session", license_id: str) -> dict[str, Entitlement]:
    """Return all entitlement records for a license keyed by feature_code."""
    from sqlmodel import select

    rows = session.exec(
        select(Entitlement).where(Entitlement.license_id == license_id)
    ).all()
    return {e.feature_code: e for e in rows}


def check_feature(session: "Session", feature_code: str) -> bool:
    """Return True if the feature is accessible, False if blocked.

    Strict enforcement logic:
      1. No license ever registered → check UNMANAGED_LIMITS.
      2. Active/Trialing license   → check entitlements (opt-in gating).
      3. Expired/Revoked license  → False (fully blocked).
    """
    from sqlmodel import select

    active_license = get_active_license(session)
    if active_license:
        entitlements = get_entitlements(session, active_license.license_id)
        ent = entitlements.get(feature_code)
        if ent is None:
            return True  # no explicit gate → accessible for active plans
        return ent.enabled

    # No active license — check if an inactive one exists
    any_license = session.exec(
        select(License).order_by(License.issued_at.desc()).limit(1)
    ).first()

    if any_license is None:
        # Truly unmanaged evaluation mode — apply evaluation limits.
        ent = UNMANAGED_LIMITS.get(feature_code)
        if ent is not None:
            return ent["enabled"]
        return True  # feature not in evaluation limits → accessible

    # A license exists but is not active (expired/revoked) — terminal block.
    return False


def require_feature(session: "Session", feature_code: str) -> None:
    """Enforce feature access. Raises LicenseError if blocked.

    Strict enforcement logic:
      1. No license ever registered → check UNMANAGED_LIMITS; raise if disabled.
      2. Active/Trialing license   → check entitlements; raise if disabled.
      3. Expired/Revoked license  → raise license_expired/license_revoked.
    """
    from sqlmodel import select

    active_license = get_active_license(session)
    if active_license:
        # Active/trialing: enforce per-feature entitlements
        entitlements = get_entitlements(session, active_license.license_id)
        ent = entitlements.get(feature_code)
        if ent is not None and not ent.enabled:
            raise LicenseError(feature_code, "feature_disabled")
        return

    # No active license — check if an inactive one exists
    any_license = session.exec(
        select(License).order_by(License.issued_at.desc()).limit(1)
    ).first()

    if any_license is None:
        # Truly unmanaged evaluation mode — apply evaluation limits.
        ent = UNMANAGED_LIMITS.get(feature_code)
        if ent is not None and not ent["enabled"]:
            raise LicenseError(feature_code, "feature_disabled")
        return

    # A license exists but is not active — terminal block with specific reason.
    if any_license.status == "expired":
        raise LicenseError(feature_code, "license_expired")
    if any_license.status == "revoked":
        raise LicenseError(feature_code, "license_revoked")
    raise LicenseError(feature_code, f"license_status:{any_license.status}")


def get_feature_limit(session: "Session", feature_code: str) -> int | None:
    """Return the numeric limit for a feature, or None (unlimited).

    Strict enforcement logic:
      1. No license ever registered → check UNMANAGED_LIMITS.
      2. Active/Trialing license   → check entitlements (None if no row).
      3. Expired/Revoked license  → 0 (fully restricted).
    """
    from sqlmodel import select

    active_license = get_active_license(session)
    if active_license:
        entitlements = get_entitlements(session, active_license.license_id)
        ent = entitlements.get(feature_code)
        if ent is None:
            return None  # no explicit limit → unlimited for active plans
        return ent.limit_value

    # No active license — check if an inactive one exists
    any_license = session.exec(
        select(License).order_by(License.issued_at.desc()).limit(1)
    ).first()

    if any_license is None:
        # Truly unmanaged evaluation mode — apply evaluation limits.
        ent = UNMANAGED_LIMITS.get(feature_code)
        if ent is not None:
            return ent["limit_value"]
        return None  # feature not in evaluation limits → unlimited

    # A license exists but is not active (expired/revoked) — fully restricted.
    return 0


# ── Monthly cap enforcement ───────────────────────────────────────────────────


def _current_month_start() -> datetime:
    """Return the first instant of the current calendar month in naive UTC.

    ToolAttempt.requested_at and LicenseUsage.used_at are both stored as naive
    UTC datetimes (utc_now_naive), so comparisons must also be naive.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def count_monthly_runs(session: "Session") -> int:
    """Count governed run attempts in the current calendar month.

    Uses ToolAttempt.requested_at (naive UTC). Idempotency replay hits do not
    create ToolAttempt records, so this count accurately reflects unique
    non-replay governed run submissions regardless of their outcome.
    """
    from sqlmodel import func, select

    from db.models import ToolAttempt

    month_start = _current_month_start()
    return session.exec(
        select(func.count()).select_from(
            select(ToolAttempt)
            .where(ToolAttempt.requested_at >= month_start)
            .subquery()
        )
    ).one()


def enforce_monthly_runs_cap(session: "Session") -> None:
    """Raise LicenseError if the monthly governed-run cap is exceeded.

    Called at the very start of POST /v1/action before ToolAttempt is created,
    so cap-exceeded requests do not increment the counter.

    Semantics:
      No license (unmanaged) → None limit → returns silently.
      Active license, no max_monthly_runs entitlement → None → unlimited.
      Active license, limit_value set → enforce.
      Expired/revoked license → get_feature_limit returns 0 → always blocked.
    """
    limit = get_feature_limit(session, "max_monthly_runs")
    if limit is None:
        return  # unlimited (unmanaged or no entitlement row)
    used = count_monthly_runs(session)
    if used >= limit:
        raise LicenseError(
            "max_monthly_runs",
            f"monthly_run_limit_exceeded:{used}/{limit}",
        )


def count_monthly_exports(session: "Session", license_id: str) -> int:
    """Count export operations recorded for a license in the current calendar month."""
    from sqlmodel import func, select

    month_start = _current_month_start()
    return session.exec(
        select(func.count()).select_from(
            select(LicenseUsage)
            .where(LicenseUsage.license_id == license_id)
            .where(LicenseUsage.feature_code == "max_monthly_exports")
            .where(LicenseUsage.used_at >= month_start)
            .subquery()
        )
    ).one()


def enforce_monthly_exports_cap(session: "Session") -> "License | None":
    """Check the monthly export cap. Raises LicenseError if exceeded.

    Returns the active License on success so the caller can record usage without
    a second DB lookup. Returns None when no active license and limit is None.

    Semantics:
      Evaluation mode → limit=0 (from UNMANAGED_LIMITS) → always blocked.
      Active license, no max_monthly_exports entitlement → None → unlimited,
        returns the License so usage is still recorded for observability.
      Active license, limit_value set → enforce.
      Expired/revoked license → get_feature_limit returns 0 → always blocked.
    """
    from sqlmodel import select

    limit = get_feature_limit(session, "max_monthly_exports")
    if limit is None:
        # Active/trialing with no entitlement row (unlimited).
        # Return the active license so callers can record usage for observability.
        return get_active_license(session)

    license = get_active_license(session)
    if license is None:
        # Non-None limit with no active license — either evaluation mode
        # (limit from UNMANAGED_LIMITS) or an expired/revoked license. Block either way.
        any_license = session.exec(
            select(License).order_by(License.issued_at.desc()).limit(1)
        ).first()
        if any_license is None:
            raise LicenseError(
                "max_monthly_exports",
                f"monthly_export_limit_exceeded:0/{limit}",
            )
        raise LicenseError(
            "max_monthly_exports",
            "monthly_export_limit_exceeded:license_not_active",
        )

    used = count_monthly_exports(session, license.license_id)
    if used >= limit:
        raise LicenseError(
            "max_monthly_exports",
            f"monthly_export_limit_exceeded:{used}/{limit}",
        )
    return license


def record_export_usage(session: "Session", license_id: str) -> None:
    """Insert a LicenseUsage row to count one export operation.

    Called after enforce_monthly_exports_cap passes and before the response is
    returned. The session.commit() in the export route persists this row.
    """
    usage_id = f"usg_{uuid4().hex[:16]}"
    row = LicenseUsage(
        usage_id=usage_id,
        license_id=license_id,
        feature_code="max_monthly_exports",
    )
    session.add(row)


def _license_status_message(license: "License | None", unmanaged: bool) -> str:
    """Return a human-readable status message for a license object."""
    if unmanaged or license is None:
        return "Evaluation mode — no license registered. Feature access is limited; activate a plan for full access."
    status = license.status
    plan = license.plan_code
    if status == "active":
        return f"License active — plan {plan!r}. Entitlements enforced per plan."
    if status == "trialing":
        trial_end = license.trial_ends_at.isoformat() if license.trial_ends_at else "unknown"
        return f"Trial active — plan {plan!r}. Trial ends {trial_end}."
    if status == "expired":
        return "License expired — gated features are blocked. Reactivate to restore access."
    if status == "revoked":
        return "License revoked — all gated features are blocked."
    return f"License status: {status!r}."


def get_license_status(session: "Session") -> dict[str, Any]:
    """Return a structured license status view for the API endpoint.

    Returns an unmanaged_mode indicator when no license is registered,
    or the full license + entitlement state when one is present.

    Includes status_message (human-readable) and plan_definition (canonical
    plan catalog entry for the current plan_code, if known).
    """
    from sqlmodel import select

    license = get_active_license(session)
    if license is None:
        # Check if there are any licenses at all (expired/revoked)
        any_license = session.exec(
            select(License).order_by(License.issued_at.desc()).limit(1)
        ).first()
        if any_license is None:
            # Evaluation mode: surface run count and evaluation limits.
            runs_used = count_monthly_runs(session)
            month_label = _current_month_start().strftime("%Y-%m")
            runs_limit = UNMANAGED_LIMITS["max_monthly_runs"]["limit_value"]
            exports_limit = UNMANAGED_LIMITS["max_monthly_exports"]["limit_value"]
            return {
                "unmanaged_mode": True,
                "status_message": _license_status_message(None, unmanaged=True),
                "license": None,
                "plan_definition": None,
                "entitlements": [
                    {
                        "feature_code": code,
                        "enabled": ent["enabled"],
                        "limit_value": ent["limit_value"],
                    }
                    for code, ent in UNMANAGED_LIMITS.items()
                ],
                "installations": [],
                "usage_summary": {
                    "window": month_label,
                    "max_monthly_runs": {
                        "used": runs_used,
                        "limit": runs_limit,
                        "exceeded": runs_used >= runs_limit,
                    },
                    "max_monthly_exports": {
                        "used": 0,
                        "limit": exports_limit,
                        "exceeded": False,
                    },
                },
            }
        license = any_license  # show the most recent non-active license

    entitlements = get_entitlements(session, license.license_id)
    installations = session.exec(
        select(Installation).where(
            Installation.license_id == license.license_id
        )
    ).all()

    # Compute usage summary for the current calendar month.
    month_label = _current_month_start().strftime("%Y-%m")
    runs_used = count_monthly_runs(session)
    runs_limit = get_feature_limit(session, "max_monthly_runs")

    is_active = license.status in ("active", "trialing")
    exports_used = (
        count_monthly_exports(session, license.license_id) if is_active else 0
    )
    exports_limit = get_feature_limit(session, "max_monthly_exports")

    # Look up account for stripe_customer_id
    account = session.exec(
        select(LicenseAccount).where(LicenseAccount.account_id == license.account_id)
    ).first()

    return {
        "unmanaged_mode": False,
        "status_message": _license_status_message(license, unmanaged=False),
        "license": {
            "license_id": license.license_id,
            "account_id": license.account_id,
            "plan_code": license.plan_code,
            "status": license.status,
            "issued_at": license.issued_at.isoformat() if license.issued_at else None,
            "starts_at": license.starts_at.isoformat() if license.starts_at else None,
            "expires_at": license.expires_at.isoformat() if license.expires_at else None,
            "trial_ends_at": license.trial_ends_at.isoformat() if license.trial_ends_at else None,
            "max_installations": license.max_installations,
            "notes": license.notes,
            # PAY-01: Stripe billing fields (presence indicates a Stripe subscription exists)
            "stripe_customer_id": account.stripe_customer_id if account else None,
            "stripe_subscription_id": license.stripe_subscription_id,
        },
        "plan_definition": PLAN_CATALOG.get(license.plan_code),
        "entitlements": [
            {
                "feature_code": e.feature_code,
                "enabled": e.enabled,
                "limit_value": e.limit_value,
            }
            for e in entitlements.values()
        ],
        "installations": [
            {
                "installation_id": inst.installation_id,
                "device_label": inst.device_label,
                "platform": inst.platform,
                "app_version": inst.app_version,
                "first_seen_at": inst.first_seen_at.isoformat() if inst.first_seen_at else None,
                "last_seen_at": inst.last_seen_at.isoformat() if inst.last_seen_at else None,
                "revoked_at": inst.revoked_at.isoformat() if inst.revoked_at else None,
            }
            for inst in installations
        ],
        "usage_summary": {
            "window": month_label,
            "max_monthly_runs": {
                "used": runs_used,
                "limit": runs_limit,
                "exceeded": runs_limit is not None and runs_used >= runs_limit,
            },
            "max_monthly_exports": {
                "used": exports_used,
                "limit": exports_limit,
                "exceeded": exports_limit is not None and exports_used >= exports_limit,
            },
        },
    }


# ── Write-side helpers ────────────────────────────────────────────────────────

def create_account(
    session: "Session",
    *,
    email: str,
    display_name: str,
) -> LicenseAccount:
    """Create and persist a new developer account."""
    account_id = f"acc_{uuid4().hex[:16]}"
    account = LicenseAccount(
        account_id=account_id,
        email=email,
        display_name=display_name,
    )
    session.add(account)
    return account


def create_license(
    session: "Session",
    *,
    account_id: str,
    plan_code: str,
    status: str = "active",
    expires_at: datetime | None = None,
    trial_ends_at: datetime | None = None,
    max_installations: int = 1,
    notes: str | None = None,
) -> License:
    """Create and persist a new license record."""
    license_id = f"lic_{uuid4().hex[:16]}"
    license = License(
        license_id=license_id,
        account_id=account_id,
        plan_code=plan_code,
        status=status,
        expires_at=expires_at,
        trial_ends_at=trial_ends_at,
        max_installations=max_installations,
        notes=notes,
    )
    session.add(license)
    return license


def add_entitlement(
    session: "Session",
    *,
    license_id: str,
    feature_code: str,
    enabled: bool = True,
    limit_value: int | None = None,
) -> Entitlement:
    """Add an entitlement record for a license feature."""
    entitlement_id = f"ent_{uuid4().hex[:16]}"
    ent = Entitlement(
        entitlement_id=entitlement_id,
        license_id=license_id,
        feature_code=feature_code,
        enabled=enabled,
        limit_value=limit_value,
    )
    session.add(ent)
    return ent


def register_installation(
    session: "Session",
    *,
    account_id: str,
    license_id: str,
    device_label: str,
    device_fingerprint: str | None = None,
    platform: str | None = None,
    app_version: str | None = None,
) -> Installation:
    """Register a new installation for a license."""
    installation_id = f"ins_{uuid4().hex[:16]}"
    inst = Installation(
        installation_id=installation_id,
        account_id=account_id,
        license_id=license_id,
        device_label=device_label,
        device_fingerprint=device_fingerprint,
        platform=platform,
        app_version=app_version,
    )
    session.add(inst)
    return inst


def enforce_installation_limit(session: "Session", account_id: str) -> None:
    """Raise LicenseError if the account has reached its max_installations limit.

    Counts active (non-revoked) installations for the account's current license.
    No license → no enforcement. No active license → no enforcement.
    """
    from sqlmodel import func, select

    license = get_active_license(session)
    if license is None:
        return
    if license.account_id != account_id:
        return  # different account — skip (should not happen in single-tenant mode)

    active_count = session.exec(
        select(func.count()).select_from(
            select(Installation)
            .where(Installation.license_id == license.license_id)
            .where(Installation.revoked_at == None)  # noqa: E711
            .subquery()
        )
    ).one()

    if active_count >= license.max_installations:
        raise LicenseError(
            "max_installations",
            f"installation_limit_reached:{license.max_installations}",
        )


def record_license_event(
    session: "Session",
    *,
    license_id: str,
    event_type: str,
    event_payload: dict[str, Any] | None = None,
) -> LicenseEvent:
    """Record a license lifecycle event for audit purposes."""
    event_id = f"lev_{uuid4().hex[:16]}"
    ev = LicenseEvent(
        event_id=event_id,
        license_id=license_id,
        event_type=event_type,
        event_payload=json.dumps(event_payload or {}),
    )
    session.add(ev)
    return ev


def expire_license(session: "Session", license_id: str) -> None:
    """Transition a license to expired status and record the event."""
    from sqlmodel import select

    license = session.exec(
        select(License).where(License.license_id == license_id)
    ).first()
    if license is None:
        raise KeyError(f"License not found: {license_id!r}")
    license.status = "expired"
    session.add(license)
    record_license_event(
        session,
        license_id=license_id,
        event_type="LICENSE_EXPIRED",
        event_payload={"license_id": license_id, "plan_code": license.plan_code},
    )


def revoke_license(session: "Session", license_id: str, *, reason: str) -> None:
    """Transition a license to revoked status and record the event."""
    from sqlmodel import select

    license = session.exec(
        select(License).where(License.license_id == license_id)
    ).first()
    if license is None:
        raise KeyError(f"License not found: {license_id!r}")
    license.status = "revoked"
    session.add(license)
    record_license_event(
        session,
        license_id=license_id,
        event_type="LICENSE_REVOKED",
        event_payload={"license_id": license_id, "reason": reason},
    )
