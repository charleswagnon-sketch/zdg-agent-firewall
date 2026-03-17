"""Portable audit export, verify, diff, and replay routes."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from sqlmodel import Session, select

from api.auth import require_admin
from core.audit import diff_chain_exports, export_chain_document, export_chain_ndjson_lines, parse_chain_export, verify_chain_export
from core.licensing import LicenseError, enforce_monthly_exports_cap, get_feature_limit, record_export_usage, require_feature
from core.replay import build_attempt_replay, serialize_raw_events
from core.runs import list_runs
from db.models import AuditEvent
from db.sqlite import get_session

router = APIRouter(dependencies=[Depends(require_admin)])


@router.get("/audit/export")
def export_audit_chain(
    chain_id: str = Query(..., max_length=256, pattern=r"^[\w\-.:]+$"),
    format: str = Query(default="json", pattern="^(json|ndjson)$"),
    session: Session = Depends(get_session),
):
    # Gate 1 — feature access: debug_bundle_export must be enabled.
    # No license registered → passes (unmanaged mode). License present with
    # debug_bundle_export=False → 402. Expired/revoked license → 402.
    try:
        require_feature(session, "debug_bundle_export")
    except LicenseError as exc:
        raise HTTPException(
            status_code=402,
            detail={"reason": str(exc), "feature": exc.feature_code},
        ) from exc

    # Gate 2 — monthly cap: max_monthly_exports.
    # Returns the active License on success (or None for unmanaged/unlimited).
    # We record usage after the cap check passes so only successful (non-blocked)
    # exports count. The session.commit() below persists the usage row.
    try:
        active_license = enforce_monthly_exports_cap(session)
    except LicenseError as exc:
        raise HTTPException(
            status_code=402,
            detail={"reason": str(exc), "feature": exc.feature_code},
        ) from exc

    if active_license is not None:
        record_export_usage(session, active_license.license_id)
        session.commit()

    if format == "json":
        return export_chain_document(session, chain_id)

    lines = export_chain_ndjson_lines(session, chain_id)
    return StreamingResponse((line + "\n" for line in lines), media_type="application/x-ndjson")


@router.post("/audit/verify")
async def verify_audit_chain_export(request: Request):
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        payload = await request.json()
    else:
        payload = (await request.body()).decode("utf-8")
    try:
        parsed = parse_chain_export(payload)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail={"reason": str(exc)}) from exc
    return verify_chain_export(parsed)


@router.post("/audit/diff")
async def diff_audit_exports(request: Request):
    try:
        payload = await request.json()
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail={"reason": "Expected JSON request body."}) from exc

    left_export = payload.get("left_export")
    right_export = payload.get("right_export")
    if left_export is None or right_export is None:
        raise HTTPException(
            status_code=400,
            detail={"reason": "Request body must include left_export and right_export."},
        )

    try:
        diff = diff_chain_exports(left_export, right_export)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail={"reason": str(exc)}) from exc
    return JSONResponse(diff)


@router.get("/audit/replay")
def get_attempt_replay(
    attempt_id: str = Query(..., max_length=256, pattern=r"^[\w\-]+$"),
    format: str = Query(default="snapshot", pattern="^(snapshot|json)$"),
    session: Session = Depends(get_session),
):
    """Return a replay artifact for a single governed run.

    format=snapshot (default) — shaped summary with labeled timeline
    format=json               — raw ordered event list, hash fields intact

    LIC-01 enforcement: replay_history_days retention window.
    No license registered (unmanaged mode) → no enforcement, unlimited replay.
    Active license, no entitlement row for replay_history_days → unlimited.
    Active license, limit_value=0 → block all replay (hard block, no age check needed).
    Active license, limit_value=N (N > 0) → block if attempt is older than N days.
    Expired/revoked license → get_feature_limit returns 0 → hard block.
    """
    # LIC-01 enforcement: replay_history_days retention window.
    # get_feature_limit returns None (unlimited) when no license is registered or
    # when no entitlement row is set for this feature.
    # A limit_value of 0 means "no history" — block all replay access.
    # A limit_value of N > 0 means enforce an N-day age window server-side.
    retention_days = get_feature_limit(session, "replay_history_days")
    if retention_days is not None and retention_days == 0:
        # Hard block: retention window is zero (license expired or plan blocks replay).
        raise HTTPException(
            status_code=402,
            detail={
                "reason": "Replay access is not available on the current plan.",
                "feature": "replay_history_days",
            },
        )

    if retention_days is not None and retention_days > 0:
        # Age-based window: find the earliest event for this attempt and compare
        # its creation time against the retention cutoff.
        # If no events exist yet, skip the check — the 404 path handles that below.
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=retention_days)
        earliest = session.exec(
            select(AuditEvent)
            .where(AuditEvent.related_attempt_id == attempt_id)
            .order_by(AuditEvent.created_at)
            .limit(1)
        ).first()
        if earliest is not None and earliest.created_at < cutoff:
            raise HTTPException(
                status_code=402,
                detail={
                    "reason": (
                        f"Replay for this attempt is outside the {retention_days}-day "
                        f"retention window for the current plan."
                    ),
                    "feature": "replay_history_days",
                },
            )

    if format == "snapshot":
        snapshot = build_attempt_replay(session, attempt_id)
        if not snapshot["timeline"]:
            raise HTTPException(
                status_code=404,
                detail={"reason": f"No events found for attempt_id={attempt_id!r}"},
            )
        return snapshot

    events = serialize_raw_events(session, attempt_id)
    if not events:
        raise HTTPException(
            status_code=404,
            detail={"reason": f"No events found for attempt_id={attempt_id!r}"},
        )
    return {"attempt_id": attempt_id, "event_count": len(events), "events": events}


@router.get("/audit/runs")
def get_runs_index(
    agent_id: str | None = Query(default=None),
    session_id: str | None = Query(default=None),
    tool_family: str | None = Query(default=None),
    decision: str | None = Query(default=None),
    started_after: str | None = Query(default=None),
    started_before: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
):
    """Return a paginated index of recent governed runs.

    One row per governed run derived from canonical persisted state.
    Each row includes attempt_id usable directly with GET /v1/audit/replay.

    Filters (all optional, all applied at DB level):
      agent_id, session_id, tool_family, decision (ALLOW|BLOCK|APPROVAL_REQUIRED),
      started_after (ISO datetime), started_before (ISO datetime)

    Ordering: started_at DESC, attempt_id ASC (deterministic tie-break).

    LIC-01 gate point: check entitlement for runs_index_access feature here.
    Candidates: max runs returned (retention window), plan_code feature flag,
    started_after lower bound enforcement for free/trial tiers.
    """
    try:
        result = list_runs(
            session,
            agent_id=agent_id,
            session_id=session_id,
            tool_family=tool_family,
            decision=decision,
            started_after=started_after,
            started_before=started_before,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"reason": str(exc)}) from exc
    return result