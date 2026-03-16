"""
api/routes/support.py — Trial support bundle and feedback endpoints.

Designed for ZDG-FR Developer Edition external trial support. All endpoints
are admin-only and deliberately safe: the support bundle never exposes
secrets, tokens, credential material, or raw agent payloads.

Endpoints:
  GET  /v1/support/bundle    — structured diagnostic snapshot for triage
  POST /v1/support/feedback  — submit trial feedback (stored locally)
"""

from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from api.auth import require_admin
from core.licensing import get_license_status
from core.runs import list_runs
from db.models import TrialFeedback
from db.sqlite import get_session

router = APIRouter(dependencies=[Depends(require_admin)])

# ── Request schema ────────────────────────────────────────────────────────────

ALLOWED_FEEDBACK_TYPES = {"bug_report", "feature_request", "general"}


class FeedbackRequest(BaseModel):
    """Structured trial feedback payload.

    feedback_type: bug_report | feature_request | general
    description:   human-readable description (max 5 000 chars)
    context:       optional non-secret context dict (steps to reproduce, env notes, etc.)
                   Never put tokens, passwords, or credential material here.
    """

    feedback_type: str
    description: str = Field(min_length=1, max_length=5000)
    context: dict = Field(default_factory=dict)


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/support/bundle")
def get_support_bundle(
    request: Request,
    session: Session = Depends(get_session),
):
    """Return a safe diagnostic snapshot for trial triage.

    Safe to share with support. Contains:
      - app version and platform basics
      - config health indicators (booleans only — no secret values)
      - license status summary (plan, status, usage counts)
      - recent run attempt IDs (last 10)
      - trial feedback count

    Explicitly excluded:
      - ZDG_ADMIN_TOKEN value (exposed as boolean 'admin_token_set' only)
      - raw agent payloads, authority context, credential material
      - any PII from ToolAttempt or AuditEvent records
    """
    from api.app import APP_VERSION

    state = request.app.state.zdg
    settings = state.settings
    bundle = state.bundle

    # Recent runs — attempt_ids only, no payloads
    runs_data = list_runs(session, limit=10)
    recent_attempt_ids = [r["attempt_id"] for r in runs_data["runs"]]

    # License summary — get_license_status is already sanitized
    lic = get_license_status(session)
    lic_license = lic.get("license") or {}
    license_summary = {
        "unmanaged_mode": lic["unmanaged_mode"],
        "status": lic_license.get("status"),
        "plan_code": lic_license.get("plan_code"),
        "usage_summary": lic.get("usage_summary"),
        "status_message": lic.get("status_message"),
    }

    # Feedback count
    feedback_count = len(session.exec(select(TrialFeedback)).all())

    return {
        "bundle_id": f"sup_{uuid4().hex[:16]}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "app": {
            "version": APP_VERSION,
            "policy_bundle_id": bundle.bundle_id,
            "policy_bundle_version": bundle.version,
        },
        "platform": {
            "python_version": platform.python_version(),
            "os": sys.platform,
            "arch": platform.machine(),
        },
        "config_health": {
            # Sensitive values exposed as booleans only — never the actual value
            "admin_token_set": bool(settings.zdg_admin_token.strip()),
            "chain_id": settings.zdg_chain_id,       # not a secret; needed for triage
            "log_format": settings.zdg_log_format,
            "env": settings.zdg_env,
            "real_exec_enabled": settings.zdg_real_exec,
            "real_exec_shell": settings.zdg_real_exec_shell,
            "real_exec_http": settings.zdg_real_exec_http,
            "real_exec_filesystem": settings.zdg_real_exec_filesystem,
            "real_exec_messaging": settings.zdg_real_exec_messaging,
            "contract_expiry_sweep_enabled": (
                settings.zdg_contract_expiry_sweep_interval_seconds > 0
            ),
        },
        "license": license_summary,
        "recent_runs": {
            "total_count": runs_data["count"],
            "attempt_ids": recent_attempt_ids,
        },
        "trial_feedback": {
            "count": feedback_count,
        },
    }


@router.post("/support/feedback", status_code=201)
def submit_feedback(
    body: FeedbackRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    """Submit structured trial feedback.

    Stored locally in the trial_feedback table. Included (count + IDs) in
    GET /v1/support/bundle so support engineers can ask for specific feedback
    entries if needed.

    Do not include secrets, tokens, or credential material in the context field.
    """
    from api.app import APP_VERSION

    if body.feedback_type not in ALLOWED_FEEDBACK_TYPES:
        raise HTTPException(
            status_code=422,
            detail={
                "reason": f"Invalid feedback_type {body.feedback_type!r}. "
                f"Must be one of: {sorted(ALLOWED_FEEDBACK_TYPES)}",
            },
        )

    feedback_id = f"fbk_{uuid4().hex[:16]}"
    fb = TrialFeedback(
        feedback_id=feedback_id,
        feedback_type=body.feedback_type,
        description=body.description,
        context=json.dumps(body.context) if body.context else None,
        app_version=APP_VERSION,
    )
    session.add(fb)
    session.commit()

    return {
        "feedback_id": feedback_id,
        "feedback_type": body.feedback_type,
        "created_at": fb.created_at.isoformat() if fb.created_at else None,
    }
