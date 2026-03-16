"""api/routes/policy.py - POST /v1/policy/reload."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlmodel import Session

from api.auth import require_admin
from api.state import AppState
from core.audit import append_audit_event
from core.logging import log_policy_reload
from core.policy import load_bundle
from db.sqlite import get_session

router = APIRouter(dependencies=[Depends(require_admin)])


@router.post("/policy/reload")
def reload_policy_bundle(
    request: Request,
    session: Session = Depends(get_session),
):
    state: AppState = request.app.state.zdg
    old_bundle = state.bundle

    try:
        new_bundle = load_bundle(state.settings.policy_bundle_path_resolved)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail={"reason": str(exc)},
        ) from exc

    if new_bundle.ruleset_hash == old_bundle.ruleset_hash:
        return {
            "reloaded": False,
            "old_bundle_id": old_bundle.bundle_id,
            "old_version": old_bundle.version,
            "old_ruleset_hash": old_bundle.ruleset_hash,
            "new_bundle_id": new_bundle.bundle_id,
            "new_version": new_bundle.version,
            "new_ruleset_hash": new_bundle.ruleset_hash,
        }

    append_audit_event(
        session,
        state.settings.zdg_chain_id,
        "POLICY_RELOAD",
        {
            "old_bundle_id": old_bundle.bundle_id,
            "old_version": old_bundle.version,
            "old_ruleset_hash": old_bundle.ruleset_hash,
            "new_bundle_id": new_bundle.bundle_id,
            "new_version": new_bundle.version,
            "new_ruleset_hash": new_bundle.ruleset_hash,
        },
    )
    session.commit()
    state.bundle = new_bundle

    log_policy_reload(
        state.logger,
        request_id=getattr(request.state, "request_id", None),
        chain_id=state.settings.zdg_chain_id,
        old_bundle_id=old_bundle.bundle_id,
        old_version=old_bundle.version,
        new_bundle_id=new_bundle.bundle_id,
        new_version=new_bundle.version,
        new_ruleset_hash=new_bundle.ruleset_hash,
    )

    return {
        "reloaded": True,
        "old_bundle_id": old_bundle.bundle_id,
        "old_version": old_bundle.version,
        "old_ruleset_hash": old_bundle.ruleset_hash,
        "new_bundle_id": new_bundle.bundle_id,
        "new_version": new_bundle.version,
        "new_ruleset_hash": new_bundle.ruleset_hash,
    }