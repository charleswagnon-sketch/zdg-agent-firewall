"""api/routes/investigate.py - POST /v1/investigate."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from sqlmodel import Session

from api.auth import require_admin
from api.state import AppState
from core.contracts import get_contract_state_view
from core.evaluation import evaluate_request, utc_now
from core.schemas import ActionRequest, InvestigationResponse
from db.sqlite import get_session

router = APIRouter(dependencies=[Depends(require_admin)])


@router.post("/investigate", response_model=InvestigationResponse)
def investigate_action(
    body: ActionRequest,
    request: Request,
    session: Session = Depends(get_session),
) -> InvestigationResponse:
    state: AppState = request.app.state.zdg
    trace_id = f"zdg_{uuid.uuid4().hex[:8]}"
    run_id = f"inv_{uuid.uuid4().hex[:16]}"
    artifacts = evaluate_request(
        session=session,
        bundle=state.bundle,
        workspace=state.settings.workspace_resolved,
        body=body,
        run_id=run_id,
        trace_id=trace_id,
        timestamp=utc_now(),
        risk_block_count_window_seconds=state.settings.zdg_risk_block_count_window_seconds,
        risk_repeated_denials_threshold=state.settings.zdg_risk_repeated_denials_threshold,
        guardrail_parallel_enabled=state.settings.zdg_guardrail_parallel_enabled,
        guardrail_parallel_workers=state.settings.zdg_guardrail_parallel_workers,
        guardrail_pii_enabled=state.settings.zdg_guardrail_pii_enabled,
        guardrail_toxicity_enabled=state.settings.zdg_guardrail_toxicity_enabled,
        guardrail_jailbreak_enabled=state.settings.zdg_guardrail_jailbreak_enabled,
        streaming_guardrails_enabled=state.settings.zdg_streaming_guardrails_enabled,
        streaming_release_hold_chars=state.settings.zdg_streaming_release_hold_chars,
    )
    contract_state_view = (
        get_contract_state_view(session=session, session_id=body.session_id)
        if body.session_id
        else None
    )
    return InvestigationResponse(
        **artifacts.trace.model_dump(),
        contract_state_view=contract_state_view,
    )
