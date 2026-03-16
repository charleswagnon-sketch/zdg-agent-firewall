"""api/routes/approvals.py - GET /v1/approvals, POST /v1/approval/{id}"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlmodel import Session

from api.auth import require_admin
from core import approval as approval_manager
from core.audit import append_audit_event
from core.modes import ReasonCode
from core.schemas import ApprovalRequest, ApprovalResponse
from db.models import Approval
from db.sqlite import get_session

router = APIRouter(dependencies=[Depends(require_admin)])


@router.get("/approvals")
def list_approvals(session: Session = Depends(get_session)):
    pending = approval_manager.get_pending(session)
    return {"count": len(pending), "approvals": pending}


@router.post("/approval/{approval_id}", response_model=ApprovalResponse)
def resolve_approval(
    approval_id: str,
    body: ApprovalRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    state = request.app.state.zdg
    record = session.get(Approval, approval_id)
    bound_decision_id = record.decision_id if record else approval_id

    success, reason_code, human_reason = approval_manager.resolve_approval(
        session=session,
        approval_id=approval_id,
        incoming_payload_hash=body.payload_hash,
        incoming_decision_id=bound_decision_id,
        incoming_bundle_version=state.bundle.version,
        approved=body.approve,
        operator=body.operator,
        comment=body.comment,
    )

    if not success:
        session.commit()
        if reason_code == ReasonCode.APPROVAL_NOT_FOUND:
            raise HTTPException(
                status_code=404,
                detail={"reason_code": reason_code, "reason": human_reason},
            )
        if reason_code == ReasonCode.APPROVAL_EXPIRED:
            raise HTTPException(
                status_code=403,
                detail={"reason_code": reason_code, "reason": human_reason},
            )
        raise HTTPException(
            status_code=409,
            detail={"reason_code": reason_code, "reason": human_reason},
        )

    append_audit_event(
        session,
        state.settings.zdg_chain_id,
        "APPROVAL_RESOLVED",
        {
            "approval_id": approval_id,
            "approved": body.approve,
            "operator": body.operator,
            "reason_code": reason_code.value,
            "decision_id": bound_decision_id,
        },
    )
    session.commit()

    return ApprovalResponse(
        approval_id=approval_id,
        status="approved" if body.approve else "denied",
        decision="ALLOW" if body.approve else "BLOCK",
        reason_code=reason_code,
        reason=human_reason,
        resolved_at=datetime.now(timezone.utc),
    )