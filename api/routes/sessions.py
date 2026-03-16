"""Admin routes for session lifecycle management."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlmodel import Session

from api.auth import require_admin
from core import contracts as contracts_manager
from core import credentialing
from core import sessions as session_manager
from core.audit import append_audit_event_with_session_chain
from core.contracts import utc_now
from core.schemas import AgentContract, ContractReinstatementResponse, ContractRenewalResponse, CredentialGrant, SessionCreateRequest, SessionStatusRequest
from db.sqlite import get_session

router = APIRouter(dependencies=[Depends(require_admin)])


@router.post("/sessions")
def create_session(
    body: SessionCreateRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    state = request.app.state.zdg
    record = session_manager.create_session(
        session=session,
        agent_id=body.agent_id,
        metadata=body.metadata,
        created_by=body.operator,
        creation_source=body.creation_source,
    )
    append_audit_event_with_session_chain(
        session=session,
        global_chain_id=state.settings.zdg_chain_id,
        session_id=record["session_id"],
        event_type="SESSION_CREATED",
        event_payload={
            "session_id": record["session_id"],
            "agent_id": record["agent_id"],
            "operator": body.operator,
            "creation_source": body.creation_source,
            "metadata": body.metadata or {},
        },
    )
    session.commit()
    return record


@router.get("/sessions")
def list_sessions(
    agent_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    session: Session = Depends(get_session),
):
    records = session_manager.list_sessions(session=session, agent_id=agent_id, status=status)
    return {"count": len(records), "sessions": records}


@router.get("/sessions/{session_id}")
def get_session_info(session_id: str, session: Session = Depends(get_session)):
    record = session_manager.get_session_info(session=session, session_id=session_id)
    if record is None:
        raise HTTPException(status_code=404, detail={"reason": "Session not found."})
    return record


@router.post("/sessions/{session_id}/close")
def close_session(
    session_id: str,
    body: SessionStatusRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    return _update_session_status(
        event_type="SESSION_CLOSED_EVENT",
        updater=session_manager.close_session,
        session_id=session_id,
        body=body,
        request=request,
        session=session,
    )


@router.post("/sessions/{session_id}/suspend")
def suspend_session(
    session_id: str,
    body: SessionStatusRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    return _update_session_status(
        event_type="SESSION_SUSPENDED_EVENT",
        updater=session_manager.suspend_session,
        session_id=session_id,
        body=body,
        request=request,
        session=session,
    )


@router.post("/sessions/{session_id}/unsuspend")
def unsuspend_session(
    session_id: str,
    body: SessionStatusRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    return _update_session_status(
        event_type="SESSION_UNSUSPENDED_EVENT",
        updater=session_manager.unsuspend_session,
        session_id=session_id,
        body=body,
        request=request,
        session=session,
    )


def _update_session_status(event_type, updater, session_id: str, body: SessionStatusRequest, request: Request, session: Session):
    state = request.app.state.zdg
    try:
        record = updater(session=session, session_id=session_id, operator=body.operator, reason=body.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail={"reason": str(exc)}) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail={"reason": str(exc)}) from exc

    append_audit_event_with_session_chain(
        session=session,
        global_chain_id=state.settings.zdg_chain_id,
        session_id=session_id,
        event_type=event_type,
        event_payload={
            "session_id": session_id,
            "agent_id": record["agent_id"],
            "operator": body.operator,
            "reason": body.reason,
            "status": record["status"],
        },
    )
    if event_type in {"SESSION_CLOSED_EVENT", "SESSION_SUSPENDED_EVENT"}:
        revoked = credentialing.revoke_active_grants(
            session=session,
            session_id=session_id,
            revoked_reason=record["status"],
            revoked_by=body.operator,
        )
        for grant in revoked:
            _append_credential_revocation_event(
                session=session,
                chain_id=state.settings.zdg_chain_id,
                grant=grant,
                operator=body.operator,
                related_attempt_id=None,
            )
        revoked_contracts = contracts_manager.revoke_active_contracts(
            session=session,
            session_id=session_id,
            revoked_reason=record["status"],
            revoked_by=body.operator,
        )
        for contract in revoked_contracts:
            _append_contract_revocation_event(
                session=session,
                chain_id=state.settings.zdg_chain_id,
                contract=contract,
                operator=body.operator,
            )
    session.commit()
    return record


def _append_credential_revocation_event(
    *,
    session: Session,
    chain_id: str,
    grant: CredentialGrant,
    operator: str,
    related_attempt_id: str | None,
) -> None:
    append_audit_event_with_session_chain(
        session=session,
        global_chain_id=chain_id,
        session_id=grant.session_id,
        event_type="CREDENTIAL_REVOKED",
        event_payload=credentialing.build_credential_event_payload(
            grant,
            event_type="CREDENTIAL_REVOKED",
            operator=operator,
        ),
        related_attempt_id=related_attempt_id,
    )


def _append_contract_revocation_event(
    *,
    session: Session,
    chain_id: str,
    contract: AgentContract,
    operator: str,
) -> None:
    append_audit_event_with_session_chain(
        session=session,
        global_chain_id=chain_id,
        session_id=contract.session_id,
        event_type="CONTRACT_REVOKED",
        event_payload={
            "contract_id": contract.contract_id,
            "run_id": contract.run_id,
            "session_id": contract.session_id,
            "agent_id": contract.agent_id,
            "actor_id": contract.actor_id,
            "delegation_chain_id": contract.delegation_chain_id,
            "revoked_reason": contract.revoked_reason,
            "revoked_by": contract.revoked_by,
            "revoked_at": contract.revoked_at.isoformat() if contract.revoked_at else None,
            "trigger_source": contract.revoked_reason,
        },
    )


@router.post(
    "/sessions/{session_id}/reinstate-contract",
    response_model=ContractReinstatementResponse,
)
def reinstate_contract(
    session_id: str,
    body: SessionStatusRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    """Operator-initiated reinstatement of all REVOKED contracts for a session.

    Transitions every REVOKED AgentContractRecord for the session back to
    ACTIVE and emits a CONTRACT_REINSTATED audit event per reinstated contract
    to both the global and session-scoped audit chains.

    Returns 404 if the session does not exist.
    Returns 409 if no REVOKED contracts exist for the session (nothing to reinstate).

    Does not modify session lifecycle state (closed/suspended sessions remain
    gated by SESSION_CLOSED / SESSION_SUSPENDED before CONTRACT_REVOKED is checked).
    Does not auto-reinstate on kill-switch reset or unsuspend.
    """
    state = request.app.state.zdg

    session_info = session_manager.get_session_info(session=session, session_id=session_id)
    if session_info is None:
        raise HTTPException(status_code=404, detail={"reason": "Session not found."})

    reinstated = contracts_manager.reinstate_revoked_contracts(
        session=session,
        session_id=session_id,
        reinstated_by=body.operator,
        reinstated_reason=body.reason,
    )
    if not reinstated:
        raise HTTPException(
            status_code=409,
            detail={"reason": "No REVOKED contracts found for this session."},
        )

    for contract in reinstated:
        _append_contract_reinstatement_event(
            session=session,
            chain_id=state.settings.zdg_chain_id,
            contract=contract,
            operator=body.operator,
            reinstatement_reason=body.reason,
        )

    session.commit()

    return ContractReinstatementResponse(
        session_id=session_id,
        reinstated_count=len(reinstated),
        reinstated_contract_ids=[c.contract_id for c in reinstated],
        operator=body.operator,
    )


def _append_contract_reinstatement_event(
    *,
    session: Session,
    chain_id: str,
    contract: AgentContract,
    operator: str,
    reinstatement_reason: str,
) -> None:
    """Emit CONTRACT_REINSTATED to global and session-scoped audit chains.

    contract is the pre-reinstatement snapshot — its revoked_reason and
    revoked_by fields still carry the prior revocation facts.
    """
    from datetime import datetime, timezone

    append_audit_event_with_session_chain(
        session=session,
        global_chain_id=chain_id,
        session_id=contract.session_id,
        event_type="CONTRACT_REINSTATED",
        event_payload={
            "contract_id": contract.contract_id,
            "run_id": contract.run_id,
            "session_id": contract.session_id,
            "agent_id": contract.agent_id,
            "actor_id": contract.actor_id,
            "delegation_chain_id": contract.delegation_chain_id,
            "reinstated_by": operator,
            "reinstated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
            "reinstatement_reason": reinstatement_reason,
            "prior_revoked_reason": contract.revoked_reason,
            "prior_revoked_by": contract.revoked_by,
        },
    )


@router.post(
    "/sessions/{session_id}/renew-contract",
    response_model=ContractRenewalResponse,
)
def renew_contract(
    session_id: str,
    body: SessionStatusRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    """Governed renewal of an expired session contract.

    Creates a fresh ACTIVE contract for the session, inheriting authority
    identity (actor, agent, delegation chain, allowed tool families) from the
    most recently expired contract. All un-renewed EXPIRED contracts for the
    session have renewed_at set but remain EXPIRED — no state mutation to ACTIVE.

    Emits CONTRACT_RENEWED per expired contract and CONTRACT_BOUND for the new
    contract to both the global and session-scoped audit chains.

    Returns 404 if the session does not exist.
    Returns 409 if no un-renewed expired contracts exist (nothing to renew).
    """
    state = request.app.state.zdg
    settings = state.settings

    session_info = session_manager.get_session_info(session=session, session_id=session_id)
    if session_info is None:
        raise HTTPException(status_code=404, detail={"reason": "Session not found."})

    bound_at = utc_now()
    expires_at = bound_at + timedelta(seconds=settings.zdg_contract_ttl_seconds)

    result = contracts_manager.renew_expired_contracts(
        session=session,
        session_id=session_id,
        renewed_by=body.operator,
        renewed_reason=body.reason,
        bound_at=bound_at,
        expires_at=expires_at,
    )
    if result is None:
        raise HTTPException(
            status_code=409,
            detail={"reason": "No un-renewed expired contracts found for this session."},
        )

    expired_snapshots, new_contract = result

    for contract in expired_snapshots:
        _append_contract_renewal_event(
            session=session,
            chain_id=settings.zdg_chain_id,
            contract=contract,
            operator=body.operator,
            renewal_reason=body.reason,
            new_contract_id=new_contract.contract_id,
        )

    append_audit_event_with_session_chain(
        session=session,
        global_chain_id=settings.zdg_chain_id,
        session_id=session_id,
        event_type="CONTRACT_BOUND",
        event_payload={
            "contract_id": new_contract.contract_id,
            "run_id": new_contract.run_id,
            "session_id": new_contract.session_id,
            "actor_id": new_contract.actor_id,
            "agent_id": new_contract.agent_id,
            "delegation_chain_id": new_contract.delegation_chain_id,
            "allowed_tool_families": new_contract.allowed_tool_families,
            "contract_state": new_contract.contract_state.value,
            "bound_at": new_contract.bound_at.isoformat(),
            "expires_at": (
                new_contract.expires_at.isoformat()
                if new_contract.expires_at is not None
                else None
            ),
            "renewal": True,
            "renewed_from_contract_ids": [c.contract_id for c in expired_snapshots],
            "renewed_by": body.operator,
        },
    )

    session.commit()

    return ContractRenewalResponse(
        session_id=session_id,
        renewed_count=len(expired_snapshots),
        renewed_contract_ids=[c.contract_id for c in expired_snapshots],
        new_contract_id=new_contract.contract_id,
        operator=body.operator,
    )


def _append_contract_renewal_event(
    *,
    session: Session,
    chain_id: str,
    contract: AgentContract,
    operator: str,
    renewal_reason: str,
    new_contract_id: str,
) -> None:
    """Emit CONTRACT_RENEWED to global and session-scoped audit chains.

    contract is the pre-renewal snapshot — expired_at and the original
    authority fields still reflect the expired contract state.
    """
    append_audit_event_with_session_chain(
        session=session,
        global_chain_id=chain_id,
        session_id=contract.session_id,
        event_type="CONTRACT_RENEWED",
        event_payload={
            "contract_id": contract.contract_id,
            "run_id": contract.run_id,
            "session_id": contract.session_id,
            "agent_id": contract.agent_id,
            "actor_id": contract.actor_id,
            "delegation_chain_id": contract.delegation_chain_id,
            "expired_at": (
                contract.expires_at.isoformat()
                if contract.expires_at is not None
                else None
            ),
            "renewed_by": operator,
            "renewal_reason": renewal_reason,
            "new_contract_id": new_contract_id,
        },
    )
