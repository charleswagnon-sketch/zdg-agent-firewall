"""Admin routes for agent lifecycle management."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlmodel import Session

from api.auth import require_admin
from core import contracts as contracts_manager
from core import credentialing
from core import agents as agent_manager
from core.audit import append_audit_event, append_audit_event_with_session_chain
from core.schemas import AgentContract, AgentRegisterRequest, AgentStatusRequest, CredentialGrant
from db.sqlite import get_session

router = APIRouter(dependencies=[Depends(require_admin)])


@router.post("/agents")
def register_agent(
    body: AgentRegisterRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    state = request.app.state.zdg
    try:
        record = agent_manager.register_agent(
            session=session,
            agent_id=body.agent_id,
            agent_type=body.agent_type,
            metadata=body.metadata,
            registered_by=body.operator,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail={"reason": str(exc)}) from exc

    append_audit_event(
        session,
        state.settings.zdg_chain_id,
        "AGENT_REGISTERED",
        {
            "agent_id": body.agent_id,
            "agent_type": body.agent_type,
            "operator": body.operator,
            "metadata": body.metadata or {},
        },
    )
    session.commit()
    return record


@router.get("/agents")
def list_agents(
    agent_type: str | None = Query(default=None),
    status: str | None = Query(default=None),
    session: Session = Depends(get_session),
):
    return {
        "count": len(agent_manager.list_agents(session=session, agent_type=agent_type, status=status)),
        "agents": agent_manager.list_agents(session=session, agent_type=agent_type, status=status),
    }


@router.get("/agents/{agent_id}")
def get_agent(agent_id: str, session: Session = Depends(get_session)):
    record = agent_manager.get_agent(session=session, agent_id=agent_id)
    if record is None:
        raise HTTPException(status_code=404, detail={"reason": "Agent not found."})
    return record


@router.post("/agents/{agent_id}/suspend")
def suspend_agent(
    agent_id: str,
    body: AgentStatusRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    return _update_agent_status(
        action="AGENT_SUSPENDED_MANUAL",
        updater=agent_manager.suspend_agent,
        agent_id=agent_id,
        body=body,
        request=request,
        session=session,
    )


@router.post("/agents/{agent_id}/unsuspend")
def unsuspend_agent(
    agent_id: str,
    body: AgentStatusRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    return _update_agent_status(
        action="AGENT_UNSUSPENDED",
        updater=agent_manager.unsuspend_agent,
        agent_id=agent_id,
        body=body,
        request=request,
        session=session,
    )


@router.post("/agents/{agent_id}/deregister")
def deregister_agent(
    agent_id: str,
    body: AgentStatusRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    return _update_agent_status(
        action="AGENT_DEREGISTERED",
        updater=agent_manager.deregister_agent,
        agent_id=agent_id,
        body=body,
        request=request,
        session=session,
    )


def _update_agent_status(action, updater, agent_id: str, body: AgentStatusRequest, request: Request, session: Session):
    state = request.app.state.zdg
    try:
        record = updater(session=session, agent_id=agent_id, operator=body.operator, reason=body.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail={"reason": str(exc)}) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail={"reason": str(exc)}) from exc

    append_audit_event(
        session,
        state.settings.zdg_chain_id,
        action,
        {
            "agent_id": agent_id,
            "operator": body.operator,
            "reason": body.reason,
            "status": record["status"],
        },
    )
    if action in {"AGENT_SUSPENDED_MANUAL", "AGENT_DEREGISTERED"}:
        revoked = credentialing.revoke_active_grants(
            session=session,
            agent_id=agent_id,
            revoked_reason=record["status"],
            revoked_by=body.operator,
        )
        for grant in revoked:
            _append_credential_revocation_event(
                session=session,
                chain_id=state.settings.zdg_chain_id,
                grant=grant,
                operator=body.operator,
            )
    # Contract revocation for suspend only.
    # Deregister excluded: _set_status() does not enforce terminal semantics —
    # unsuspend_agent() can re-activate a deregistered agent through the same path.
    if action == "AGENT_SUSPENDED_MANUAL":
        revoked_contracts = contracts_manager.revoke_active_contracts(
            session=session,
            agent_id=agent_id,
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
) -> None:
    append_audit_event(
        session,
        chain_id,
        "CREDENTIAL_REVOKED",
        credentialing.build_credential_event_payload(
            grant,
            event_type="CREDENTIAL_REVOKED",
            operator=operator,
        ),
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
