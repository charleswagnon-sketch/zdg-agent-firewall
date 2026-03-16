"""api/routes/killswitch.py - GET /v1/killswitch, POST /v1/killswitch/*"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlmodel import Session

from api.auth import require_admin
from core import contracts as contracts_manager
from core import credentialing
from core import killswitch as ks_manager
from core.audit import append_audit_event, append_audit_event_with_session_chain
from core.schemas import AgentContract, CredentialGrant, KillSwitchResetRequest, KillSwitchStatus
from db.sqlite import get_session

router = APIRouter(dependencies=[Depends(require_admin)])


@router.get("/killswitch", response_model=KillSwitchStatus)
def get_killswitch_status(session: Session = Depends(get_session)):
    status = ks_manager.get_status(session)
    return KillSwitchStatus(**status)


@router.post("/killswitch/reset")
def reset_killswitch(
    body: KillSwitchResetRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    state = request.app.state.zdg
    count = ks_manager.reset_killswitch(
        session=session,
        operator=body.operator,
        scope=body.scope,
        scope_value=body.scope_value,
    )
    append_audit_event(
        session,
        state.settings.zdg_chain_id,
        "KILLSWITCH_MANUAL_RESET",
        {
            "operator": body.operator,
            "scope": body.scope.value,
            "scope_value": body.scope_value,
            "reset_count": count,
            "comment": body.comment,
        },
    )
    session.commit()
    return {"reset_count": count, "operator": body.operator, "scope": body.scope}


@router.post("/killswitch/activate")
def activate_killswitch(
    body: KillSwitchResetRequest,
    request: Request,
    session: Session = Depends(get_session),
):
    """Manually activate a kill switch at any scope."""

    state = request.app.state.zdg
    ks_id = ks_manager.activate_killswitch(
        session=session,
        scope=body.scope,
        scope_value=body.scope_value,
        trigger_reason=body.comment or "Manually activated by operator",
    )
    append_audit_event(
        session,
        state.settings.zdg_chain_id,
        "KILLSWITCH_MANUAL_ACTIVATE",
        {
            "operator": body.operator,
            "scope": body.scope.value,
            "scope_value": body.scope_value,
            "killswitch_id": ks_id,
            "comment": body.comment,
        },
    )
    revoke_kwargs = {
        "session": session,
        "revoked_reason": f"killswitch:{body.scope.value}",
        "revoked_by": body.operator,
    }
    if body.scope.value == "session":
        revoke_kwargs["session_id"] = body.scope_value
    elif body.scope.value == "agent":
        revoke_kwargs["agent_id"] = body.scope_value
    elif body.scope.value == "tool_family":
        revoke_kwargs["tool_family"] = body.scope_value

    revoked = credentialing.revoke_active_grants(**revoke_kwargs)
    for grant in revoked:
        _append_credential_revocation_event(
            session=session,
            chain_id=state.settings.zdg_chain_id,
            grant=grant,
            operator=body.operator,
        )

    # Contract revocation: global, agent, and session scopes only.
    # tool_family scope is intentionally excluded — AgentContractRecord has no
    # single tool_family field; contracts span multiple families.
    contract_revoke_kwargs: dict = {
        "session": session,
        "revoked_reason": f"killswitch:{body.scope.value}",
        "revoked_by": body.operator,
    }
    if body.scope.value == "global":
        contract_revoke_kwargs["allow_global"] = True
    elif body.scope.value == "agent":
        contract_revoke_kwargs["agent_id"] = body.scope_value
    elif body.scope.value == "session":
        contract_revoke_kwargs["session_id"] = body.scope_value

    if body.scope.value in {"global", "agent", "session"}:
        revoked_contracts = contracts_manager.revoke_active_contracts(**contract_revoke_kwargs)
        for contract in revoked_contracts:
            _append_contract_revocation_event(
                session=session,
                chain_id=state.settings.zdg_chain_id,
                contract=contract,
                operator=body.operator,
            )

    session.commit()
    return {"activated": True, "killswitch_id": ks_id, "scope": body.scope}


def _append_credential_revocation_event(
    *,
    session: Session,
    chain_id: str,
    grant: CredentialGrant,
    operator: str,
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
