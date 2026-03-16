from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlmodel import SQLModel, Session, create_engine, select

from core import credentialing
from core.modes import CredentialLeaseState, ReasonCode
from core.schemas import ActionRequest, ActorIdentity, AgentIdentity, CredentialGrant, DelegationChain, RunAuthorityContext
from db.models import CredentialGrantRecord
from wrappers.base import BaseWrapper, ExecutionContext, WrapperResult


def _make_session() -> Session:
    import db.models  # noqa: F401

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    return Session(engine)


def _authority_context(
    *,
    run_id: str = "run_credential",
    session_id: str | None = "session_credential",
    trace_id: str = "trace_credential",
    agent_id: str = "agent-credential",
    tool_family: str = "shell",
    action: str = "execute",
) -> RunAuthorityContext:
    return RunAuthorityContext(
        run_id=run_id,
        session_id=session_id,
        trace_id=trace_id,
        actor_identity=ActorIdentity(
            actor_id="ops@example.com",
            actor_type="human",
            tenant_id="tenant-a",
            role_bindings=["operator"],
        ),
        agent_identity=AgentIdentity(
            agent_id=agent_id,
            allowed_tool_families=[tool_family],
            lifecycle_state="active",
        ),
        delegation_chain=DelegationChain(
            delegation_chain_id=f"dlg_{agent_id}_{tool_family}_{action}",
            root_actor_id="ops@example.com",
            delegated_agent_ids=[agent_id],
            authority_scope={"tool_family": tool_family, "action": action},
        ),
        requested_tool_family=tool_family,
        requested_operation=action,
        policy_bundle_id="bundle-a",
        policy_bundle_version="1.0.0",
    )


def test_validate_authority_context_requires_explicit_binding_for_privileged_real_execution():
    authority_context = _authority_context()
    body = ActionRequest(
        agent_id="agent-credential",
        tool_family="shell",
        action="execute",
        args={"command": "echo safe"},
    )
    context = ExecutionContext(real_exec_shell=True, tool_family="shell")

    failure = credentialing.validate_authority_context(
        body=body,
        authority_context=authority_context,
        context=context,
        evaluation_time=datetime.now(timezone.utc).replace(tzinfo=None),
    )

    assert failure is not None
    assert failure[0] == ReasonCode.AUTHORITY_BINDING_REQUIRED


def test_issue_activate_and_revoke_credential_grant_round_trip():
    session = _make_session()
    authority_context = _authority_context()
    issued_at = datetime.now(timezone.utc).replace(tzinfo=None)
    body = ActionRequest(
        agent_id="agent-credential",
        tool_family="shell",
        action="execute",
        args={"command": "echo safe"},
        actor_identity=authority_context.actor_identity,
        delegation_chain=authority_context.delegation_chain,
    )

    grant = credentialing.issue_credential_grant(
        session=session,
        authority_context=authority_context,
        body=body,
        ttl_seconds=120,
        issued_at=issued_at,
    )
    activated = credentialing.activate_credential_grant(
        session=session,
        grant_id=grant.grant_id,
        activated_at=issued_at,
    )
    revoked = credentialing.revoke_credential_grant(
        session=session,
        grant_id=grant.grant_id,
        revoked_reason="execution_completed",
        revoked_by="ops@example.com",
        revoked_at=issued_at,
    )
    session.commit()

    assert activated.lease_state == CredentialLeaseState.ACTIVE
    assert revoked is not None
    assert revoked.lease_state == CredentialLeaseState.REVOKED
    assert revoked.revoked_reason == "execution_completed"

    stored = session.exec(select(CredentialGrantRecord)).one()
    assert stored.actor_id == "ops@example.com"
    assert stored.tool_family == "shell"


def test_revoke_active_grants_revokes_matching_scope_only():
    session = _make_session()
    issued_at = datetime.now(timezone.utc).replace(tzinfo=None)

    for grant_id, session_id in [("grt_a", "session-a"), ("grt_b", "session-b")]:
        session.add(
            CredentialGrantRecord(
                grant_id=grant_id,
                run_id=f"run-{grant_id}",
                session_id=session_id,
                trace_id=f"trace-{grant_id}",
                actor_id="ops@example.com",
                agent_id="agent-credential",
                delegation_chain_id=f"dlg-{grant_id}",
                tool_family="shell",
                action="execute",
                privilege_scope_json="{}",
                lease_state=CredentialLeaseState.ACTIVE.value,
                issued_at=issued_at,
                activated_at=issued_at,
                expires_at=issued_at + timedelta(minutes=5),
            )
        )
    session.commit()

    revoked = credentialing.revoke_active_grants(
        session=session,
        session_id="session-a",
        revoked_reason="session_closed",
        revoked_by="ops@example.com",
        revoked_at=issued_at,
    )
    session.commit()

    assert len(revoked) == 1
    assert revoked[0].session_id == "session-a"
    records = {record.grant_id: record for record in session.exec(select(CredentialGrantRecord)).all()}
    assert records["grt_a"].lease_state == CredentialLeaseState.REVOKED.value
    assert records["grt_b"].lease_state == CredentialLeaseState.ACTIVE.value


def test_credential_event_payload_includes_canonical_correlation_fields():
    authority_context = _authority_context()
    grant = CredentialGrant(
        grant_id="grt_test",
        run_id=authority_context.run_id,
        session_id=authority_context.session_id,
        trace_id=authority_context.trace_id,
        actor_id=authority_context.actor_identity.actor_id,
        agent_id=authority_context.agent_identity.agent_id,
        delegation_chain_id=authority_context.delegation_chain.delegation_chain_id,
        tool_family="shell",
        action="execute",
        privilege_scope={"tool_family": "shell", "action": "execute"},
        lease_state=CredentialLeaseState.REVOKED,
        issued_at=datetime(2026, 3, 13, 10, 0, 0),
        activated_at=datetime(2026, 3, 13, 10, 0, 5),
        expires_at=datetime(2026, 3, 13, 10, 5, 0),
        revoked_at=datetime(2026, 3, 13, 10, 0, 10),
        revoked_reason="execution_completed",
        revoked_by="ops@example.com",
    )

    payload = credentialing.build_credential_event_payload(
        grant,
        event_type="CREDENTIAL_REVOKED",
        authority_context=authority_context,
        operator="ops@example.com",
    )

    assert payload["run_id"] == authority_context.run_id
    assert payload["session_id"] == authority_context.session_id
    assert payload["trace_id"] == authority_context.trace_id
    assert payload["actor_id"] == "ops@example.com"
    assert payload["agent_id"] == "agent-credential"
    assert payload["delegation_id"] == authority_context.delegation_chain.delegation_chain_id
    assert payload["authority_scope"] == {"tool_family": "shell", "action": "execute"}
    assert payload["decision_state"] is None
    assert payload["disposition"] is None
    assert payload["source_component"] == "agent_firewall.credentialing"
    assert payload["timestamp"] == "2026-03-13T10:00:10"


def test_revoked_credential_cannot_continue_privileged_wrapper_execution():
    class DummyShellWrapper(BaseWrapper):
        tool_family = "shell"

        def normalize(self, args):
            return args

        def execute(self, request):
            return WrapperResult(executed=True, mock=False, output_summary="should not run")

    wrapper = DummyShellWrapper(
        context=ExecutionContext(
            real_exec_shell=True,
            tool_family="shell",
            credential_grant_id="grt_revoked",
            credential_lease_state=CredentialLeaseState.REVOKED.value,
            privilege_scope={"tool_family": "shell", "action": "execute"},
        )
    )

    result = wrapper.run({"command": "echo blocked"})

    assert result.executed is False
    assert result.blocked_reason == "Scoped credential grant is required before privileged real execution."
