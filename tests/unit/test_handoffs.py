from __future__ import annotations

from datetime import datetime

from core import handoffs
from core.modes import Disposition, HandoffValidationState
from core.schemas import ActorIdentity, AgentIdentity, DelegationChain, RunAuthorityContext


def _authority_context() -> RunAuthorityContext:
    return RunAuthorityContext(
        run_id="run_handoff",
        session_id="ses_handoff",
        trace_id="trc_handoff",
        actor_identity=ActorIdentity(
            actor_id="ops@example.com",
            actor_type="human",
            tenant_id="tenant-a",
            role_bindings=["operator"],
        ),
        agent_identity=AgentIdentity(
            agent_id="agent-handoff",
            allowed_tool_families=["shell"],
            lifecycle_state="active",
        ),
        delegation_chain=DelegationChain(
            delegation_chain_id="dlg_handoff",
            root_actor_id="ops@example.com",
            delegated_agent_ids=["agent-handoff"],
            authority_scope={"tool_family": "shell", "action": "execute"},
        ),
        requested_tool_family="shell",
        requested_operation="execute",
        policy_bundle_id="bundle-a",
        policy_bundle_version="1.0.0",
    )


def test_resolve_handoff_schema_uses_static_registry_version():
    schema = handoffs.resolve_handoff_schema("shell", "execute")

    assert schema is not None
    assert schema.schema_id == "handoff.shell.execute"
    assert schema.schema_version == "1.0"


def test_validate_handoff_fails_closed_for_missing_required_field():
    envelope = handoffs.build_handoff_envelope(
        authority_context=_authority_context(),
        tool_family="shell",
        action="execute",
        args={"cwd": "C:/tmp"},
        timestamp=datetime(2026, 3, 13, 12, 0, 0),
    )
    schema = handoffs.resolve_handoff_schema("shell", "execute")

    result = handoffs.validate_handoff(envelope, schema)

    assert result.valid is False
    assert result.validation_state == HandoffValidationState.FAILED
    assert result.schema_version == "1.0"
    assert result.disposition == Disposition.BLOCK
    assert any("command" in error for error in result.errors)

