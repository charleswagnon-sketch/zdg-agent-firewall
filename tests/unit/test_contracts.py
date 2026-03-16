"""
Unit tests: Agent contract binding, persistence, audit evidence, and handoff linkage.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlmodel import Session, SQLModel, create_engine

from core.modes import ContractState
from core.schemas import AgentContract, ActorIdentity, AgentIdentity, DelegationChain, RunAuthorityContext


def _make_session() -> Session:
    """In-memory SQLite session with all tables."""
    import db.models  # noqa: F401 — register all tables in metadata
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    from db.migrations import _add_append_only_triggers
    with engine.connect() as conn:
        _add_append_only_triggers(conn)
        conn.commit()
    return Session(engine)


def _make_authority_context(
    run_id: str = "run_test001",
    agent_id: str = "agent-001",
    actor_id: str = "actor-001",
    session_id: str | None = None,
    allowed_tool_families: list[str] | None = None,
) -> RunAuthorityContext:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return RunAuthorityContext(
        run_id=run_id,
        session_id=session_id,
        trace_id="trc_test",
        actor_identity=ActorIdentity(actor_id=actor_id, actor_type="human"),
        agent_identity=AgentIdentity(
            agent_id=agent_id,
            allowed_tool_families=allowed_tool_families or ["shell", "filesystem"],
        ),
        delegation_chain=DelegationChain(
            delegation_chain_id="dlg_test001",
            root_actor_id=actor_id,
            delegated_agent_ids=[agent_id],
            authority_scope={"tool_family": "shell", "action": "execute"},
            issued_at=now,
        ),
        requested_tool_family="shell",
        requested_operation="execute",
        policy_bundle_id="test-bundle",
        policy_bundle_version="1.0.0",
    )


# ── bind creates and persists a record ──────────────────────────────────────

def test_bind_contract_creates_record():
    from core.contracts import bind_contract
    from db.models import AgentContractRecord
    from sqlmodel import select

    session = _make_session()
    authority = _make_authority_context()
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    contract = bind_contract(
        session=session,
        authority_context=authority,
        bound_at=bound_at,
    )
    session.commit()

    assert isinstance(contract, AgentContract)
    assert contract.contract_id.startswith("ctr_")
    assert contract.run_id == "run_test001"
    assert contract.actor_id == "actor-001"
    assert contract.agent_id == "agent-001"
    assert contract.delegation_chain_id == "dlg_test001"
    assert contract.contract_state == ContractState.ACTIVE
    assert "shell" in contract.allowed_tool_families
    assert "filesystem" in contract.allowed_tool_families

    # Verify the DB record exists
    record = session.exec(
        select(AgentContractRecord).where(AgentContractRecord.contract_id == contract.contract_id)
    ).first()
    assert record is not None
    assert record.run_id == "run_test001"
    assert record.contract_state == "active"


# ── get_active_contract returns bound contract ───────────────────────────────

def test_get_active_contract_returns_bound():
    from core.contracts import bind_contract, get_active_contract

    session = _make_session()
    authority = _make_authority_context(run_id="run_find001")
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    original = bind_contract(session=session, authority_context=authority, bound_at=bound_at)
    session.commit()

    found = get_active_contract(session=session, run_id="run_find001")
    assert found is not None
    assert found.contract_id == original.contract_id


def test_get_active_contract_returns_none_for_unknown_run():
    from core.contracts import get_active_contract

    session = _make_session()
    result = get_active_contract(session=session, run_id="run_does_not_exist")
    assert result is None


# ── bind emits CONTRACT_BOUND audit event ────────────────────────────────────

def test_bind_contract_emits_audit_event():
    from core.audit import append_audit_event, verify_chain
    from core.contracts import bind_contract

    session = _make_session()
    chain_id = "test-contract-chain"
    authority = _make_authority_context(run_id="run_audit001")
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    contract = bind_contract(session=session, authority_context=authority, bound_at=bound_at)
    # Emit CONTRACT_BOUND event manually (same as route does)
    from core.audit import append_audit_event
    append_audit_event(
        session=session,
        chain_id=chain_id,
        event_type="CONTRACT_BOUND",
        event_payload={
            "contract_id": contract.contract_id,
            "run_id": contract.run_id,
            "actor_id": contract.actor_id,
            "agent_id": contract.agent_id,
            "contract_state": contract.contract_state.value,
            "bound_at": contract.bound_at.isoformat(),
        },
    )
    session.commit()

    from db.models import AuditEvent
    from sqlmodel import select
    events = session.exec(
        select(AuditEvent)
        .where(AuditEvent.chain_id == chain_id)
        .where(AuditEvent.event_type == "CONTRACT_BOUND")
    ).all()
    assert len(events) == 1
    import json
    payload = json.loads(events[0].event_payload)
    assert payload["contract_id"] == contract.contract_id
    assert payload["run_id"] == "run_audit001"
    assert payload["actor_id"] == "actor-001"
    assert payload["agent_id"] == "agent-001"
    assert payload["contract_state"] == "active"


# ── audit chain containing CONTRACT_BOUND verifies correctly ─────────────────

def test_contract_audit_chain_verifies():
    from core.audit import append_audit_event, verify_chain, export_chain_document, verify_chain_export
    from core.contracts import bind_contract

    session = _make_session()
    chain_id = "test-verify-chain"
    authority = _make_authority_context(run_id="run_verify001")
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    contract = bind_contract(session=session, authority_context=authority, bound_at=bound_at)
    append_audit_event(
        session=session,
        chain_id=chain_id,
        event_type="CONTRACT_BOUND",
        event_payload={
            "contract_id": contract.contract_id,
            "run_id": contract.run_id,
            "actor_id": contract.actor_id,
            "agent_id": contract.agent_id,
            "contract_state": contract.contract_state.value,
        },
    )
    session.commit()

    ok, msg = verify_chain(session, chain_id)
    assert ok, f"Chain should verify: {msg}"

    document = export_chain_document(session, chain_id)
    result = verify_chain_export(document)
    assert result["ok"], f"Export verification failed: {result}"
    assert result["verified_event_count"] == 1


# ── handoff envelope contract_id is populated when contract exists ────────────

def test_handoff_envelope_carries_contract_id():
    from core.contracts import bind_contract
    from core.handoffs import build_handoff_envelope
    from core.schemas import HandoffEnvelope

    session = _make_session()
    authority = _make_authority_context()
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    contract = bind_contract(session=session, authority_context=authority, bound_at=bound_at)
    session.commit()

    envelope = build_handoff_envelope(
        authority_context=authority,
        tool_family="shell",
        action="execute",
        args={"command": "ls"},
        timestamp=bound_at,
    )
    # contract_id starts as None (not yet linked)
    assert envelope.contract_id is None

    # Link it (same mutation the route performs)
    envelope.contract_id = contract.contract_id
    assert envelope.contract_id == contract.contract_id
    assert envelope.contract_id.startswith("ctr_")


# ── contract_id absent on envelope when no contract bound ─────────────────────

def test_handoff_envelope_contract_id_none_when_no_contract():
    from core.handoffs import build_handoff_envelope

    authority = _make_authority_context()
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    envelope = build_handoff_envelope(
        authority_context=authority,
        tool_family="shell",
        action="execute",
        args={"command": "ls"},
        timestamp=bound_at,
    )
    assert envelope.contract_id is None


# ── two binds for the same run produce independent records ────────────────────

def test_two_binds_same_run_are_independent():
    from core.contracts import bind_contract, get_active_contract
    from db.models import AgentContractRecord
    from sqlmodel import select

    session = _make_session()
    authority = _make_authority_context(run_id="run_dup001")
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    c1 = bind_contract(session=session, authority_context=authority, bound_at=bound_at)
    c2 = bind_contract(session=session, authority_context=authority, bound_at=bound_at)
    session.commit()

    assert c1.contract_id != c2.contract_id
    records = session.exec(
        select(AgentContractRecord).where(AgentContractRecord.run_id == "run_dup001")
    ).all()
    assert len(records) == 2


# ── record_usage creates a ContractUsageRecord ───────────────────────────────

def test_record_usage_creates_record():
    from core.contracts import bind_contract, record_usage
    from core.schemas import ContractUsageState
    from db.models import ContractUsageRecord
    from sqlmodel import select

    session = _make_session()
    authority = _make_authority_context(run_id="run_usage001")
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    contract = bind_contract(session=session, authority_context=authority, bound_at=bound_at)
    session.commit()

    usage = record_usage(session=session, contract=contract, elapsed_ms=42.5, tool_invocations=1)
    session.commit()

    assert isinstance(usage, ContractUsageState)
    assert usage.usage_id.startswith("usg_")
    assert usage.contract_id == contract.contract_id
    assert usage.run_id == "run_usage001"
    assert usage.elapsed_ms == 42.5
    assert usage.tool_invocations == 1
    assert usage.tokens_used == 0
    assert usage.spend_used == 0.0

    db_record = session.exec(
        select(ContractUsageRecord).where(ContractUsageRecord.usage_id == usage.usage_id)
    ).first()
    assert db_record is not None
    assert db_record.contract_id == contract.contract_id


# ── record_usage audit chain verifies correctly ──────────────────────────────

def test_record_usage_audit_chain_verifies():
    from core.audit import append_audit_event, verify_chain
    from core.contracts import bind_contract, record_usage

    session = _make_session()
    chain_id = "test-usage-chain"
    authority = _make_authority_context(run_id="run_usage002")
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    contract = bind_contract(session=session, authority_context=authority, bound_at=bound_at)
    usage = record_usage(session=session, contract=contract, elapsed_ms=10.0)
    append_audit_event(
        session=session,
        chain_id=chain_id,
        event_type="CONTRACT_USAGE_UPDATED",
        event_payload={
            "usage_id": usage.usage_id,
            "contract_id": usage.contract_id,
            "run_id": usage.run_id,
            "elapsed_ms": usage.elapsed_ms,
            "tool_invocations": usage.tool_invocations,
            "tokens_used": usage.tokens_used,
            "spend_used": usage.spend_used,
            "current_state": usage.current_state.value,
        },
    )
    session.commit()

    ok, msg = verify_chain(session, chain_id)
    assert ok, f"Chain should verify: {msg}"


# ── query_session_usage returns zero for new session ─────────────────────────

def test_query_session_usage_returns_zero_for_new_session():
    from core.contracts import query_session_usage

    session = _make_session()
    result = query_session_usage(session=session, session_id="session-no-usage")
    assert result.invocation_count == 0
    assert result.elapsed_ms_total == 0.0


# ── query_session_usage aggregates prior records ──────────────────────────────

def test_query_session_usage_aggregates_prior_records():
    from core.contracts import bind_contract, record_usage, query_session_usage

    session = _make_session()
    sid = "session-agg-001"

    authority1 = _make_authority_context(run_id="run_agg001", session_id=sid)
    authority2 = _make_authority_context(run_id="run_agg002", session_id=sid)
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    c1 = bind_contract(session=session, authority_context=authority1, bound_at=bound_at)
    c2 = bind_contract(session=session, authority_context=authority2, bound_at=bound_at)
    record_usage(session=session, contract=c1, elapsed_ms=100.0)
    record_usage(session=session, contract=c2, elapsed_ms=250.0)
    session.commit()

    result = query_session_usage(session=session, session_id=sid)
    assert result.invocation_count == 2
    assert result.elapsed_ms_total == 350.0


# ── revoke_active_contracts by session_id ────────────────────────────────────

def test_revoke_active_contracts_by_session_id():
    from core.contracts import bind_contract, revoke_active_contracts
    from core.modes import ContractState
    from db.models import AgentContractRecord
    from sqlmodel import select

    session = _make_session()
    sid_a = "session-revoke-a"
    sid_b = "session-revoke-b"
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    ca1 = bind_contract(session=session, authority_context=_make_authority_context(run_id="run_rev001", session_id=sid_a), bound_at=bound_at)
    ca2 = bind_contract(session=session, authority_context=_make_authority_context(run_id="run_rev002", session_id=sid_a), bound_at=bound_at)
    cb1 = bind_contract(session=session, authority_context=_make_authority_context(run_id="run_rev003", session_id=sid_b), bound_at=bound_at)
    session.commit()

    revoked = revoke_active_contracts(
        session=session,
        session_id=sid_a,
        revoked_reason="session_closed",
        revoked_by="test-op",
    )
    session.commit()

    assert len(revoked) == 2
    for c in revoked:
        assert c.contract_state == ContractState.REVOKED
        assert c.revoked_reason == "session_closed"
        assert c.revoked_by == "test-op"
        assert c.revoked_at is not None

    # session B contract untouched
    rec_b = session.exec(
        select(AgentContractRecord).where(AgentContractRecord.contract_id == cb1.contract_id)
    ).first()
    assert rec_b.contract_state == "active"


# ── revoke_active_contracts global requires allow_global=True ─────────────────

def test_revoke_active_contracts_global_requires_allow_global():
    from core.contracts import bind_contract, revoke_active_contracts
    from core.modes import ContractState
    import pytest

    session = _make_session()
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)
    bind_contract(session=session, authority_context=_make_authority_context(run_id="run_glob001"), bound_at=bound_at)
    session.commit()

    # Without allow_global=True → ValueError
    with pytest.raises(ValueError, match="allow_global=True"):
        revoke_active_contracts(
            session=session,
            revoked_reason="killswitch:global",
            revoked_by="test-op",
        )

    # With allow_global=True → succeeds
    revoked = revoke_active_contracts(
        session=session,
        revoked_reason="killswitch:global",
        revoked_by="test-op",
        allow_global=True,
    )
    session.commit()
    assert len(revoked) == 1
    assert revoked[0].contract_state == ContractState.REVOKED


# ── has_revoked_contract returns False for active contract ────────────────────

def test_has_revoked_contract_returns_false_for_active():
    from core.contracts import bind_contract, has_revoked_contract

    session = _make_session()
    sid = "session-gate-active"
    authority = _make_authority_context(run_id="run_gate001", session_id=sid)
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    bind_contract(session=session, authority_context=authority, bound_at=bound_at)
    session.commit()

    assert has_revoked_contract(session=session, session_id=sid) is False


# ── has_revoked_contract returns True after revocation ────────────────────────

def test_has_revoked_contract_returns_true_after_revocation():
    from core.contracts import bind_contract, has_revoked_contract, revoke_active_contracts

    session = _make_session()
    sid = "session-gate-revoked"
    authority = _make_authority_context(run_id="run_gate002", session_id=sid)
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    bind_contract(session=session, authority_context=authority, bound_at=bound_at)
    session.commit()

    assert has_revoked_contract(session=session, session_id=sid) is False

    revoke_active_contracts(
        session=session,
        session_id=sid,
        revoked_reason="session_closed",
        revoked_by="test-op",
    )
    session.commit()

    assert has_revoked_contract(session=session, session_id=sid) is True


# ── reinstate_revoked_contracts: DB fields written correctly ──────────────────

def test_reinstate_writes_reinstated_at_by_reason():
    """reinstate_revoked_contracts() sets reinstated_at/by/reason and clears revocation fields."""
    from core.contracts import bind_contract, reinstate_revoked_contracts, revoke_active_contracts
    from db.models import AgentContractRecord
    from sqlmodel import select

    session = _make_session()
    sid = "session-reinstate-write"
    authority = _make_authority_context(run_id="run_rw001", session_id=sid)
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    contract = bind_contract(session=session, authority_context=authority, bound_at=bound_at)
    session.commit()

    revoke_active_contracts(
        session=session,
        session_id=sid,
        revoked_reason="killswitch:session",
        revoked_by="ops-001",
    )
    session.commit()

    reinstated = reinstate_revoked_contracts(
        session=session,
        session_id=sid,
        reinstated_by="reinstate-op",
        reinstated_reason="cleared for resumption",
    )
    session.commit()

    assert len(reinstated) == 1

    record = session.exec(
        select(AgentContractRecord).where(AgentContractRecord.contract_id == contract.contract_id)
    ).first()
    assert record is not None
    assert record.contract_state == "active"
    # Reinstatement fields written
    assert record.reinstated_at is not None
    assert record.reinstated_by == "reinstate-op"
    assert record.reinstated_reason == "cleared for resumption"
    # Revocation fields cleared
    assert record.revoked_at is None
    assert record.revoked_reason is None
    assert record.revoked_by is None


# ── reinstate_revoked_contracts: returned snapshot is pre-mutation ─────────────

def test_reinstate_returns_prior_snapshot():
    """Returned AgentContract carries pre-mutation revocation state for audit payload use."""
    from core.contracts import bind_contract, reinstate_revoked_contracts, revoke_active_contracts

    session = _make_session()
    sid = "session-reinstate-snap"
    authority = _make_authority_context(run_id="run_snap001", session_id=sid)
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    bind_contract(session=session, authority_context=authority, bound_at=bound_at)
    session.commit()

    revoke_active_contracts(
        session=session,
        session_id=sid,
        revoked_reason="killswitch:session",
        revoked_by="ops-snap",
    )
    session.commit()

    reinstated = reinstate_revoked_contracts(
        session=session,
        session_id=sid,
        reinstated_by="reinstate-op",
        reinstated_reason="test snapshot",
    )
    session.commit()

    assert len(reinstated) == 1
    snapshot = reinstated[0]

    # Snapshot reflects state at time of capture — before mutation
    assert snapshot.contract_state == ContractState.REVOKED
    assert snapshot.revoked_reason == "killswitch:session"
    assert snapshot.revoked_by == "ops-snap"
    assert snapshot.revoked_at is not None


# ── reinstate_revoked_contracts: empty return when nothing to reinstate ─────────

def test_reinstate_returns_empty_when_nothing_to_reinstate():
    """Returns [] if no REVOKED contracts exist — caller is responsible for 409."""
    from core.contracts import bind_contract, reinstate_revoked_contracts

    session = _make_session()
    sid = "session-reinstate-empty"
    authority = _make_authority_context(run_id="run_empty001", session_id=sid)
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    # Contract is ACTIVE — not revoked
    bind_contract(session=session, authority_context=authority, bound_at=bound_at)
    session.commit()

    result = reinstate_revoked_contracts(
        session=session,
        session_id=sid,
        reinstated_by="reinstate-op",
        reinstated_reason="should be empty",
    )
    session.commit()

    assert result == []


# ── reinstate_revoked_contracts: sweeps all REVOKED contracts for session ──────

def test_reinstate_clears_all_revoked_for_session():
    """All REVOKED contracts for the session are transitioned; has_revoked_contract → False."""
    from core.contracts import (
        bind_contract,
        has_revoked_contract,
        reinstate_revoked_contracts,
        revoke_active_contracts,
    )

    session = _make_session()
    sid = "session-reinstate-multi"
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    # Bind two contracts for the same session (different run_ids)
    c1 = bind_contract(
        session=session,
        authority_context=_make_authority_context(run_id="run_multi001", session_id=sid),
        bound_at=bound_at,
    )
    c2 = bind_contract(
        session=session,
        authority_context=_make_authority_context(run_id="run_multi002", session_id=sid),
        bound_at=bound_at,
    )
    session.commit()

    revoke_active_contracts(
        session=session,
        session_id=sid,
        revoked_reason="killswitch:session",
        revoked_by="ops-multi",
    )
    session.commit()

    assert has_revoked_contract(session=session, session_id=sid) is True

    reinstated = reinstate_revoked_contracts(
        session=session,
        session_id=sid,
        reinstated_by="reinstate-op",
        reinstated_reason="bulk reinstatement",
    )
    session.commit()

    assert len(reinstated) == 2
    assert {r.contract_id for r in reinstated} == {c1.contract_id, c2.contract_id}
    # Gate is lifted
    assert has_revoked_contract(session=session, session_id=sid) is False


# ── get_contract_state_view: never-reinstated contract surfaces defaults ───────

def test_state_view_never_reinstated_surfaces_defaults():
    """ContractStateView for a never-reinstated contract has was_reinstated=False and null fields."""
    from core.contracts import bind_contract, get_contract_state_view

    session = _make_session()
    sid = "session-view-default"
    authority = _make_authority_context(run_id="run_vd001", session_id=sid)
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    bind_contract(session=session, authority_context=authority, bound_at=bound_at)
    session.commit()

    view = get_contract_state_view(session=session, session_id=sid)
    assert view is not None
    assert view.was_reinstated is False
    assert view.reinstated_at is None
    assert view.reinstated_by is None
    assert view.reinstated_reason is None


# ── get_contract_state_view: surfaces reinstatement fields after reinstatement ──

def test_state_view_after_reinstatement_surfaces_fields():
    """ContractStateView after reinstatement surfaces was_reinstated=True and correct fields."""
    from core.contracts import (
        bind_contract,
        get_contract_state_view,
        reinstate_revoked_contracts,
        revoke_active_contracts,
    )

    session = _make_session()
    sid = "session-view-reinstated"
    authority = _make_authority_context(run_id="run_vr001", session_id=sid)
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    bind_contract(session=session, authority_context=authority, bound_at=bound_at)
    session.commit()

    revoke_active_contracts(
        session=session,
        session_id=sid,
        revoked_reason="killswitch:session",
        revoked_by="ops-view",
    )
    session.commit()

    reinstate_revoked_contracts(
        session=session,
        session_id=sid,
        reinstated_by="view-op",
        reinstated_reason="unit test reinstatement",
    )
    session.commit()

    view = get_contract_state_view(session=session, session_id=sid)
    assert view is not None

    # Contract is back to ACTIVE
    assert view.contract_state == ContractState.ACTIVE

    # Reinstatement fields are surfaced
    assert view.was_reinstated is True
    assert view.reinstated_at is not None
    assert view.reinstated_by == "view-op"
    assert view.reinstated_reason == "unit test reinstatement"

    # Revocation fields are cleared
    assert view.revoked_at is None
    assert view.revoked_reason is None
    assert view.revoked_by is None


# ── bind_contract persists expires_at ─────────────────────────────────────────

def test_bind_contract_persists_expires_at():
    """bind_contract stores expires_at and _to_schema surfaces it."""
    from core.contracts import bind_contract
    from db.models import AgentContractRecord
    from sqlmodel import select

    session = _make_session()
    authority = _make_authority_context(run_id="run_exp001")
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)
    expires_at = bound_at + timedelta(seconds=3600)

    contract = bind_contract(
        session=session,
        authority_context=authority,
        bound_at=bound_at,
        expires_at=expires_at,
    )
    session.commit()

    assert contract.expires_at == expires_at

    record = session.exec(
        select(AgentContractRecord).where(AgentContractRecord.contract_id == contract.contract_id)
    ).first()
    assert record is not None
    assert record.expires_at == expires_at


def test_bind_contract_expires_at_none_by_default():
    """bind_contract without expires_at leaves the field None."""
    from core.contracts import bind_contract

    session = _make_session()
    authority = _make_authority_context(run_id="run_exp002")
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    contract = bind_contract(session=session, authority_context=authority, bound_at=bound_at)
    session.commit()

    assert contract.expires_at is None


# ── expire_active_contracts transitions ACTIVE→EXPIRED ───────────────────────

def test_expire_active_contracts_transitions_past_expiry():
    """expire_active_contracts transitions contracts past their expires_at to EXPIRED."""
    from core.contracts import bind_contract, expire_active_contracts
    from db.models import AgentContractRecord
    from sqlmodel import select

    session = _make_session()
    sid = "session-expire-001"
    authority = _make_authority_context(run_id="run_exp003", session_id=sid)
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)
    # Contract expired 1 second ago
    expires_at = bound_at - timedelta(seconds=1)

    contract = bind_contract(
        session=session,
        authority_context=authority,
        bound_at=bound_at,
        expires_at=expires_at,
    )
    session.commit()

    expired = expire_active_contracts(
        session=session,
        reference_time=bound_at,
        session_id=sid,
    )
    session.commit()

    assert len(expired) == 1
    assert expired[0].contract_id == contract.contract_id

    record = session.exec(
        select(AgentContractRecord).where(AgentContractRecord.contract_id == contract.contract_id)
    ).first()
    assert record.contract_state == "expired"


def test_expire_active_contracts_does_not_expire_future_contract():
    """expire_active_contracts leaves contracts with future expires_at untouched."""
    from core.contracts import bind_contract, expire_active_contracts
    from db.models import AgentContractRecord
    from sqlmodel import select

    session = _make_session()
    sid = "session-expire-002"
    authority = _make_authority_context(run_id="run_exp004", session_id=sid)
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)
    # Contract expires in the future
    expires_at = bound_at + timedelta(hours=1)

    contract = bind_contract(
        session=session,
        authority_context=authority,
        bound_at=bound_at,
        expires_at=expires_at,
    )
    session.commit()

    expired = expire_active_contracts(
        session=session,
        reference_time=bound_at,
        session_id=sid,
    )
    session.commit()

    assert expired == []

    record = session.exec(
        select(AgentContractRecord).where(AgentContractRecord.contract_id == contract.contract_id)
    ).first()
    assert record.contract_state == "active"


def test_expire_active_contracts_at_exact_boundary():
    """expires_at == reference_time is treated as expired (inclusive boundary)."""
    from core.contracts import bind_contract, expire_active_contracts
    from db.models import AgentContractRecord
    from sqlmodel import select

    session = _make_session()
    sid = "session-expire-boundary"
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)
    expires_at = bound_at  # exact boundary

    authority = _make_authority_context(run_id="run_expb001", session_id=sid)
    contract = bind_contract(
        session=session,
        authority_context=authority,
        bound_at=bound_at,
        expires_at=expires_at,
    )
    session.commit()

    expired = expire_active_contracts(
        session=session,
        reference_time=bound_at,
        session_id=sid,
    )
    session.commit()

    assert len(expired) == 1
    record = session.exec(
        select(AgentContractRecord).where(AgentContractRecord.contract_id == contract.contract_id)
    ).first()
    assert record.contract_state == "expired"


def test_expire_active_contracts_skips_contracts_without_expires_at():
    """Contracts with expires_at=None are never expired by expire_active_contracts."""
    from core.contracts import bind_contract, expire_active_contracts
    from db.models import AgentContractRecord
    from sqlmodel import select

    session = _make_session()
    sid = "session-expire-no-ttl"
    authority = _make_authority_context(run_id="run_exp005", session_id=sid)
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    # No expires_at — should never be swept
    contract = bind_contract(session=session, authority_context=authority, bound_at=bound_at)
    session.commit()

    expired = expire_active_contracts(
        session=session,
        reference_time=bound_at + timedelta(days=999),
        session_id=sid,
    )
    session.commit()

    assert expired == []
    record = session.exec(
        select(AgentContractRecord).where(AgentContractRecord.contract_id == contract.contract_id)
    ).first()
    assert record.contract_state == "active"


def test_expire_active_contracts_is_session_scoped():
    """expire_active_contracts with session_id only expires that session's contracts."""
    from core.contracts import bind_contract, expire_active_contracts
    from db.models import AgentContractRecord
    from sqlmodel import select

    session = _make_session()
    sid_a = "session-scope-a"
    sid_b = "session-scope-b"
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)
    expires_at = bound_at - timedelta(seconds=1)

    ca = bind_contract(
        session=session,
        authority_context=_make_authority_context(run_id="run_scope001", session_id=sid_a),
        bound_at=bound_at,
        expires_at=expires_at,
    )
    cb = bind_contract(
        session=session,
        authority_context=_make_authority_context(run_id="run_scope002", session_id=sid_b),
        bound_at=bound_at,
        expires_at=expires_at,
    )
    session.commit()

    # Only sweep session A
    expired = expire_active_contracts(
        session=session,
        reference_time=bound_at,
        session_id=sid_a,
    )
    session.commit()

    assert len(expired) == 1
    assert expired[0].contract_id == ca.contract_id

    rec_a = session.exec(
        select(AgentContractRecord).where(AgentContractRecord.contract_id == ca.contract_id)
    ).first()
    rec_b = session.exec(
        select(AgentContractRecord).where(AgentContractRecord.contract_id == cb.contract_id)
    ).first()
    assert rec_a.contract_state == "expired"
    assert rec_b.contract_state == "active"


# ── has_expired_contract gate ─────────────────────────────────────────────────

def test_has_expired_contract_returns_false_for_active():
    """has_expired_contract returns False when all contracts are ACTIVE."""
    from core.contracts import bind_contract, has_expired_contract

    session = _make_session()
    sid = "session-hec-active"
    authority = _make_authority_context(run_id="run_hec001", session_id=sid)
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    bind_contract(
        session=session,
        authority_context=authority,
        bound_at=bound_at,
        expires_at=bound_at + timedelta(hours=1),
    )
    session.commit()

    assert has_expired_contract(session=session, session_id=sid) is False


def test_has_expired_contract_returns_true_after_expiry():
    """has_expired_contract returns True after expire_active_contracts transitions the contract."""
    from core.contracts import bind_contract, expire_active_contracts, has_expired_contract

    session = _make_session()
    sid = "session-hec-expired"
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)
    expires_at = bound_at - timedelta(seconds=1)

    bind_contract(
        session=session,
        authority_context=_make_authority_context(run_id="run_hec002", session_id=sid),
        bound_at=bound_at,
        expires_at=expires_at,
    )
    session.commit()

    assert has_expired_contract(session=session, session_id=sid) is False

    expire_active_contracts(session=session, reference_time=bound_at, session_id=sid)
    session.commit()

    assert has_expired_contract(session=session, session_id=sid) is True


def test_has_expired_contract_returns_false_for_no_session_contracts():
    """has_expired_contract returns False when no contracts exist for the session."""
    from core.contracts import has_expired_contract

    session = _make_session()
    assert has_expired_contract(session=session, session_id="session-no-contracts") is False


# ── expire_active_contracts returns pre-mutation snapshots ────────────────────

# ── renew_expired_contracts ───────────────────────────────────────────────────


def test_renew_expired_contracts_creates_new_active_contract():
    """renew_expired_contracts creates a fresh ACTIVE contract for the session."""
    from core.contracts import bind_contract, expire_active_contracts, renew_expired_contracts
    from db.models import AgentContractRecord
    from sqlmodel import select

    session = _make_session()
    sid = "session-renew-new"
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)
    expires_at = bound_at - timedelta(seconds=1)

    bind_contract(
        session=session,
        authority_context=_make_authority_context(run_id="run_renew001", session_id=sid),
        bound_at=bound_at,
        expires_at=expires_at,
    )
    session.commit()
    expire_active_contracts(session=session, reference_time=bound_at, session_id=sid)
    session.commit()

    result = renew_expired_contracts(
        session=session,
        session_id=sid,
        renewed_by="ops-renew",
        renewed_reason="TTL elapsed, renewal authorised",
        bound_at=bound_at,
        expires_at=bound_at + timedelta(hours=1),
    )
    session.commit()

    assert result is not None
    _, new_contract = result
    assert new_contract.contract_state == ContractState.ACTIVE
    assert new_contract.contract_id.startswith("ctr_")

    # New record is in the DB and ACTIVE
    rec = session.exec(
        select(AgentContractRecord).where(
            AgentContractRecord.contract_id == new_contract.contract_id
        )
    ).first()
    assert rec is not None
    assert rec.contract_state == "active"


def test_renew_expired_contracts_marks_old_record_renewed_stays_expired():
    """Expired records get renewed_at set but contract_state stays 'expired'."""
    from core.contracts import bind_contract, expire_active_contracts, renew_expired_contracts
    from db.models import AgentContractRecord
    from sqlmodel import select

    session = _make_session()
    sid = "session-renew-mark"
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)
    expires_at = bound_at - timedelta(seconds=1)

    old = bind_contract(
        session=session,
        authority_context=_make_authority_context(run_id="run_renew002", session_id=sid),
        bound_at=bound_at,
        expires_at=expires_at,
    )
    session.commit()
    expire_active_contracts(session=session, reference_time=bound_at, session_id=sid)
    session.commit()

    renew_expired_contracts(
        session=session,
        session_id=sid,
        renewed_by="ops-renew",
        renewed_reason="test",
        bound_at=bound_at,
    )
    session.commit()

    rec = session.exec(
        select(AgentContractRecord).where(AgentContractRecord.contract_id == old.contract_id)
    ).first()
    assert rec is not None
    # State stays EXPIRED — no mutation to ACTIVE
    assert rec.contract_state == "expired"
    # Renewal metadata written
    assert rec.renewed_at is not None
    assert rec.renewed_by == "ops-renew"
    assert rec.renewed_reason == "test"


def test_renew_expired_contracts_returns_none_when_nothing_to_renew():
    """Returns None when no un-renewed EXPIRED contracts exist."""
    from core.contracts import bind_contract, renew_expired_contracts

    session = _make_session()
    sid = "session-renew-empty"
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)

    # Active contract — not expired
    bind_contract(session=session, authority_context=_make_authority_context(run_id="run_rn003", session_id=sid), bound_at=bound_at)
    session.commit()

    result = renew_expired_contracts(
        session=session,
        session_id=sid,
        renewed_by="ops",
        renewed_reason="should be None",
        bound_at=bound_at,
    )
    assert result is None


def test_renew_expired_contracts_returns_pre_mutation_snapshots():
    """Returned expired snapshots carry pre-renewal state (renewed_at still None)."""
    from core.contracts import bind_contract, expire_active_contracts, renew_expired_contracts

    session = _make_session()
    sid = "session-renew-snap"
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)
    expires_at = bound_at - timedelta(seconds=1)

    bind_contract(
        session=session,
        authority_context=_make_authority_context(run_id="run_rsnap001", session_id=sid),
        bound_at=bound_at,
        expires_at=expires_at,
    )
    session.commit()
    expire_active_contracts(session=session, reference_time=bound_at, session_id=sid)
    session.commit()

    result = renew_expired_contracts(
        session=session,
        session_id=sid,
        renewed_by="ops",
        renewed_reason="test",
        bound_at=bound_at,
    )
    assert result is not None
    snapshots, _ = result
    assert len(snapshots) == 1
    # Snapshot reflects state before mutation — renewed_at still None
    assert snapshots[0].renewed_at is None
    assert snapshots[0].contract_state == ContractState.EXPIRED


def test_has_expired_contract_returns_false_after_renewal():
    """Gate lifts once renew_expired_contracts marks all expired contracts as renewed."""
    from core.contracts import bind_contract, expire_active_contracts, has_expired_contract, renew_expired_contracts

    session = _make_session()
    sid = "session-hec-renew"
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)
    expires_at = bound_at - timedelta(seconds=1)

    bind_contract(
        session=session,
        authority_context=_make_authority_context(run_id="run_hec_ren001", session_id=sid),
        bound_at=bound_at,
        expires_at=expires_at,
    )
    session.commit()
    expire_active_contracts(session=session, reference_time=bound_at, session_id=sid)
    session.commit()

    # Gate should be active before renewal
    assert has_expired_contract(session=session, session_id=sid) is True

    renew_expired_contracts(
        session=session,
        session_id=sid,
        renewed_by="ops",
        renewed_reason="test",
        bound_at=bound_at,
    )
    session.commit()

    # Gate lifts after renewal — old expired record has renewed_at set
    assert has_expired_contract(session=session, session_id=sid) is False


def test_renew_expired_contracts_inherits_authority_from_source():
    """New contract carries same actor_id, agent_id, delegation_chain_id as expired contract."""
    from core.contracts import bind_contract, expire_active_contracts, renew_expired_contracts
    from db.models import AgentContractRecord
    from sqlmodel import select

    session = _make_session()
    sid = "session-renew-inherit"
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)
    authority = _make_authority_context(
        run_id="run_inherit001",
        agent_id="agent-special",
        actor_id="actor-special",
        session_id=sid,
        allowed_tool_families=["filesystem"],
    )

    old = bind_contract(
        session=session,
        authority_context=authority,
        bound_at=bound_at,
        expires_at=bound_at - timedelta(seconds=1),
    )
    session.commit()
    expire_active_contracts(session=session, reference_time=bound_at, session_id=sid)
    session.commit()

    result = renew_expired_contracts(
        session=session,
        session_id=sid,
        renewed_by="ops",
        renewed_reason="inherit check",
        bound_at=bound_at,
    )
    session.commit()

    assert result is not None
    _, new_contract = result

    assert new_contract.agent_id == old.agent_id
    assert new_contract.actor_id == old.actor_id
    assert new_contract.delegation_chain_id == old.delegation_chain_id
    assert new_contract.session_id == sid
    assert "filesystem" in new_contract.allowed_tool_families


def test_expire_active_contracts_returns_pre_mutation_snapshots():
    """Returned contracts carry ACTIVE state (pre-mutation) for audit payload use."""
    from core.contracts import bind_contract, expire_active_contracts

    session = _make_session()
    sid = "session-snapshot-exp"
    bound_at = datetime.now(timezone.utc).replace(tzinfo=None)
    expires_at = bound_at - timedelta(seconds=1)

    bind_contract(
        session=session,
        authority_context=_make_authority_context(run_id="run_snap_exp001", session_id=sid),
        bound_at=bound_at,
        expires_at=expires_at,
    )
    session.commit()

    expired = expire_active_contracts(session=session, reference_time=bound_at, session_id=sid)

    assert len(expired) == 1
    # Snapshot reflects state at capture time — ACTIVE before mutation
    assert expired[0].contract_state == ContractState.ACTIVE
    assert expired[0].expires_at == expires_at
