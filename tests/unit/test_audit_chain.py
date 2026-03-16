"""
Unit tests 18-19: Tamper-evident audit chain.
"""
from __future__ import annotations

import json
import pytest
from sqlmodel import Session, create_engine, SQLModel


def _make_session():
    """In-memory SQLite session for isolated testing."""
    import db.models  # noqa: F401 — ensure all tables registered in metadata
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    # Add append-only triggers
    from db.migrations import _add_append_only_triggers
    with engine.connect() as conn:
        _add_append_only_triggers(conn)
        conn.commit()
    return Session(engine)


# ── Test 18: chain hashes correctly ───────────────────────────────────────────

def test_audit_chain_hashes_correctly():
    """Test 18: Event log chain hashes correctly — each record's hash covers prior hash."""
    from core.audit import (
        append_audit_event,
        compute_event_hash,
        get_latest_event_hash,
        verify_chain,
        GENESIS_HASH,
    )

    session = _make_session()
    chain_id = "test-chain-001"

    # Initially no events — genesis hash
    latest = get_latest_event_hash(session, chain_id)
    assert latest == GENESIS_HASH

    # Append first event
    evt1_id = append_audit_event(
        session,
        chain_id=chain_id,
        event_type="ACTION_ATTEMPT",
        event_payload={"tool_family": "shell", "action": "execute", "agent_id": "agent-1"},
    )
    session.commit()

    # Append second event
    evt2_id = append_audit_event(
        session,
        chain_id=chain_id,
        event_type="POLICY_DECISION",
        event_payload={"decision": "ALLOW", "risk_score": 5},
    )
    session.commit()

    # Append third event
    evt3_id = append_audit_event(
        session,
        chain_id=chain_id,
        event_type="EXECUTION_RESULT",
        event_payload={"executed": True, "output": "files listed"},
    )
    session.commit()

    # Verify the full chain
    ok, msg = verify_chain(session, chain_id)
    assert ok, f"Chain should be valid: {msg}"
    assert "CHAIN OK (3 events)" in msg

    # Also verify the IDs were generated
    assert evt1_id.startswith("evt_")
    assert evt2_id.startswith("evt_")
    assert evt3_id.startswith("evt_")
    assert evt1_id != evt2_id != evt3_id


def test_audit_genesis_chain_is_valid():
    """Empty chain verifies as OK."""
    from core.audit import verify_chain

    session = _make_session()
    ok, msg = verify_chain(session, "empty-chain")
    assert ok
    assert "CHAIN OK (0 events)" in msg


def test_audit_multiple_chains_independent():
    """Events in different chains don't interfere with each other."""
    from core.audit import append_audit_event, verify_chain

    session = _make_session()

    for chain_id in ("chain-A", "chain-B", "chain-C"):
        append_audit_event(
            session,
            chain_id=chain_id,
            event_type="TEST_EVENT",
            event_payload={"chain": chain_id},
        )
    session.commit()

    for chain_id in ("chain-A", "chain-B", "chain-C"):
        ok, msg = verify_chain(session, chain_id)
        assert ok, f"Chain {chain_id} should be valid: {msg}"


# ── Test 19: tampering causes verification failure ────────────────────────────

def test_tampering_breaks_chain():
    """Test 19: Modifying an earlier event causes hash chain verification to fail."""
    from core.audit import append_audit_event, verify_chain
    from db.models import AuditEvent
    from sqlmodel import select

    session = _make_session()
    chain_id = "tamper-test-chain"

    # Build a chain of 3 events
    append_audit_event(
        session,
        chain_id=chain_id,
        event_type="ACTION_ATTEMPT",
        event_payload={"tool_family": "shell", "action": "execute"},
    )
    append_audit_event(
        session,
        chain_id=chain_id,
        event_type="POLICY_DECISION",
        event_payload={"decision": "ALLOW"},
    )
    append_audit_event(
        session,
        chain_id=chain_id,
        event_type="EXECUTION_RESULT",
        event_payload={"executed": True},
    )
    session.commit()

    # Confirm chain is valid before tampering
    ok, msg = verify_chain(session, chain_id)
    assert ok, f"Pre-tamper chain should be valid: {msg}"

    # Tamper: modify the payload of the FIRST event (lowest rowid)
    stmt = (
        select(AuditEvent)
        .where(AuditEvent.chain_id == chain_id)
        .order_by(AuditEvent.seq)
        .limit(1)
    )
    first_event = session.exec(stmt).first()
    assert first_event is not None

    # Simulate an attacker with direct file-level access to the SQLite DB.
    # We must drop the append-only trigger first, tamper, then restore it.
    # This proves the hash chain catches tampering even when DB-level guards
    # are circumvented (e.g. raw file editing).
    raw_conn = session.connection().connection.dbapi_connection
    raw_conn.execute("DROP TRIGGER IF EXISTS audit_events_no_update")
    tampered_payload = json.dumps({"tool_family": "shell", "action": "TAMPERED"})
    raw_conn.execute(
        "UPDATE audit_events SET event_payload = ? WHERE event_id = ?",
        (tampered_payload, first_event.event_id),
    )
    raw_conn.commit()
    # Restore trigger
    raw_conn.execute(
        "CREATE TRIGGER IF NOT EXISTS audit_events_no_update "
        "BEFORE UPDATE ON audit_events BEGIN "
        "SELECT RAISE(ABORT, 'audit_events is append-only'); END"
    )
    raw_conn.commit()
    session.expire_all()

    # Now verify — chain should be broken
    ok, msg = verify_chain(session, chain_id)
    assert not ok, "Tampered chain should fail verification"
    assert "CHAIN BROKEN" in msg


def test_tampering_middle_event_breaks_subsequent():
    """Modifying a middle event invalidates that event AND all subsequent events."""
    from core.audit import append_audit_event, verify_chain
    from db.models import AuditEvent
    from sqlmodel import select
    import sqlalchemy

    session = _make_session()
    chain_id = "middle-tamper-chain"

    for i in range(5):
        append_audit_event(
            session,
            chain_id=chain_id,
            event_type="TEST_EVENT",
            event_payload={"seq": i, "data": f"event-{i}"},
        )
    session.commit()

    ok, _ = verify_chain(session, chain_id)
    assert ok, "Should be valid before tamper"

    # Tamper with event at position 2 (0-indexed)
    stmt = (
        select(AuditEvent)
        .where(AuditEvent.chain_id == chain_id)
        .order_by(AuditEvent.seq)
    )
    events = session.exec(stmt).all()
    target = events[2]  # Middle event

    # Drop trigger to simulate direct file-level tampering
    raw_conn = session.connection().connection.dbapi_connection
    raw_conn.execute("DROP TRIGGER IF EXISTS audit_events_no_update")
    raw_conn.execute(
        "UPDATE audit_events SET event_payload = ? WHERE event_id = ?",
        (json.dumps({"seq": 999, "data": "INJECTED"}), target.event_id),
    )
    raw_conn.commit()
    # Restore trigger
    raw_conn.execute(
        "CREATE TRIGGER IF NOT EXISTS audit_events_no_update "
        "BEFORE UPDATE ON audit_events BEGIN "
        "SELECT RAISE(ABORT, 'audit_events is append-only'); END"
    )
    raw_conn.commit()
    session.expire_all()

    ok, msg = verify_chain(session, chain_id)
    assert not ok
    assert "CHAIN BROKEN" in msg
    # The broken position should be 2 or later
    assert "position=2" in msg or "position=3" in msg or "position=4" in msg
