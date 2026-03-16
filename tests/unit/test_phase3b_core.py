"""Phase 3B unit tests for agent/session lifecycle and portable audit helpers."""

from __future__ import annotations

from copy import deepcopy

import pytest
from sqlmodel import SQLModel, Session, create_engine


def _make_session() -> Session:
    import db.models  # noqa: F401

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    return Session(engine)



def test_agent_lifecycle_round_trip():
    from core import agents

    session = _make_session()

    registered = agents.register_agent(
        session=session,
        agent_id="agent-phase3b",
        agent_type="openclaw",
        metadata={"team": "ops"},
        registered_by="ops@example.com",
    )
    session.commit()

    assert registered["agent_id"] == "agent-phase3b"
    assert registered["status"] == "active"
    assert registered["metadata"]["team"] == "ops"

    suspended = agents.suspend_agent(
        session=session,
        agent_id="agent-phase3b",
        operator="ops@example.com",
        reason="Manual pause",
    )
    session.commit()
    assert suspended["status"] == "suspended"
    assert suspended["status_reason"] == "Manual pause"

    unsuspended = agents.unsuspend_agent(
        session=session,
        agent_id="agent-phase3b",
        operator="ops@example.com",
        reason="Resume",
    )
    session.commit()
    assert unsuspended["status"] == "active"

    deregistered = agents.deregister_agent(
        session=session,
        agent_id="agent-phase3b",
        operator="ops@example.com",
        reason="Retired",
    )
    session.commit()
    assert deregistered["status"] == "deregistered"



def test_session_lifecycle_round_trip():
    from core import sessions

    session = _make_session()

    created = sessions.create_session(
        session=session,
        agent_id="agent-session",
        metadata={"origin": "unit"},
        created_by="ops@example.com",
        creation_source="api",
    )
    session.commit()

    assert created["status"] == "active"
    assert created["agent_id"] == "agent-session"
    assert created["metadata"]["origin"] == "unit"
    assert len(sessions.list_active_sessions(session=session, agent_id="agent-session")) == 1

    suspended = sessions.suspend_session(
        session=session,
        session_id=created["session_id"],
        operator="ops@example.com",
        reason="Investigating",
    )
    session.commit()
    assert suspended["status"] == "suspended"

    unsuspended = sessions.unsuspend_session(
        session=session,
        session_id=created["session_id"],
        operator="ops@example.com",
        reason="Recovered",
    )
    session.commit()
    assert unsuspended["status"] == "active"

    closed = sessions.close_session(
        session=session,
        session_id=created["session_id"],
        operator="ops@example.com",
        reason="Done",
    )
    session.commit()
    assert closed["status"] == "closed"
    assert sessions.list_active_sessions(session=session, agent_id="agent-session") == []



def test_closed_session_cannot_be_unsuspended():
    from core import sessions

    session = _make_session()
    created = sessions.create_session(
        session=session,
        agent_id="agent-closed",
        metadata=None,
        created_by="ops@example.com",
    )
    session.commit()

    sessions.close_session(
        session=session,
        session_id=created["session_id"],
        operator="ops@example.com",
        reason="Closed",
    )
    session.commit()

    with pytest.raises(ValueError):
        sessions.unsuspend_session(
            session=session,
            session_id=created["session_id"],
            operator="ops@example.com",
            reason="Should fail",
        )



def test_portable_audit_export_verify_and_diff_helpers():
    from core.audit import (
        append_audit_event_with_session_chain,
        diff_chain_exports,
        export_chain_document,
        export_chain_ndjson_lines,
        parse_chain_export,
        verify_chain_export,
    )

    session = _make_session()

    append_audit_event_with_session_chain(
        session=session,
        global_chain_id="global-chain",
        session_id="ses_portable",
        event_type="EVENT_ONE",
        event_payload={"step": 1},
    )
    append_audit_event_with_session_chain(
        session=session,
        global_chain_id="global-chain",
        session_id="ses_portable",
        event_type="EVENT_TWO",
        event_payload={"step": 2},
    )
    session.commit()

    exported = export_chain_document(session, "global-chain")
    session_export = export_chain_document(session, "session:ses_portable")

    assert exported["event_count"] == 2
    assert session_export["event_count"] == 2
    assert verify_chain_export(exported)["ok"] is True
    assert verify_chain_export(session_export)["ok"] is True

    ndjson_payload = "\n".join(export_chain_ndjson_lines(session, "global-chain"))
    parsed = parse_chain_export(ndjson_payload)
    assert parsed["chain_id"] == "global-chain"
    assert parsed["event_count"] == 2

    tampered = deepcopy(exported)
    tampered["events"][1]["event_type"] = "EVENT_TWO_TAMPERED"
    verification = verify_chain_export(tampered)
    assert verification["ok"] is False

    diff = diff_chain_exports(exported, tampered)
    assert diff["common_prefix_length"] == 1
    assert diff["left_unique_count"] == 1
    assert diff["right_unique_count"] == 1
