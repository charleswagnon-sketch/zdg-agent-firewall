"""
Unit tests 11-13: Approval workflow â€” binding, payload mismatch, expiry.
"""
from __future__ import annotations

import time
import pytest
from sqlmodel import Session, create_engine, SQLModel


def _make_session():
    """In-memory SQLite session for isolated approval testing."""
    import db.models  # noqa: F401 â€” ensure all tables registered in metadata
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    return Session(engine)


# â”€â”€ Test 11: approval binds to payload_hash â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def test_approval_binds_to_payload_hash():
    """Test 11: Approval is bound to payload_hash and resolves correctly when matched."""
    from core.approval import create_approval, resolve_approval
    from core.modes import ReasonCode

    session = _make_session()

    p_hash = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    decision_id = "dec_abc123"
    bundle_version = "1.0.0"

    approval_id, expires_at = create_approval(
        session=session,
        decision_id=decision_id,
        policy_bundle_version=bundle_version,
        agent_id="agent-001",
        tool_family="messaging",
        action="send",
        payload_hash=p_hash,
        risk_score=40,
        triggered_rules=["BULK_SEND_DETECTED"],
        reason="Bulk send to 8 recipients requires operator approval",
        expiry_seconds=600,
    )
    session.commit()

    assert approval_id.startswith("apv_")
    assert expires_at is not None

    # Resolve with matching payload hash
    success, reason_code, human_reason = resolve_approval(
        session=session,
        approval_id=approval_id,
        incoming_payload_hash=p_hash,
        incoming_decision_id=decision_id,
        incoming_bundle_version=bundle_version,
        approved=True,
        operator="operator@example.com",
        comment="Reviewed and approved",
    )
    session.commit()

    assert success, f"Expected success, got: {human_reason}"
    assert reason_code == ReasonCode.ALLOW


def test_approval_deny_resolves_correctly():
    """Operator denying an approval returns BLOCK decision."""
    from core.approval import create_approval, resolve_approval
    from core.modes import ReasonCode, Decision

    session = _make_session()
    p_hash = "sha256:" + "a" * 64

    approval_id, _ = create_approval(
        session=session,
        decision_id="dec_deny_test",
        policy_bundle_version="1.0.0",
        agent_id="agent-002",
        tool_family="shell",
        action="execute",
        payload_hash=p_hash,
        risk_score=35,
        triggered_rules=["DESTRUCTIVE_SHELL_PATTERN"],
        reason="Destructive pattern requires approval",
        expiry_seconds=600,
    )
    session.commit()

    success, reason_code, human_reason = resolve_approval(
        session=session,
        approval_id=approval_id,
        incoming_payload_hash=p_hash,
        incoming_decision_id="dec_deny_test",
        incoming_bundle_version="1.0.0",
        approved=False,
        operator="operator@example.com",
        comment="Denied â€” pattern too risky",
    )
    session.commit()

    assert success
    assert reason_code == ReasonCode.EXPLICIT_POLICY_DENY


# â”€â”€ Test 12: changed payload returns PAYLOAD_MISMATCH â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def test_changed_payload_returns_payload_mismatch():
    """Test 12: Resolving approval with different payload_hash returns PAYLOAD_MISMATCH."""
    from core.approval import create_approval, resolve_approval
    from core.modes import ReasonCode

    session = _make_session()

    original_hash = "sha256:" + "a" * 64
    tampered_hash = "sha256:" + "b" * 64  # Different hash â€” payload was changed

    approval_id, _ = create_approval(
        session=session,
        decision_id="dec_mismatch",
        policy_bundle_version="1.0.0",
        agent_id="agent-003",
        tool_family="messaging",
        action="send",
        payload_hash=original_hash,
        risk_score=40,
        triggered_rules=["BULK_SEND_DETECTED"],
        reason="Bulk send requires approval",
        expiry_seconds=600,
    )
    session.commit()

    # Attempt to resolve with a different payload hash
    success, reason_code, human_reason = resolve_approval(
        session=session,
        approval_id=approval_id,
        incoming_payload_hash=tampered_hash,   # â† different from what was approved
        incoming_decision_id="dec_mismatch",
        incoming_bundle_version="1.0.0",
        approved=True,
        operator="operator@example.com",
    )

    assert not success, "Should fail due to payload mismatch"
    assert reason_code == ReasonCode.PAYLOAD_MISMATCH
    assert "payload" in human_reason.lower() or "mismatch" in human_reason.lower()


def test_changed_decision_id_returns_payload_mismatch():
    """Resolving approval with wrong decision_id returns PAYLOAD_MISMATCH."""
    from core.approval import create_approval, resolve_approval
    from core.modes import ReasonCode

    session = _make_session()
    p_hash = "sha256:" + "c" * 64

    approval_id, _ = create_approval(
        session=session,
        decision_id="dec_original",
        policy_bundle_version="1.0.0",
        agent_id="agent-004",
        tool_family="http",
        action="request",
        payload_hash=p_hash,
        risk_score=35,
        triggered_rules=[],
        reason="Test",
        expiry_seconds=600,
    )
    session.commit()

    success, reason_code, _ = resolve_approval(
        session=session,
        approval_id=approval_id,
        incoming_payload_hash=p_hash,
        incoming_decision_id="dec_DIFFERENT",   # â† wrong decision_id
        incoming_bundle_version="1.0.0",
        approved=True,
        operator="operator@example.com",
    )

    assert not success
    assert reason_code == ReasonCode.PAYLOAD_MISMATCH


def test_changed_bundle_version_returns_payload_mismatch():
    """Resolving approval with wrong bundle version returns PAYLOAD_MISMATCH."""
    from core.approval import create_approval, resolve_approval
    from core.modes import ReasonCode

    session = _make_session()
    p_hash = "sha256:" + "d" * 64

    approval_id, _ = create_approval(
        session=session,
        decision_id="dec_bundle_test",
        policy_bundle_version="1.0.0",
        agent_id="agent-005",
        tool_family="filesystem",
        action="read",
        payload_hash=p_hash,
        risk_score=30,
        triggered_rules=[],
        reason="Test",
        expiry_seconds=600,
    )
    session.commit()

    success, reason_code, _ = resolve_approval(
        session=session,
        approval_id=approval_id,
        incoming_payload_hash=p_hash,
        incoming_decision_id="dec_bundle_test",
        incoming_bundle_version="2.0.0",   # â† policy bundle version changed
        approved=True,
        operator="operator@example.com",
    )

    assert not success
    assert reason_code == ReasonCode.PAYLOAD_MISMATCH


# â”€â”€ Test 13: expired approval returns APPROVAL_EXPIRED â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def test_expired_approval_returns_approval_expired():
    """Test 13: Resolving an expired approval returns APPROVAL_EXPIRED."""
    from core.approval import create_approval, resolve_approval
    from core.modes import ReasonCode

    session = _make_session()
    p_hash = "sha256:" + "e" * 64

    # Create an approval that expires in 1 second
    approval_id, expires_at = create_approval(
        session=session,
        decision_id="dec_expiry_test",
        policy_bundle_version="1.0.0",
        agent_id="agent-006",
        tool_family="messaging",
        action="send",
        payload_hash=p_hash,
        risk_score=40,
        triggered_rules=["BULK_SEND_DETECTED"],
        reason="Expiry test",
        expiry_seconds=1,  # Expires in 1 second
    )
    session.commit()

    # Wait for it to expire
    time.sleep(2)

    success, reason_code, human_reason = resolve_approval(
        session=session,
        approval_id=approval_id,
        incoming_payload_hash=p_hash,
        incoming_decision_id="dec_expiry_test",
        incoming_bundle_version="1.0.0",
        approved=True,
        operator="operator@example.com",
    )

    assert not success, "Expired approval should fail"
    assert reason_code == ReasonCode.APPROVAL_EXPIRED
    assert "closed" in human_reason.lower() or "expir" in human_reason.lower()


def test_already_resolved_returns_approval_already_resolved():
    """Resolving an approval a second time returns APPROVAL_ALREADY_RESOLVED, not PAYLOAD_MISMATCH."""
    from core.approval import create_approval, resolve_approval
    from core.modes import ReasonCode

    session = _make_session()
    p_hash = "sha256:" + "a1" * 32

    approval_id, _ = create_approval(
        session=session,
        decision_id="dec_dup_resolve",
        policy_bundle_version="1.0.0",
        agent_id="agent-dup",
        tool_family="shell",
        action="execute",
        payload_hash=p_hash,
        risk_score=35,
        triggered_rules=[],
        reason="Duplicate resolve test",
        expiry_seconds=600,
    )
    session.commit()

    # First resolve — should succeed
    success1, _, _ = resolve_approval(
        session=session,
        approval_id=approval_id,
        incoming_payload_hash=p_hash,
        incoming_decision_id="dec_dup_resolve",
        incoming_bundle_version="1.0.0",
        approved=True,
        operator="operator@example.com",
    )
    session.commit()
    assert success1

    # Second resolve — must return APPROVAL_ALREADY_RESOLVED
    success2, reason_code, human_reason = resolve_approval(
        session=session,
        approval_id=approval_id,
        incoming_payload_hash=p_hash,
        incoming_decision_id="dec_dup_resolve",
        incoming_bundle_version="1.0.0",
        approved=True,
        operator="operator@example.com",
    )

    assert not success2
    assert reason_code == ReasonCode.APPROVAL_ALREADY_RESOLVED
    assert "already resolved" in human_reason.lower()


def test_approval_not_found_returns_error():
    """Non-existent approval ID returns APPROVAL_NOT_FOUND."""
    from core.approval import resolve_approval
    from core.modes import ReasonCode

    session = _make_session()

    success, reason_code, human_reason = resolve_approval(
        session=session,
        approval_id="apr_does_not_exist",
        incoming_payload_hash="sha256:" + "0" * 64,
        incoming_decision_id="dec_none",
        incoming_bundle_version="1.0.0",
        approved=True,
        operator="operator@example.com",
    )

    assert not success
    assert reason_code == ReasonCode.APPROVAL_NOT_FOUND
    assert "not found" in human_reason.lower()



def test_get_pending_excludes_expired_and_resolved():
    """get_pending returns only non-expired, unresolved approvals."""
    from core.approval import create_approval, resolve_approval, get_pending

    session = _make_session()
    p_hash_active = "sha256:" + "f" * 64
    p_hash_expired = "sha256:" + "0" * 64
    p_hash_resolved = "sha256:" + "1" * 64

    # Active pending
    apr_active, _ = create_approval(
        session=session, decision_id="dec_active", policy_bundle_version="1.0.0",
        agent_id="agent-007", tool_family="messaging", action="send",
        payload_hash=p_hash_active, risk_score=40, triggered_rules=[], reason="active",
        expiry_seconds=600,
    )

    # Expired (1s)
    apr_expired, _ = create_approval(
        session=session, decision_id="dec_expired", policy_bundle_version="1.0.0",
        agent_id="agent-007", tool_family="messaging", action="send",
        payload_hash=p_hash_expired, risk_score=40, triggered_rules=[], reason="expired",
        expiry_seconds=1,
    )

    # Resolved
    apr_resolved, _ = create_approval(
        session=session, decision_id="dec_resolved", policy_bundle_version="1.0.0",
        agent_id="agent-007", tool_family="messaging", action="send",
        payload_hash=p_hash_resolved, risk_score=40, triggered_rules=[], reason="resolved",
        expiry_seconds=600,
    )
    session.commit()

    # Resolve one
    resolve_approval(
        session=session, approval_id=apr_resolved,
        incoming_payload_hash=p_hash_resolved, incoming_decision_id="dec_resolved",
        incoming_bundle_version="1.0.0", approved=True, operator="ops",
    )
    session.commit()

    # Wait for expiry
    time.sleep(2)

    pending = get_pending(session)
    pending_ids = [p["approval_id"] for p in pending]

    assert apr_active in pending_ids, "Active approval should be in pending"
    assert apr_expired not in pending_ids, "Expired approval should NOT be in pending"
    assert apr_resolved not in pending_ids, "Resolved approval should NOT be in pending"
