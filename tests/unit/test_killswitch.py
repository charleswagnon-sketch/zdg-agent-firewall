"""
Unit tests 14-17: Kill switch — scopes, precedence, override behavior.
"""
from __future__ import annotations

import pytest
from sqlmodel import Session, create_engine, SQLModel


def _make_session():
    """In-memory SQLite session for isolated kill switch testing."""
    import db.models  # noqa: F401 — ensure all tables registered in metadata
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    return Session(engine)


def _activate(session, scope, scope_value=None, reason="test"):
    from core.killswitch import activate_killswitch
    evt_id = activate_killswitch(
        session=session,
        scope=scope,
        scope_value=scope_value,
        trigger_reason=reason,
        triggered_by="test-suite",
    )
    session.commit()
    return evt_id


def _check(session, agent_id="agent-x", tool_family="shell", session_id=None):
    from core.killswitch import check_killswitch
    return check_killswitch(session, agent_id, tool_family, session_id)


# ── Test 14: global kill switch overrides everything ─────────────────────────

def test_global_killswitch_blocks_all():
    """Test 14: Global kill switch overrides all agent/tool/session checks."""
    from core.modes import KillSwitchScope

    session = _make_session()

    is_active, scope, scope_value, reason = _check(session, "agent-1", "shell")
    assert not is_active, "Should be inactive before activation"

    _activate(session, KillSwitchScope.GLOBAL)

    # Every agent, every tool family, every session should be blocked
    for agent_id in ("agent-1", "agent-2", "agent-99"):
        for tool_family in ("shell", "http", "filesystem", "messaging"):
            is_active, scope, _, _ = _check(session, agent_id, tool_family)
            assert is_active, f"Global KS should block {agent_id}/{tool_family}"
            assert scope == KillSwitchScope.GLOBAL


def test_global_killswitch_reset_allows_again():
    """After resetting a global kill switch, traffic flows again."""
    from core.modes import KillSwitchScope
    from core.killswitch import reset_killswitch

    session = _make_session()
    _activate(session, KillSwitchScope.GLOBAL)

    is_active, _, _, _ = _check(session)
    assert is_active

    reset_killswitch(session, operator="ops@example.com", scope=KillSwitchScope.GLOBAL)
    session.commit()

    is_active, _, _, _ = _check(session)
    assert not is_active, "Should be inactive after global reset"


# ── Test 15: agent-scoped kill switch blocks matching agent only ──────────────

def test_agent_scoped_killswitch_blocks_only_that_agent():
    """Test 15: Agent-scoped kill switch blocks only the specified agent."""
    from core.modes import KillSwitchScope

    session = _make_session()
    target_agent = "agent-blocked"
    safe_agent = "agent-safe"

    _activate(session, KillSwitchScope.AGENT, scope_value=target_agent)

    # Target agent should be blocked
    is_active, scope, scope_val, _ = _check(session, target_agent, "shell")
    assert is_active
    assert scope == KillSwitchScope.AGENT
    assert scope_val == target_agent

    # Safe agent should NOT be blocked
    is_active, _, _, _ = _check(session, safe_agent, "shell")
    assert not is_active, f"{safe_agent} should not be blocked by agent-scoped KS"


def test_agent_scoped_killswitch_any_tool_family():
    """Agent-scoped kill switch blocks the agent regardless of tool family."""
    from core.modes import KillSwitchScope

    session = _make_session()
    _activate(session, KillSwitchScope.AGENT, scope_value="rogue-agent")

    for tool_family in ("shell", "http", "filesystem", "messaging"):
        is_active, _, _, _ = _check(session, "rogue-agent", tool_family)
        assert is_active, f"Agent KS should block rogue-agent/{tool_family}"


# ── Test 16: tool-family kill switch blocks only that tool family ─────────────

def test_tool_family_killswitch_blocks_only_that_family():
    """Test 16: Tool-family kill switch blocks only the specified tool family."""
    from core.modes import KillSwitchScope

    session = _make_session()
    _activate(session, KillSwitchScope.TOOL_FAMILY, scope_value="shell")

    # Shell should be blocked for any agent
    is_active, scope, scope_val, _ = _check(session, "agent-1", "shell")
    assert is_active
    assert scope == KillSwitchScope.TOOL_FAMILY
    assert scope_val == "shell"

    is_active, _, _, _ = _check(session, "agent-2", "shell")
    assert is_active

    # Other tool families should NOT be blocked
    for family in ("http", "filesystem", "messaging"):
        is_active, _, _, _ = _check(session, "agent-1", family)
        assert not is_active, f"{family} should not be blocked by shell-only KS"


def test_tool_family_killswitch_reset():
    """Resetting a tool-family kill switch restores that family."""
    from core.modes import KillSwitchScope
    from core.killswitch import reset_killswitch

    session = _make_session()
    _activate(session, KillSwitchScope.TOOL_FAMILY, scope_value="http")

    is_active, _, _, _ = _check(session, "agent-1", "http")
    assert is_active

    reset_killswitch(
        session, operator="ops", scope=KillSwitchScope.TOOL_FAMILY, scope_value="http"
    )
    session.commit()

    is_active, _, _, _ = _check(session, "agent-1", "http")
    assert not is_active, "http family should be unblocked after reset"


# ── Test 17: precedence order global > agent > tool_family > session ──────────

def test_killswitch_precedence_global_over_agent():
    """Test 17a: Global kill switch takes precedence over agent-scoped."""
    from core.modes import KillSwitchScope

    session = _make_session()
    _activate(session, KillSwitchScope.AGENT, scope_value="agent-x")
    _activate(session, KillSwitchScope.GLOBAL)

    is_active, scope, _, _ = _check(session, "agent-x", "shell")
    assert is_active
    assert scope == KillSwitchScope.GLOBAL, (
        f"Global should take precedence over agent-scoped, got {scope}"
    )


def test_killswitch_precedence_agent_over_tool_family():
    """Test 17b: Agent-scoped takes precedence over tool-family-scoped."""
    from core.modes import KillSwitchScope

    session = _make_session()
    _activate(session, KillSwitchScope.TOOL_FAMILY, scope_value="shell")
    _activate(session, KillSwitchScope.AGENT, scope_value="agent-x")

    is_active, scope, _, _ = _check(session, "agent-x", "shell")
    assert is_active
    assert scope == KillSwitchScope.AGENT, (
        f"Agent should take precedence over tool_family, got {scope}"
    )


def test_killswitch_precedence_tool_family_over_session():
    """Test 17c: Tool-family-scoped takes precedence over session-scoped."""
    from core.modes import KillSwitchScope

    session = _make_session()
    _activate(session, KillSwitchScope.SESSION, scope_value="sess-abc")
    _activate(session, KillSwitchScope.TOOL_FAMILY, scope_value="shell")

    is_active, scope, _, _ = _check(
        session, "agent-1", "shell", session_id="sess-abc"
    )
    assert is_active
    assert scope == KillSwitchScope.TOOL_FAMILY, (
        f"tool_family should take precedence over session, got {scope}"
    )


def test_killswitch_session_scoped_blocks_only_that_session():
    """Session-scoped kill switch blocks only requests from that session."""
    from core.modes import KillSwitchScope

    session = _make_session()
    _activate(session, KillSwitchScope.SESSION, scope_value="sess-blocked")

    is_active, scope, _, _ = _check(
        session, "agent-1", "shell", session_id="sess-blocked"
    )
    assert is_active
    assert scope == KillSwitchScope.SESSION

    # Same agent, different session — should pass
    is_active, _, _, _ = _check(
        session, "agent-1", "shell", session_id="sess-safe"
    )
    assert not is_active


def test_killswitch_get_status():
    """get_status returns accurate picture of active kill switches."""
    from core.modes import KillSwitchScope
    from core.killswitch import get_status

    session = _make_session()

    status = get_status(session)
    assert status["global_halt"] is False
    assert len(status["scoped_halts"]) == 0

    _activate(session, KillSwitchScope.GLOBAL)
    _activate(session, KillSwitchScope.AGENT, scope_value="agent-x")

    status = get_status(session)
    assert status["global_halt"] is True
    # Scoped halts include the agent-scoped one
    assert any(
        h.get("scope") == KillSwitchScope.AGENT.value for h in status["scoped_halts"]
    )


def test_no_active_killswitch_returns_false():
    """Clean state: check returns not-active for all combinations."""
    session = _make_session()

    for agent in ("agent-1", "agent-2"):
        for family in ("shell", "http", "filesystem", "messaging"):
            is_active, _, _, _ = _check(session, agent, family)
            assert not is_active


def _seed_block_decision(session, attempt_id: str, agent_id: str, tool_family: str, decided_at):
    from db.models import PolicyDecision, ToolAttempt

    session.add(
        ToolAttempt(
            attempt_id=attempt_id,
            session_id="sess-test",
            agent_id=agent_id,
            runtime="direct",
            tool_family=tool_family,
            action="execute",
            raw_payload="{}",
            normalized_payload="{}",
            payload_hash=f"sha256:{attempt_id}",
            normalization_status="COMPLETE",
        )
    )
    session.flush()

    session.add(
        PolicyDecision(
            decision_id=f"dec_{attempt_id}",
            attempt_id=attempt_id,
            policy_bundle_id="test-bundle",
            policy_bundle_version="1.0.0",
            ruleset_hash="sha256:test",
            risk_score=80,
            decision="BLOCK",
            reason_code="RISK_THRESHOLD_BLOCK",
            triggered_rules="[]",
            reason="test block",
            decided_at=decided_at,
        )
    )



def test_auto_trigger_ignores_other_agents_and_families():
    """Auto-trigger should only count recent blocks for the same agent and tool family."""
    from datetime import datetime, timedelta, timezone

    from core.killswitch import check_auto_trigger, check_killswitch

    session = _make_session()
    now = datetime.now(timezone.utc)

    for idx in range(3):
        _seed_block_decision(
            session,
            attempt_id=f"other-shell-{idx}",
            agent_id="other-agent",
            tool_family="shell",
            decided_at=now - timedelta(seconds=30),
        )
    for idx in range(3):
        _seed_block_decision(
            session,
            attempt_id=f"target-http-{idx}",
            agent_id="target-agent",
            tool_family="http",
            decided_at=now - timedelta(seconds=30),
        )
    session.commit()

    activated = check_auto_trigger(
        session=session,
        tool_family="shell",
        agent_id="target-agent",
        shell_block_count=3,
        shell_block_window=120,
        http_block_count=10,
        http_block_window=300,
        escalate_count=3,
    )

    assert activated == []
    is_active, _, _, _ = check_killswitch(session, "target-agent", "shell", None)
    assert not is_active



def test_auto_trigger_activates_for_matching_agent_and_family():
    """Auto-trigger should activate once the matching agent/family reaches the threshold."""
    from datetime import datetime, timedelta, timezone

    from core.killswitch import check_auto_trigger, check_killswitch
    from core.modes import KillSwitchScope

    session = _make_session()
    now = datetime.now(timezone.utc)

    for idx in range(3):
        _seed_block_decision(
            session,
            attempt_id=f"target-shell-{idx}",
            agent_id="target-agent",
            tool_family="shell",
            decided_at=now - timedelta(seconds=30),
        )
    session.commit()

    activated = check_auto_trigger(
        session=session,
        tool_family="shell",
        agent_id="target-agent",
        shell_block_count=3,
        shell_block_window=120,
        http_block_count=10,
        http_block_window=300,
        escalate_count=3,
    )
    session.commit()

    assert len(activated) == 1
    is_active, scope, scope_value, _ = check_killswitch(session, "target-agent", "shell", None)
    assert is_active
    assert scope == KillSwitchScope.AGENT
    assert scope_value == "target-agent"


