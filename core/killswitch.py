"""
core/killswitch.py - Kill switch state management.

Supports four scopes: global, agent, tool_family, session.
Precedence (highest to lowest): global -> agent -> tool_family -> session.

Kill switch evaluation occurs BEFORE policy evaluation.
If any applicable scope is active, the action is BLOCKED immediately
with reason_code=KILLSWITCH_ACTIVE.

Auto-trigger conditions:
  - 3 shell BLOCK events within 120 seconds -> agent-scoped halt
  - 10 HTTP BLOCK events within 300 seconds -> agent-scoped halt
  - KS_ESCALATE_COUNT distinct agent halts  -> global halt
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlmodel import Session

from core.modes import KillSwitchScope


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def check_killswitch(
    session: "Session",
    agent_id: str,
    tool_family: str,
    session_id: str | None,
) -> tuple[bool, KillSwitchScope | None, str | None, str | None]:
    """
    Check whether any active kill switch applies to this request.

    Evaluates scopes in precedence order: global -> agent -> tool_family -> session.
    Returns the first matching active scope.
    """
    from db.models import KillSwitchEvent
    from sqlmodel import select

    scope_checks: list[tuple[KillSwitchScope, str | None]] = [
        (KillSwitchScope.GLOBAL, None),
        (KillSwitchScope.AGENT, agent_id),
        (KillSwitchScope.TOOL_FAMILY, tool_family),
        (KillSwitchScope.SESSION, session_id),
    ]

    for scope, scope_value in scope_checks:
        stmt = (
            select(KillSwitchEvent)
            .where(KillSwitchEvent.scope == scope.value)
            .where(KillSwitchEvent.reset_at.is_(None))  # type: ignore[attr-defined]
        )
        if scope_value is not None:
            stmt = stmt.where(KillSwitchEvent.scope_value == scope_value)

        event = session.exec(stmt).first()
        if event:
            return True, scope, scope_value, event.trigger_reason

    return False, None, None, None


def activate_killswitch(
    session: "Session",
    scope: KillSwitchScope,
    scope_value: str | None,
    trigger_reason: str,
    agent_id: str | None = None,
    session_id: str | None = None,
    triggered_by: str = "auto",
) -> str:
    """
    Insert a new active kill switch event.
    Returns the new event id.
    Does not commit - caller is responsible.
    """
    from db.models import KillSwitchEvent

    event_id = f"ks_{uuid.uuid4().hex[:12]}"
    event = KillSwitchEvent(
        id=event_id,
        scope=scope.value,
        scope_value=scope_value,
        triggered_at=utc_now(),
        trigger_reason=trigger_reason,
        agent_id=agent_id,
        session_id=session_id,
        reset_at=None,
        reset_by=None,
    )
    session.add(event)
    return event_id


def reset_killswitch(
    session: "Session",
    operator: str,
    scope: KillSwitchScope = KillSwitchScope.GLOBAL,
    scope_value: str | None = None,
) -> int:
    """
    Reset all active kill switches matching scope + scope_value.
    Returns count of events reset.
    """
    from db.models import KillSwitchEvent
    from sqlmodel import select

    stmt = (
        select(KillSwitchEvent)
        .where(KillSwitchEvent.scope == scope.value)
        .where(KillSwitchEvent.reset_at.is_(None))  # type: ignore[attr-defined]
    )
    if scope_value is not None:
        stmt = stmt.where(KillSwitchEvent.scope_value == scope_value)

    events = session.exec(stmt).all()
    now = utc_now()
    for event in events:
        event.reset_at = now
        event.reset_by = operator
        session.add(event)

    return len(events)


def get_status(session: "Session") -> dict[str, Any]:
    """Return current kill switch status for all scopes."""
    from db.models import KillSwitchEvent
    from sqlmodel import select

    stmt = select(KillSwitchEvent).where(KillSwitchEvent.reset_at.is_(None))  # type: ignore[attr-defined]
    active = session.exec(stmt).all()

    global_halt = any(e.scope == "global" for e in active)
    scoped = [
        {
            "scope": e.scope,
            "scope_value": e.scope_value,
            "triggered_at": e.triggered_at.isoformat() if e.triggered_at else None,
            "trigger_reason": e.trigger_reason,
        }
        for e in active
        if e.scope != "global"
    ]

    return {"global_halt": global_halt, "scoped_halts": scoped}


def check_auto_trigger(
    session: "Session",
    tool_family: str,
    agent_id: str,
    shell_block_count: int,
    shell_block_window: int,
    http_block_count: int,
    http_block_window: int,
    escalate_count: int,
) -> list[str]:
    """
    After a BLOCK event, check auto-trigger conditions.
    Returns list of newly activated kill switch event IDs.

    Auto-trigger logic:
    1. Count BLOCK decisions for this agent+tool_family in the relevant window.
    2. If count >= threshold and no agent-scoped halt exists: create agent halt.
    3. Count distinct agent-scoped halts today.
    4. If count >= escalate_count and no global halt exists: create global halt.
    """
    from db.models import KillSwitchEvent, PolicyDecision, ToolAttempt
    from sqlmodel import func, select

    activated: list[str] = []
    now = utc_now()

    if tool_family == "shell":
        count_threshold = shell_block_count
        window_seconds = shell_block_window
    elif tool_family == "http":
        count_threshold = http_block_count
        window_seconds = http_block_window
    else:
        return activated

    window_start = now - timedelta(seconds=window_seconds)

    block_stmt = (
        select(func.count())
        .select_from(PolicyDecision)
        .join(ToolAttempt, ToolAttempt.attempt_id == PolicyDecision.attempt_id)
        .where(PolicyDecision.decision == "BLOCK")
        .where(PolicyDecision.decided_at >= window_start)
        .where(ToolAttempt.agent_id == agent_id)
        .where(ToolAttempt.tool_family == tool_family)
    )
    block_count = session.exec(block_stmt).one() or 0

    existing_stmt = (
        select(KillSwitchEvent)
        .where(KillSwitchEvent.scope == "agent")
        .where(KillSwitchEvent.scope_value == agent_id)
        .where(KillSwitchEvent.reset_at.is_(None))  # type: ignore[attr-defined]
    )
    existing = session.exec(existing_stmt).first()

    if block_count >= count_threshold and not existing:
        ks_id = activate_killswitch(
            session,
            scope=KillSwitchScope.AGENT,
            scope_value=agent_id,
            trigger_reason=(
                f"Auto-triggered: {block_count} {tool_family} BLOCK events "
                f"in {window_seconds}s window"
            ),
            agent_id=agent_id,
        )
        activated.append(ks_id)

        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        agent_halts_today_stmt = (
            select(func.count(func.distinct(KillSwitchEvent.scope_value)))
            .select_from(KillSwitchEvent)
            .where(KillSwitchEvent.scope == "agent")
            .where(KillSwitchEvent.triggered_at >= today_start)
        )
        agent_halts_today = session.exec(agent_halts_today_stmt).one() or 0

        global_active_stmt = (
            select(KillSwitchEvent)
            .where(KillSwitchEvent.scope == "global")
            .where(KillSwitchEvent.reset_at.is_(None))  # type: ignore[attr-defined]
        )
        global_active = session.exec(global_active_stmt).first()

        if agent_halts_today >= escalate_count and not global_active:
            global_ks_id = activate_killswitch(
                session,
                scope=KillSwitchScope.GLOBAL,
                scope_value=None,
                trigger_reason=(
                    f"Auto-escalated: {agent_halts_today} agent-scoped halts today"
                ),
            )
            activated.append(global_ks_id)

    return activated
