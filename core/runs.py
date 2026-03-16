"""
core/runs.py — Developer-facing recent runs index.

Derives one row per governed run from canonical persisted state:
  - ToolAttempt        — identity, timing, handoff validation state
  - PolicyDecision     — final decision, reason code
  - ExecutionResult    — execution outcome, mock flag
  - AgentContractRecord — contract state at time of run
  - AuditEvent (ACTION_ATTEMPTED only) — guardrail_blocked

All fields are grounded in canonical persisted state written during the
governed-run transaction. No fields are synthesized outside that state.
Fields that cannot be grounded are omitted (None or False as appropriate).

Provenance rule:
  ToolAttempt is created exactly once per non-replay governed run (same
  transaction as ACTION_ATTEMPTED). Idempotency replay hits do not create
  a new ToolAttempt, so the index naturally excludes replay non-events and
  matches the ACTION_ATTEMPTED-anchored replay artifact set.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlmodel import Session

from core.replay import _duration_ms  # shared iso-to-ms helper

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200
_VALID_DECISIONS: frozenset[str] = frozenset({"ALLOW", "BLOCK", "APPROVAL_REQUIRED"})


def list_runs(
    session: "Session",
    *,
    agent_id: str | None = None,
    session_id: str | None = None,
    tool_family: str | None = None,
    decision: str | None = None,
    started_after: str | None = None,
    started_before: str | None = None,
    limit: int = _DEFAULT_LIMIT,
    offset: int = 0,
) -> dict[str, Any]:
    """Return a paginated index of governed runs derived from persisted state.

    Ordering: started_at DESC, attempt_id ASC (deterministic tie-break).
    Pagination: limit/offset. Max limit: 200.

    Filters applied at DB level (indexed columns):
      agent_id, session_id, tool_family, decision, started_after, started_before.

    Returns:
      { "count": <total matching runs>, "runs": [ <run rows> ] }

    LIC-01 gate point: add entitlement check here before executing the query.
    Candidates: max_runs_retention (limit window), plan_code feature flag for
    runs index access, per-row field filtering based on plan tier.
    """
    from datetime import datetime

    from db.models import (
        AgentContractRecord,
        AuditEvent,
        ExecutionResult,
        PolicyDecision,
        ToolAttempt,
    )
    from sqlmodel import func, select

    limit = min(max(limit, 1), _MAX_LIMIT)
    offset = max(offset, 0)

    _ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(T[\d:.+Z-]+)?$")
    if started_after is not None and not _ISO_RE.match(started_after):
        raise ValueError(
            "started_after must be an ISO 8601 datetime string (e.g. 2024-01-01T00:00:00)."
        )
    if started_before is not None and not _ISO_RE.match(started_before):
        raise ValueError(
            "started_before must be an ISO 8601 datetime string (e.g. 2024-01-01T00:00:00)."
        )

    # ── Step 1: build filtered ToolAttempt query ─────────────────────────────
    stmt = select(ToolAttempt)

    if agent_id:
        stmt = stmt.where(ToolAttempt.agent_id == agent_id)
    if session_id:
        stmt = stmt.where(ToolAttempt.session_id == session_id)
    if tool_family:
        stmt = stmt.where(ToolAttempt.tool_family == tool_family)
    if started_after:
        stmt = stmt.where(ToolAttempt.requested_at >= datetime.fromisoformat(started_after))
    if started_before:
        stmt = stmt.where(ToolAttempt.requested_at <= datetime.fromisoformat(started_before))
    if decision:
        decision_upper = decision.upper()
        if decision_upper not in _VALID_DECISIONS:
            raise ValueError(
                f"Invalid decision filter {decision!r}. "
                f"Valid values: {', '.join(sorted(_VALID_DECISIONS))}."
            )
        # PolicyDecision.decision is an indexed column — filter at DB level
        stmt = stmt.join(
            PolicyDecision,
            PolicyDecision.attempt_id == ToolAttempt.attempt_id,
        ).where(PolicyDecision.decision == decision_upper)

    # ── Step 2: count and paginate ────────────────────────────────────────────
    total: int = session.exec(
        select(func.count()).select_from(stmt.subquery())
    ).one()

    stmt = (
        stmt
        .order_by(ToolAttempt.requested_at.desc(), ToolAttempt.attempt_id.asc())
        .offset(offset)
        .limit(limit)
    )
    attempts = session.exec(stmt).all()

    if not attempts:
        return {"count": total, "runs": []}

    attempt_ids = [a.attempt_id for a in attempts]

    # ── Step 3: batch fetch related records in 4 queries ─────────────────────
    decisions: dict[str, PolicyDecision] = {
        pd.attempt_id: pd
        for pd in session.exec(
            select(PolicyDecision).where(PolicyDecision.attempt_id.in_(attempt_ids))
        ).all()
    }
    exec_results: dict[str, ExecutionResult] = {
        er.attempt_id: er
        for er in session.exec(
            select(ExecutionResult).where(ExecutionResult.attempt_id.in_(attempt_ids))
        ).all()
    }
    # AgentContractRecord.run_id == attempt_id (one contract per run)
    contracts: dict[str, AgentContractRecord] = {
        cr.run_id: cr
        for cr in session.exec(
            select(AgentContractRecord).where(
                AgentContractRecord.run_id.in_(attempt_ids)
            )
        ).all()
    }
    # ACTION_ATTEMPTED carries guardrail_blocked — one event per attempt
    action_attempted_payloads: dict[str, dict[str, Any]] = {
        ev.related_attempt_id: json.loads(ev.event_payload or "{}")
        for ev in session.exec(
            select(AuditEvent)
            .where(AuditEvent.related_attempt_id.in_(attempt_ids))
            .where(AuditEvent.event_type == "ACTION_ATTEMPTED")
        ).all()
        if ev.related_attempt_id is not None
    }

    # ── Step 4: shape each run row ────────────────────────────────────────────
    runs = []
    for attempt in attempts:
        aid = attempt.attempt_id
        pd = decisions.get(aid)
        er = exec_results.get(aid)
        cr = contracts.get(aid)
        ap = action_attempted_payloads.get(aid) or {}

        # ended_at: prefer execution completion time, fall back to decision time
        if er is not None and er.completed_at:
            ended_at = er.completed_at.isoformat()
        elif pd is not None and pd.decided_at:
            ended_at = pd.decided_at.isoformat()
        else:
            ended_at = None

        started_at = attempt.requested_at.isoformat() if attempt.requested_at else None

        # handoff_status from ToolAttempt.handoff_validation_state (indexed column).
        # "passed" includes the vacuous pass: when no handoff envelope is present the
        # validator resolves the handoff as vacuously valid and writes "passed" to the DB.
        # That means a run with no explicit handoff can still show handoff_status="passed".
        hvs = attempt.handoff_validation_state
        handoff_status = (
            "passed" if hvs == "passed"
            else "failed" if hvs == "failed"
            else "none"
        )

        runs.append({
            "attempt_id": aid,
            "session_id": attempt.session_id,
            "agent_id": attempt.agent_id,
            "tool_family": attempt.tool_family,
            "action": attempt.action,
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_ms": _duration_ms(started_at, ended_at),
            "final_decision": pd.decision if pd else None,
            "terminal_reason_code": pd.reason_code if pd else None,
            "execution_status": er.execution_status if er else None,
            # executed=True only when the wrapper invoked the real tool against an
            # external system. mock=True means the wrapper returned a simulated outcome
            # without actual invocation (e.g. integration-test mode). In mock mode:
            # executed=False, mock=True, execution_status="mock_success".
            "executed": er.executed if er is not None else False,
            "mock": er.mock if er is not None else False,
            "guardrail_blocked": bool(ap.get("guardrail_blocked", False)),
            "handoff_status": handoff_status,
            "contract_state": cr.contract_state if cr else None,
        })

    return {"count": total, "runs": runs}


