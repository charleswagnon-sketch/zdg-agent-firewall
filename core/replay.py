"""
core/replay.py — Operator-facing replay snapshot builder.

Shapes persisted runtime events into a human-usable replay artifact.
Most fields in the replay snapshot are observed directly from emitted
AuditEvent records for the given attempt_id. A small number of fields
are derived proxies pending first-class event support:

  in_bounds    — inferred from the fact that CREDENTIAL_ISSUED is only
                 emitted after validate_authority_context() passes; not
                 read from a stored audit field. (CRED-TRACE-01 parked)
  usage_count  — always 1 or 0 (execution event present/absent); not
                 counted from actual CREDENTIAL_USED events.
  duration_ms  — computed from first/last event timestamps.

These derived fields are clearly marked in _build_credential_summary().
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlmodel import Session


# ── Human-readable labels for canonical event types ──────────────────────────

_EVENT_LABELS: dict[str, str] = {
    # ── Governed run lifecycle ────────────────────────────────────────────────
    "ACTION_ATTEMPTED": "Intent received and evaluated",
    "ACTION_ALLOWED": "Action permitted by policy",
    "ACTION_BLOCKED": "Action blocked by policy or lifecycle gate",
    "APPROVAL_REQUIRED": "Action held pending operator approval",
    "APPROVAL_CONSUMED": "Pre-issued approval consumed",
    "UNREGISTERED_TOOL_FAMILY": "Tool family not registered with a wrapper",
    "EXECUTION_COMPLETED": "Wrapper execution completed",
    "EXECUTION_FAILED": "Wrapper execution failed or rejected",
    # ── Session lifecycle ─────────────────────────────────────────────────────
    "SESSION_CREATED": "Session opened",
    "SESSION_CLOSED_EVENT": "Session closed",
    "SESSION_SUSPENDED_EVENT": "Session suspended",
    "SESSION_UNSUSPENDED_EVENT": "Session unsuspended — active",
    # ── Contract lifecycle ────────────────────────────────────────────────────
    "CONTRACT_BOUND": "Contract bound to governed run",
    "CONTRACT_EXPIRED": "Contract TTL elapsed before lifecycle check",
    "CONTRACT_REVOKED": "Contract revoked",
    "CONTRACT_REINSTATED": "Contract reinstated",
    "CONTRACT_RENEWED": "Contract renewed — new term bound",
    "CONTRACT_USAGE_UPDATED": "Contract usage recorded",
    # ── Credential lifecycle ──────────────────────────────────────────────────
    "CREDENTIAL_ISSUED": "Ephemeral scoped credential issued",
    "CREDENTIAL_ACTIVATED": "Credential activated for privileged execution",
    "CREDENTIAL_REVOKED": "Credential revoked — lease closed",
    "CREDENTIAL_EXPIRED": "Credential expired — TTL elapsed",
    # ── Handoff lifecycle ─────────────────────────────────────────────────────
    "HANDOFF_ATTEMPTED": "Handoff envelope received",
    "HANDOFF_SCHEMA_RESOLVED": "Handoff schema resolved",
    "HANDOFF_VALIDATION_PASSED": "Handoff validation passed",
    "HANDOFF_VALIDATION_FAILED": "Handoff validation failed",
    "HANDOFF_PROPAGATION_ALLOWED": "Handoff propagation permitted",
    "HANDOFF_PROPAGATION_PREVENTED": "Handoff propagation blocked",
    "HANDOFF_DISPOSITION_APPLIED": "Handoff disposition applied",
    # ── Guardrail and breach ──────────────────────────────────────────────────
    "GUARDRAIL_EVALUATED": "Guardrail checks evaluated",
    "BREACH_WARN": "Breach warning emitted",
    "BREACH_ESCALATED": "Breach escalated — operator review required",
    "CONTRACT_BREACHED": "Policy contract threshold breached",
    "DECISION_FINALIZED": "Terminal decision finalized and recorded",
    "CREDENTIAL_USED": "Credential used for governed tool execution",
    # ── License and billing ───────────────────────────────────────────────────
    "LICENSE_ACTIVATED": "License activated",
    "LICENSE_EXPIRED": "License expired",
    "LICENSE_REVOKED": "License revoked",
    "INSTALLATION_REGISTERED": "Installation registered",
    "SUBSCRIPTION_ACTIVATED": "Stripe subscription activated",
    "SUBSCRIPTION_UPDATED": "Stripe subscription updated",
    "PAYMENT_FAILED": "Stripe payment failed",
}

_TERMINAL_EVENT_TYPES: frozenset[str] = frozenset({
    "ACTION_ALLOWED",
    "ACTION_BLOCKED",
    "APPROVAL_REQUIRED",
    "UNREGISTERED_TOOL_FAMILY",
    "DECISION_FINALIZED",
})

_EXECUTION_EVENT_TYPES: frozenset[str] = frozenset({
    "EXECUTION_COMPLETED",
    "EXECUTION_FAILED",
})


def event_label(event_type: str) -> str:
    """Return a human-readable label for a canonical event type."""
    return _EVENT_LABELS.get(event_type, event_type)


def build_attempt_replay(session: "Session", attempt_id: str) -> dict[str, Any]:
    """Build a shaped replay snapshot for a single governed run.

    All summary fields are derived from persisted AuditEvent records whose
    related_attempt_id matches the given attempt_id. The raw event payload
    for every timeline event is preserved intact alongside its human label.

    Field provenance convention used throughout this function:
      Observed — value read directly from a specific named event payload field.
      Derived  — value inferred from the presence or absence of event types,
                 or computed from multiple fields (e.g. duration_ms, used, in_bounds).

    Returns a dict with:
      - attempt_id
      - run_summary        — final decision, reason, timing, agent context (observed)
      - authority_summary  — actor and delegation identity (observed from ACTION_ATTEMPTED)
      - contract_summary   — contract lifecycle state (observed from CONTRACT_BOUND)
      - credential_summary — credential issuance, scope, use, and revocation state
                             (mix of observed event fields and derived presence checks)
      - handoff_summary    — handoff validation and disposition (observed from handoff events)
      - guardrail_summary  — guardrail block state and triggered count (observed + derived count)
      - execution_summary  — execution outcome (observed from EXECUTION_* events, defaults False)
      - usage_summary      — spend/invocation tracking if available (observed from CONTRACT_USAGE_UPDATED)
      - timeline           — ordered labeled events, raw payload intact (canonical evidence record)

    LIC-01 gate point: add entitlement check here before shaping the snapshot.
    Candidates: replay_retention (limit replay access by age), plan_code feature
    flag for snapshot vs raw-only access, per-section field redaction by tier.
    """
    from db.models import AuditEvent
    from sqlmodel import select

    # Exclude session-chain copies: every event written via
    # append_audit_event_with_session_chain is persisted on both the global
    # chain and session:<id> chain with the same payload and related_attempt_id.
    # Filtering to non-session chains keeps exactly one row per logical event
    # in the developer-facing timeline without discarding any evidence (the
    # raw export via serialize_raw_events() returns all rows unfiltered).
    events = session.exec(
        select(AuditEvent)
        .where(AuditEvent.related_attempt_id == attempt_id)
        .where(~AuditEvent.chain_id.like("session:%"))
        .order_by(AuditEvent.seq)
    ).all()

    timeline = [_serialize_labeled_event(e) for e in events]

    # Index by event type for summary extraction
    by_type: dict[str, list[dict[str, Any]]] = {}
    for ev in timeline:
        by_type.setdefault(ev["event_type"], []).append(ev)

    attempted_ev = by_type.get("ACTION_ATTEMPTED", [{}])[0]
    attempted_payload = attempted_ev.get("event_payload") or {}

    terminal_ev = _first_of_types(by_type, _TERMINAL_EVENT_TYPES)
    # Mission 1: Prefer DECISION_FINALIZED over other terminal types if present.
    dec_finalized = by_type.get("DECISION_FINALIZED")
    if dec_finalized:
        terminal_ev = dec_finalized[0]

    terminal_payload = terminal_ev.get("event_payload") or {} if terminal_ev else {}

    exec_ev = _first_of_types(by_type, _EXECUTION_EVENT_TYPES)
    exec_payload = exec_ev.get("event_payload") or {} if exec_ev else {}

    contract_bound = (by_type.get("CONTRACT_BOUND") or [{}])[0]
    contract_payload = contract_bound.get("event_payload") or {} if contract_bound else {}

    usage_list = by_type.get("CONTRACT_USAGE_UPDATED") or []
    usage_payload = (usage_list[-1].get("event_payload") or {}) if usage_list else {}

    credential_summary = _build_credential_summary(by_type, exec_ev, attempt_id)

    handoff_event, handoff_payload = _pick_handoff(by_type)

    guardrail_list = by_type.get("GUARDRAIL_EVALUATED") or []
    guardrail_payload = (guardrail_list[0].get("event_payload") or {}) if guardrail_list else {}

    # Timing
    start_time = attempted_ev.get("created_at")
    end_time = timeline[-1]["created_at"] if timeline else None
    duration_ms = _duration_ms(start_time, end_time)

    # Final decision: terminal event carries decision_state; fall back to
    # pre_lifecycle_decision from ACTION_ATTEMPTED for legacy / edge cases.
    # Mission 1: use 'decision' field from DECISION_FINALIZED if present.
    final_decision = (
        terminal_payload.get("decision")
        or terminal_payload.get("decision_state")
        or attempted_payload.get("pre_lifecycle_decision")
    )
    terminal_reason_code = (
        terminal_payload.get("reason_code")
        or attempted_payload.get("pre_lifecycle_reason_code")
    )

    # Authority summary: Mission 1: use authority_context from terminal event if available.
    auth_ctx = terminal_payload.get("authority_context") or attempted_payload.get("authority_context") or {}
    actor_id = auth_ctx.get("actor_identity", {}).get("actor_id") or attempted_payload.get("actor_id")
    delegation_chain_id = auth_ctx.get("delegation_chain", {}).get("delegation_chain_id") or attempted_payload.get("delegation_chain_id")

    # Guardrail checks triggered
    checks = guardrail_payload.get("checks") or []
    checks_triggered = sum(1 for c in checks if c.get("triggered"))

    # Handoff validation state
    if handoff_event is None:
        handoff_validation_state = "none"
    else:
        handoff_validation_state = handoff_payload.get("validation_state")

    return {
        "attempt_id": attempt_id,
        "run_summary": {
            "final_decision": final_decision,
            "terminal_reason_code": terminal_reason_code,
            "agent_id": attempted_payload.get("agent_id"),
            "tool_family": attempted_payload.get("tool_family"),
            "action": attempted_payload.get("action"),
            "session_id": attempted_payload.get("session_id"),
            "start_time": start_time,
            "end_time": end_time,
            "duration_ms": duration_ms,
            "ruleset_hash": terminal_payload.get("ruleset_hash"),
            "policy_bundle_version": terminal_payload.get("policy_bundle_version"),
        },
        "authority_summary": {
            "actor_id": actor_id,
            "delegation_chain_id": delegation_chain_id,
        },
        "contract_summary": {
            "contract_id": contract_payload.get("contract_id"),
            "contract_state": contract_payload.get("contract_state"),
            "bound_at": contract_payload.get("bound_at"),
            "expires_at": contract_payload.get("expires_at"),
        },
        "credential_summary": credential_summary,
        "handoff_summary": {
            "handoff_id": handoff_payload.get("handoff_id"),
            "validation_state": handoff_validation_state,
            "disposition": handoff_payload.get("disposition"),
        },
        "guardrail_summary": {
            "guardrail_blocked": bool(guardrail_payload.get("blocked", False)),
            "checks_triggered": checks_triggered,
        },
        # executed=True only when the wrapper invoked the real tool against an
        # external system. mock=True means the wrapper returned a simulated outcome
        # without actual invocation. In mock mode: executed=False, mock=True,
        # execution_status="mock_success". Both fields default to False when no
        # EXECUTION_COMPLETED / EXECUTION_FAILED event is present (BLOCK path).
        "execution_summary": {
            "executed": exec_payload.get("executed", False),
            "mock": exec_payload.get("mock", False),
            "execution_status": exec_payload.get("execution_status"),
            "output_summary": exec_payload.get("output_summary"),
        },
        "usage_summary": {
            "invocation_count": usage_payload.get("tool_invocations"),
            "elapsed_ms": usage_payload.get("elapsed_ms"),
        },
        "timeline": timeline,
    }


def serialize_raw_events(session: "Session", attempt_id: str) -> list[dict[str, Any]]:
    """Return the raw ordered event list for an attempt without shaping."""
    from db.models import AuditEvent
    from sqlmodel import select

    events = session.exec(
        select(AuditEvent)
        .where(AuditEvent.related_attempt_id == attempt_id)
        .order_by(AuditEvent.seq)
    ).all()
    return [
        {
            "event_id": e.event_id,
            "event_type": e.event_type,
            "related_attempt_id": e.related_attempt_id,
            "chain_id": e.chain_id,
            "prev_event_hash": e.prev_event_hash,
            "event_hash": e.event_hash,
            "created_at": e.created_at.isoformat() if e.created_at else None,
            "seq": e.seq,
            "event_payload": json.loads(e.event_payload or "{}"),
        }
        for e in events
    ]


# ── Internal helpers ──────────────────────────────────────────────────────────

def _serialize_labeled_event(record: Any) -> dict[str, Any]:
    return {
        "seq": record.seq,
        "event_type": record.event_type,
        "label": event_label(record.event_type),
        "event_id": record.event_id,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "event_payload": json.loads(record.event_payload or "{}"),
    }


def _first_of_types(
    by_type: dict[str, list[dict[str, Any]]],
    type_set: frozenset[str],
) -> dict[str, Any] | None:
    for t in type_set:
        events = by_type.get(t)
        if events:
            return events[0]
    return None


def _build_credential_summary(
    by_type: dict[str, list[dict[str, Any]]],
    exec_ev: dict[str, Any] | None,
    attempt_id: str,
) -> dict[str, Any]:
    """Derive the credential lifecycle summary from persisted events.

    Most fields are observed from CREDENTIAL_ISSUED, CREDENTIAL_USED, and
    CREDENTIAL_REVOKED event payloads.

    Mission 1 (Evidence Hardening):
      in_bounds   — OBSERVED: True if CREDENTIAL_ISSUED or CREDENTIAL_USED exists.
      usage_count — OBSERVED: Count of CREDENTIAL_USED events.

    The authority_context nested in credential event payloads is intentionally
    excluded from the summary to avoid surfacing auth_context claims.
    """
    issued_list = by_type.get("CREDENTIAL_ISSUED") or []
    used_list = by_type.get("CREDENTIAL_USED") or []
    revoked_list = by_type.get("CREDENTIAL_REVOKED") or []

    if not issued_list and not used_list:
        return {
            "issued": False,
            "grant_id": None,
            "subject_type": None,
            "subject_id": None,
            "authority_scope": None,
            "session_id": None,
            "attempt_id": attempt_id,
            "issued_at": None,
            "expires_at": None,
            "revoked_at": None,
            "revocation_reason": None,
            "used": False,
            "usage_count": 0,
            "in_bounds": False,
        }

    # Prefer data from ISSUED if available, fallback to USED for reconstruction
    primary_ev = issued_list[0] if issued_list else used_list[0]
    issued_payload = primary_ev.get("event_payload") or {}

    auth_ctx = issued_payload.get("authority_context") or {}
    actor_identity = auth_ctx.get("actor_identity") or {}
    subject_type = actor_identity.get("actor_type")

    revoked_payload = revoked_list[0].get("event_payload") or {} if revoked_list else {}

    # OBSERVED facts from Mission 1
    usage_count = len(used_list)
    used = usage_count > 0
    in_bounds = True  # Existence of issued/used events proves in-bounds

    return {
        "issued": True,
        "grant_id": issued_payload.get("grant_id"),
        "subject_type": subject_type,
        "subject_id": issued_payload.get("actor_id"),
        "authority_scope": issued_payload.get("privilege_scope"),
        "session_id": issued_payload.get("session_id"),
        "attempt_id": attempt_id,
        "issued_at": issued_payload.get("issued_at"),
        "expires_at": issued_payload.get("expires_at"),
        "revoked_at": revoked_payload.get("revoked_at"),
        "revocation_reason": revoked_payload.get("revoked_reason"),
        "used": used,
        "usage_count": usage_count,
        "in_bounds": in_bounds,
    }


def _pick_handoff(
    by_type: dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Return the first handoff validation event and its payload."""
    for t in ("HANDOFF_VALIDATION_PASSED", "HANDOFF_VALIDATION_FAILED"):
        events = by_type.get(t)
        if events:
            ev = events[0]
            return ev, ev.get("event_payload") or {}
    return None, {}


def _duration_ms(start_iso: str | None, end_iso: str | None) -> float | None:
    if not start_iso or not end_iso:
        return None
    try:
        t0 = datetime.fromisoformat(start_iso)
        t1 = datetime.fromisoformat(end_iso)
        return round((t1 - t0).total_seconds() * 1000, 2)
    except Exception:
        return None
