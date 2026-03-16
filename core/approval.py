"""
core/approval.py - Approval workflow management.

Approvals are bound to payload_hash, decision_id, policy bundle version, and expiry
at creation time. Phase 2A additionally supports one-time consumption of a resolved
approval by a later matching /v1/action request.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from db.models import Approval
    from sqlmodel import Session

from core.modes import ReasonCode


def utc_now() -> datetime:
    """Naive UTC datetime compatible with SQLite round-trip semantics."""

    return datetime.now(timezone.utc).replace(tzinfo=None)


def _normalize_utc_naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _is_expired(expires_at: datetime, now: datetime | None = None) -> bool:
    current = now or utc_now()
    return _normalize_utc_naive(current) >= _normalize_utc_naive(expires_at)


def create_approval(
    session: "Session",
    decision_id: str,
    policy_bundle_version: str,
    agent_id: str,
    tool_family: str,
    action: str,
    payload_hash: str,
    risk_score: int,
    triggered_rules: list[str],
    reason: str,
    expiry_seconds: int = 600,
) -> tuple[str, datetime]:
    """Create a new pending approval record."""

    import json

    from db.models import Approval

    approval_id = f"apv_{uuid.uuid4().hex[:16]}"
    created_at = utc_now()
    expires_at = created_at + timedelta(seconds=expiry_seconds)

    record = Approval(
        approval_id=approval_id,
        decision_id=decision_id,
        payload_hash=payload_hash,
        policy_bundle_version=policy_bundle_version,
        agent_id=agent_id,
        tool_family=tool_family,
        action=action,
        risk_score=risk_score,
        triggered_rules=json.dumps(triggered_rules),
        reason=reason,
        approved=None,
        operator=None,
        comment=None,
        expires_at=expires_at,
        created_at=created_at,
        resolved_at=None,
        consumed_at=None,
        consumed_attempt_id=None,
    )
    session.add(record)
    return approval_id, expires_at


def resolve_approval(
    session: "Session",
    approval_id: str,
    incoming_payload_hash: str,
    incoming_decision_id: str,
    incoming_bundle_version: str,
    approved: bool,
    operator: str,
    comment: str | None = None,
) -> tuple[bool, ReasonCode, str]:
    """Resolve a pending approval."""

    from db.models import Approval
    from sqlmodel import select

    stmt = select(Approval).where(Approval.approval_id == approval_id)
    record = session.exec(stmt).first()

    if not record:
        return False, ReasonCode.APPROVAL_NOT_FOUND, "Approval record not found."

    if record.resolved_at is not None:
        return False, ReasonCode.APPROVAL_ALREADY_RESOLVED, "Approval already resolved."

    now = utc_now()
    if _is_expired(record.expires_at, now=now):
        record.approved = False
        record.resolved_at = now
        record.comment = "AUTO_EXPIRED"
        session.add(record)
        return (
            False,
            ReasonCode.APPROVAL_EXPIRED,
            "Approval window has closed. Re-submit the action for a new evaluation.",
        )

    if incoming_payload_hash != record.payload_hash:
        return (
            False,
            ReasonCode.PAYLOAD_MISMATCH,
            "Payload hash mismatch - the submitted payload differs from the approved request.",
        )

    if incoming_decision_id != record.decision_id:
        return (
            False,
            ReasonCode.PAYLOAD_MISMATCH,
            "Decision ID mismatch - this approval does not apply to the current request.",
        )

    if incoming_bundle_version != record.policy_bundle_version:
        return False, ReasonCode.PAYLOAD_MISMATCH, "Policy bundle version changed since approval was created."

    record.approved = approved
    record.operator = operator
    record.comment = comment
    record.resolved_at = now
    session.add(record)

    if approved:
        return True, ReasonCode.ALLOW, f"Approved by operator '{operator}'"
    return True, ReasonCode.EXPLICIT_POLICY_DENY, f"Denied by operator '{operator}'"


def check_approved_action(
    session: "Session",
    approval_id: str,
    payload_hash: str,
    policy_bundle_version: str,
    agent_id: str,
    tool_family: str,
    action: str,
) -> tuple[bool, ReasonCode, str, "Approval | None"]:
    """Validate whether a resolved approval authorizes one later matching action."""

    from db.models import Approval
    from sqlmodel import select

    record = session.exec(
        select(Approval).where(Approval.approval_id == approval_id)
    ).first()

    if not record:
        return False, ReasonCode.APPROVAL_NOT_FOUND, "Approval record not found.", None

    if record.resolved_at is None or record.approved is None:
        return False, ReasonCode.PAYLOAD_MISMATCH, "Approval has not been resolved yet.", record

    if record.approved is False:
        return False, ReasonCode.EXPLICIT_POLICY_DENY, "Approval was explicitly denied by an operator.", record

    if _is_expired(record.expires_at):
        return False, ReasonCode.APPROVAL_EXPIRED, "Approval window has closed. Re-submit the action for a new evaluation.", record

    if record.consumed_at is not None:
        return False, ReasonCode.APPROVAL_ALREADY_USED, "Approval has already been consumed by a prior execution.", record

    if payload_hash != record.payload_hash:
        return False, ReasonCode.PAYLOAD_MISMATCH, "Payload hash mismatch - this approval does not match the submitted action.", record

    if policy_bundle_version != record.policy_bundle_version:
        return False, ReasonCode.PAYLOAD_MISMATCH, "Policy bundle version changed since approval was created.", record

    if agent_id != record.agent_id or tool_family != record.tool_family or action != record.action:
        return False, ReasonCode.PAYLOAD_MISMATCH, "Approval does not match the agent, tool family, or action being submitted.", record

    return True, ReasonCode.APPROVED_MATCHED, f"Resolved approval '{approval_id}' authorizes this execution.", record


def consume_approval(
    session: "Session",
    approval_id: str,
    attempt_id: str,
) -> tuple[bool, ReasonCode, str]:
    """Mark a resolved approval as consumed by a specific tool attempt."""

    from db.models import Approval
    from sqlmodel import select

    record = session.exec(
        select(Approval).where(Approval.approval_id == approval_id)
    ).first()

    if not record:
        return False, ReasonCode.APPROVAL_NOT_FOUND, "Approval record not found."

    if record.consumed_at is not None:
        return False, ReasonCode.APPROVAL_ALREADY_USED, "Approval has already been consumed by a prior execution."

    record.consumed_at = utc_now()
    record.consumed_attempt_id = attempt_id
    session.add(record)
    return True, ReasonCode.APPROVED_MATCHED, f"Approval '{approval_id}' consumed by attempt '{attempt_id}'."


def get_pending(session: "Session") -> list[dict]:
    """Return all non-expired, unresolved approvals."""

    import json

    from db.models import Approval
    from sqlmodel import select

    now = utc_now()
    stmt = (
        select(Approval)
        .where(Approval.resolved_at.is_(None))
        .where(Approval.expires_at > now)
        .order_by(Approval.created_at.desc())
    )
    records = session.exec(stmt).all()
    return [
        {
            "approval_id": record.approval_id,
            "decision_id": record.decision_id,
            "agent_id": record.agent_id,
            "tool_family": record.tool_family,
            "action": record.action,
            "payload_hash": record.payload_hash,
            "policy_bundle_version": record.policy_bundle_version,
            "risk_score": record.risk_score,
            "triggered_rules": json.loads(record.triggered_rules or "[]"),
            "reason": record.reason,
            "expires_at": record.expires_at.isoformat() if record.expires_at else None,
            "created_at": record.created_at.isoformat() if record.created_at else None,
        }
        for record in records
    ]