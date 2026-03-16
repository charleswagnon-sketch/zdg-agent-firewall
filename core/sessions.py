"""Session registry and lifecycle helpers."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlmodel import Session, select

from db.models import SessionRecord


_VALID_SESSION_STATUSES = {"active", "closed", "suspended"}


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _serialize(record: SessionRecord) -> dict[str, Any]:
    return {
        "session_id": record.session_id,
        "agent_id": record.agent_id,
        "status": record.status,
        "metadata": json.loads(record.metadata_json or "{}"),
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "created_by": record.created_by,
        "creation_source": record.creation_source,
        "closed_at": record.closed_at.isoformat() if record.closed_at else None,
        "closed_by": record.closed_by,
        "close_reason": record.close_reason,
        "suspended_at": record.suspended_at.isoformat() if record.suspended_at else None,
        "suspended_by": record.suspended_by,
        "suspend_reason": record.suspend_reason,
    }


def create_session(
    session: Session,
    agent_id: str | None,
    metadata: dict[str, Any] | None,
    created_by: str,
    creation_source: str = "api",
) -> dict[str, Any]:
    session_id = f"ses_{uuid.uuid4().hex[:16]}"
    now = utc_now()
    record = SessionRecord(
        session_id=session_id,
        agent_id=agent_id,
        status="active",
        metadata_json=json.dumps(metadata or {}),
        created_at=now,
        created_by=created_by,
        creation_source=creation_source,
        closed_at=None,
        closed_by=None,
        close_reason=None,
        suspended_at=None,
        suspended_by=None,
        suspend_reason=None,
    )
    session.add(record)
    return _serialize(record)


def get_session_info(session: Session, session_id: str) -> dict[str, Any] | None:
    record = session.exec(select(SessionRecord).where(SessionRecord.session_id == session_id)).first()
    if record is None:
        return None
    return _serialize(record)


def list_active_sessions(session: Session, agent_id: str | None = None) -> list[dict[str, Any]]:
    stmt = select(SessionRecord).where(SessionRecord.status == "active")
    if agent_id:
        stmt = stmt.where(SessionRecord.agent_id == agent_id)
    stmt = stmt.order_by(SessionRecord.created_at.desc())
    return [_serialize(record) for record in session.exec(stmt).all()]


def list_sessions(
    session: Session,
    agent_id: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    stmt = select(SessionRecord)
    if agent_id:
        stmt = stmt.where(SessionRecord.agent_id == agent_id)
    if status:
        stmt = stmt.where(SessionRecord.status == status)
    stmt = stmt.order_by(SessionRecord.created_at.desc())
    return [_serialize(record) for record in session.exec(stmt).all()]


def close_session(session: Session, session_id: str, operator: str, reason: str) -> dict[str, Any]:
    record = _get_record(session, session_id)
    now = utc_now()
    record.status = "closed"
    record.closed_at = now
    record.closed_by = operator
    record.close_reason = reason
    session.add(record)
    return _serialize(record)


def suspend_session(session: Session, session_id: str, operator: str, reason: str) -> dict[str, Any]:
    record = _get_record(session, session_id)
    now = utc_now()
    record.status = "suspended"
    record.suspended_at = now
    record.suspended_by = operator
    record.suspend_reason = reason
    session.add(record)
    return _serialize(record)


def unsuspend_session(session: Session, session_id: str, operator: str, reason: str) -> dict[str, Any]:
    record = _get_record(session, session_id)
    if record.status == "closed":
        raise ValueError("Closed sessions cannot be unsuspended.")
    record.status = "active"
    record.suspended_at = None
    # Clear suspension attribution — unsuspend operator/reason is captured in the
    # audit event emitted by the caller, not stored in the session record fields
    # that describe the original suspension.
    record.suspended_by = None
    record.suspend_reason = None
    session.add(record)
    return _serialize(record)


def _get_record(session: Session, session_id: str) -> SessionRecord:
    record = session.exec(select(SessionRecord).where(SessionRecord.session_id == session_id)).first()
    if record is None:
        raise KeyError(f"Session '{session_id}' was not found.")
    if record.status not in _VALID_SESSION_STATUSES:
        raise ValueError(f"Unsupported session status '{record.status}'.")
    return record