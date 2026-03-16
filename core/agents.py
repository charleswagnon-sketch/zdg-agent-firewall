"""Agent registry and lifecycle helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlmodel import Session, select

from db.models import AgentRecord


_VALID_AGENT_STATUSES = {"active", "suspended", "deregistered"}


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _serialize(record: AgentRecord) -> dict[str, Any]:
    return {
        "agent_id": record.agent_id,
        "agent_type": record.agent_type,
        "status": record.status,
        "metadata": json.loads(record.metadata_json or "{}"),
        "registered_at": record.registered_at.isoformat() if record.registered_at else None,
        "registered_by": record.registered_by,
        "status_changed_at": record.status_changed_at.isoformat() if record.status_changed_at else None,
        "status_changed_by": record.status_changed_by,
        "status_reason": record.status_reason,
    }


def register_agent(
    session: Session,
    agent_id: str,
    agent_type: str,
    metadata: dict[str, Any] | None,
    registered_by: str,
) -> dict[str, Any]:
    existing = session.exec(select(AgentRecord).where(AgentRecord.agent_id == agent_id)).first()
    if existing is not None:
        raise ValueError(f"Agent '{agent_id}' is already registered.")

    now = utc_now()
    record = AgentRecord(
        agent_id=agent_id,
        agent_type=agent_type,
        status="active",
        metadata_json=json.dumps(metadata or {}),
        registered_at=now,
        registered_by=registered_by,
        status_changed_at=now,
        status_changed_by=registered_by,
        status_reason="Registered",
    )
    session.add(record)
    return _serialize(record)


def get_agent(session: Session, agent_id: str) -> dict[str, Any] | None:
    record = session.exec(select(AgentRecord).where(AgentRecord.agent_id == agent_id)).first()
    if record is None:
        return None
    return _serialize(record)


def list_agents(
    session: Session,
    agent_type: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    stmt = select(AgentRecord)
    if agent_type:
        stmt = stmt.where(AgentRecord.agent_type == agent_type)
    if status:
        stmt = stmt.where(AgentRecord.status == status)
    stmt = stmt.order_by(AgentRecord.registered_at.desc())
    return [_serialize(record) for record in session.exec(stmt).all()]


def suspend_agent(session: Session, agent_id: str, operator: str, reason: str) -> dict[str, Any]:
    return _set_status(session, agent_id, "suspended", operator, reason)


def unsuspend_agent(session: Session, agent_id: str, operator: str, reason: str) -> dict[str, Any]:
    return _set_status(session, agent_id, "active", operator, reason)


def deregister_agent(session: Session, agent_id: str, operator: str, reason: str) -> dict[str, Any]:
    return _set_status(session, agent_id, "deregistered", operator, reason)


def _set_status(
    session: Session,
    agent_id: str,
    status: str,
    operator: str,
    reason: str,
) -> dict[str, Any]:
    if status not in _VALID_AGENT_STATUSES:
        raise ValueError(f"Unsupported agent status '{status}'.")

    record = session.exec(select(AgentRecord).where(AgentRecord.agent_id == agent_id)).first()
    if record is None:
        raise KeyError(f"Agent '{agent_id}' is not registered.")

    now = utc_now()
    record.status = status
    record.status_changed_at = now
    record.status_changed_by = operator
    record.status_reason = reason
    session.add(record)
    return _serialize(record)