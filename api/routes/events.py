"""api/routes/events.py - GET /v1/events"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlmodel import Session, select

from api.auth import require_admin
from db.models import AuditEvent
from db.sqlite import get_session

router = APIRouter(dependencies=[Depends(require_admin)])

logger = logging.getLogger(__name__)


@router.get("/events")
def list_events(
    limit: int = Query(default=50, ge=1, le=500),
    agent_id: str | None = Query(default=None, max_length=256),
    tool_family: str | None = Query(default=None, max_length=128),
    event_type: str | None = Query(default=None, max_length=128),
    session: Session = Depends(get_session),
):
    stmt = select(AuditEvent).order_by(AuditEvent.created_at.desc())

    if event_type:
        stmt = stmt.where(AuditEvent.event_type == event_type)
    if agent_id:
        stmt = stmt.where(
            func.json_extract(AuditEvent.event_payload, "$.agent_id") == agent_id
        )
    if tool_family:
        stmt = stmt.where(
            func.json_extract(AuditEvent.event_payload, "$.tool_family") == tool_family
        )

    stmt = stmt.limit(limit)
    events = session.exec(stmt).all()

    result = []
    for event in events:
        try:
            payload = json.loads(event.event_payload)
        except Exception:
            logger.warning(
                "events_payload_parse_failed event_id=%s event_type=%s",
                event.event_id,
                event.event_type,
            )
            payload = {}
        result.append(
            {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "related_attempt_id": event.related_attempt_id,
                "chain_id": event.chain_id,
                "event_hash": event.event_hash[:16] + "...",
                "created_at": event.created_at.isoformat() if event.created_at else None,
                "payload": payload,
            }
        )
    return {"count": len(result), "events": result}
