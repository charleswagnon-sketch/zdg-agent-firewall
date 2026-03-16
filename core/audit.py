"""Tamper-evident append-only audit helpers and portable chain utilities."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlmodel import Session

from core.normalize import canonical_json


GENESIS_HASH = "GENESIS"


def utc_now() -> datetime:
    """Naive UTC datetime compatible with SQLite round-trip semantics."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def compute_event_hash(event_fields: dict[str, Any], prev_hash: str) -> str:
    payload = canonical_json(event_fields) + ":" + (prev_hash or GENESIS_HASH)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def compute_document_hash(document_fields: dict[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json(document_fields).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _next_seq(session: "Session", chain_id: str) -> int:
    """Return the next sequence number for the given chain.

    Uses SELECT MAX(seq) + 1 within the caller's open transaction. This is safe
    and deterministic under two complementary guarantees:

    1. SQLite serializes all write transactions (WAL mode: many readers, one
       writer at a time). A second concurrent write to the same chain_id will
       wait for the first writer to commit before it can proceed. No two
       transactions can observe the same MAX(seq) and both commit successfully.

    2. SQLAlchemy autoflushes pending inserts before executing queries within
       the same session. If append_audit_event() is called twice for the same
       chain_id inside a single transaction (via append_audit_event_with_session_chain
       for two events in sequence), the second MAX(seq) query sees the first
       uncommitted INSERT, producing a correct seq=N+1 without a mid-transaction
       commit.

    Fail-closed guarantee: the UNIQUE(chain_id, seq) index on audit_events
    provides defense-in-depth. Any seq collision — however caused — raises
    sqlite3.IntegrityError at commit time. The collision never silently produces
    a duplicate seq or ambiguous replay ordering. The transaction aborts; the
    caller receives an error.

    Single-process assumption: this app runs as one uvicorn worker. Under
    multi-worker deployment each worker would need its own serialized write path
    or advisory lock; the unique constraint still provides fail-closed protection
    but concurrent write attempts would surface as IntegrityError on the second
    writer rather than blocking.
    """
    from db.models import AuditEvent
    from sqlmodel import func, select

    result = session.exec(
        select(func.max(AuditEvent.seq)).where(AuditEvent.chain_id == chain_id)
    ).one()
    return (result or 0) + 1


def get_latest_event_hash(session: "Session", chain_id: str) -> str:
    from db.models import AuditEvent
    from sqlmodel import select

    stmt = (
        select(AuditEvent.event_hash)
        .where(AuditEvent.chain_id == chain_id)
        .order_by(AuditEvent.seq.desc())
        .limit(1)
    )
    result = session.exec(stmt).first()
    return result if result else GENESIS_HASH


def append_audit_event(
    session: "Session",
    chain_id: str,
    event_type: str,
    event_payload: dict[str, Any],
    related_attempt_id: str | None = None,
) -> str:
    from db.models import AuditEvent

    event_id = f"evt_{uuid.uuid4().hex[:16]}"
    created_at = utc_now()
    seq = _next_seq(session, chain_id)

    hashable_fields = {
        "chain_id": chain_id,
        "created_at": created_at.isoformat(),
        "event_id": event_id,
        "event_payload": event_payload,
        "event_type": event_type,
        "related_attempt_id": related_attempt_id or "",
        "seq": seq,
    }

    prev_hash = get_latest_event_hash(session, chain_id)
    event_hash = compute_event_hash(hashable_fields, prev_hash)

    record = AuditEvent(
        event_id=event_id,
        event_type=event_type,
        related_attempt_id=related_attempt_id,
        chain_id=chain_id,
        prev_event_hash=prev_hash,
        event_hash=event_hash,
        event_payload=json.dumps(event_payload),
        created_at=created_at,
        seq=seq,
    )
    session.add(record)
    return event_id


def append_audit_event_with_session_chain(
    session: "Session",
    global_chain_id: str,
    session_id: str | None,
    event_type: str,
    event_payload: dict[str, Any],
    related_attempt_id: str | None = None,
) -> str:
    event_id = append_audit_event(
        session=session,
        chain_id=global_chain_id,
        event_type=event_type,
        event_payload=event_payload,
        related_attempt_id=related_attempt_id,
    )
    if session_id:
        append_audit_event(
            session=session,
            chain_id=f"session:{session_id}",
            event_type=event_type,
            event_payload=event_payload,
            related_attempt_id=related_attempt_id,
        )
    return event_id


def verify_chain(session: "Session", chain_id: str) -> tuple[bool, str]:
    from db.models import AuditEvent
    from sqlmodel import select

    stmt = select(AuditEvent).where(AuditEvent.chain_id == chain_id).order_by(AuditEvent.seq)
    events = session.exec(stmt).all()
    verification = verify_chain_export(export_chain_document(session, chain_id))
    if verification["ok"]:
        return True, f"CHAIN OK ({len(events)} events)"
    position = verification.get("first_broken_position")
    return False, (
        f"CHAIN BROKEN at position={position}: {verification.get('reason', 'verification failed')}"
    )


def export_chain_document(session: "Session", chain_id: str) -> dict[str, Any]:
    from db.models import AuditEvent
    from sqlmodel import select

    stmt = select(AuditEvent).where(AuditEvent.chain_id == chain_id).order_by(AuditEvent.seq)
    records = session.exec(stmt).all()
    events = [_serialize_event(record) for record in records]
    export_timestamp = utc_now().isoformat()
    base = {
        "chain_id": chain_id,
        "export_timestamp": export_timestamp,
        "genesis_hash": GENESIS_HASH,
        "event_count": len(events),
        "first_event_at": events[0]["created_at"] if events else None,
        "last_event_at": events[-1]["created_at"] if events else None,
        "final_hash": events[-1]["event_hash"] if events else GENESIS_HASH,
        "events": events,
    }
    base["document_hash"] = compute_document_hash(base)
    return base


def export_chain_ndjson_lines(session: "Session", chain_id: str) -> list[str]:
    document = export_chain_document(session, chain_id)
    manifest = {
        key: value
        for key, value in document.items()
        if key != "events"
    }
    lines = [json.dumps({"type": "manifest", **manifest})]
    for event in document["events"]:
        lines.append(json.dumps({"type": "event", "event": event}))
    return lines


def parse_chain_export(payload: dict[str, Any] | str) -> dict[str, Any]:
    if isinstance(payload, dict):
        return payload

    text = str(payload).strip()
    if not text:
        raise ValueError("Audit export payload is empty.")
    if text.startswith("{"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        else:
            if not isinstance(parsed, dict):
                raise ValueError("JSON audit export must be an object.")
            return parsed

    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        raise ValueError("NDJSON audit export payload is empty.")
    manifest_record = json.loads(lines[0])
    if manifest_record.get("type") != "manifest":
        raise ValueError("NDJSON export must begin with a manifest record.")
    document = {
        key: value for key, value in manifest_record.items() if key != "type"
    }
    events: list[dict[str, Any]] = []
    for line in lines[1:]:
        record = json.loads(line)
        if record.get("type") != "event":
            raise ValueError("NDJSON export contains a non-event record after the manifest.")
        events.append(record["event"])
    document["events"] = events
    return document


def verify_chain_export(payload: dict[str, Any] | str) -> dict[str, Any]:
    document = parse_chain_export(payload)
    events = list(document.get("events") or [])
    prev_hash = GENESIS_HASH
    first_broken_position: int | None = None
    reason = "CHAIN OK"

    for position, event in enumerate(events):
        hashable_fields = {
            "chain_id": document.get("chain_id"),
            "created_at": event.get("created_at"),
            "event_id": event.get("event_id"),
            "event_payload": event.get("event_payload") or {},
            "event_type": event.get("event_type"),
            "related_attempt_id": event.get("related_attempt_id") or "",
            "seq": event.get("seq"),
        }
        expected_hash = compute_event_hash(hashable_fields, prev_hash)
        if event.get("prev_event_hash") != prev_hash:
            first_broken_position = position
            reason = "Previous-event hash mismatch"
            break
        if event.get("event_hash") != expected_hash:
            first_broken_position = position
            reason = "Event hash mismatch"
            break
        prev_hash = event.get("event_hash") or GENESIS_HASH

    computed_final_hash = prev_hash if events else GENESIS_HASH
    export_without_hash = dict(document)
    claimed_document_hash = export_without_hash.pop("document_hash", None)
    computed_document_hash = compute_document_hash(export_without_hash)
    document_hash_ok = claimed_document_hash == computed_document_hash
    if first_broken_position is None and not document_hash_ok:
        reason = "Document hash mismatch"
    ok = first_broken_position is None and document_hash_ok

    return {
        "ok": ok,
        "verified_event_count": len(events),
        "claimed_final_hash": document.get("final_hash", GENESIS_HASH),
        "computed_final_hash": computed_final_hash,
        "claimed_document_hash": claimed_document_hash,
        "computed_document_hash": computed_document_hash,
        "first_broken_position": first_broken_position,
        "reason": reason,
    }


def diff_chain_exports(left_payload: dict[str, Any] | str, right_payload: dict[str, Any] | str) -> dict[str, Any]:
    left = parse_chain_export(left_payload)
    right = parse_chain_export(right_payload)
    left_events = list(left.get("events") or [])
    right_events = list(right.get("events") or [])

    common_prefix_length = 0
    for left_event, right_event in zip(left_events, right_events):
        if left_event == right_event:
            common_prefix_length += 1
            continue
        break

    first_left = left_events[common_prefix_length] if common_prefix_length < len(left_events) else None
    first_right = right_events[common_prefix_length] if common_prefix_length < len(right_events) else None

    return {
        "left_chain_id": left.get("chain_id"),
        "right_chain_id": right.get("chain_id"),
        "common_prefix_length": common_prefix_length,
        "left_event_count": len(left_events),
        "right_event_count": len(right_events),
        "first_divergent_left": first_left,
        "first_divergent_right": first_right,
        "left_unique_count": max(len(left_events) - common_prefix_length, 0),
        "right_unique_count": max(len(right_events) - common_prefix_length, 0),
    }


def _serialize_event(record: Any) -> dict[str, Any]:
    return {
        "event_id": record.event_id,
        "event_type": record.event_type,
        "related_attempt_id": record.related_attempt_id,
        "chain_id": record.chain_id,
        "prev_event_hash": record.prev_event_hash,
        "event_hash": record.event_hash,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "seq": record.seq,
        "event_payload": json.loads(record.event_payload or "{}"),
    }
