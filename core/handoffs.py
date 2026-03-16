"""core/handoffs.py - Static typed handoff registry and validation."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Callable

from core.modes import Disposition, HandoffValidationState
from core.schemas import HandoffEnvelope, HandoffSchema, HandoffValidationResult, RunAuthorityContext


_TYPE_LABELS: dict[type, str] = {
    str: "string",
    int: "integer",
    bool: "boolean",
    dict: "object",
    list: "array",
}


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _validate_filesystem_payload(payload: dict[str, Any]) -> list[str]:
    operation = str(payload.get("operation", "read")).lower().strip()
    if operation == "move" and not any(payload.get(key) for key in ("destination", "dst", "target_path")):
        return ["Filesystem move handoff requires destination, dst, or target_path."]
    return []


def _validate_http_payload(payload: dict[str, Any]) -> list[str]:
    method = str(payload.get("method", "GET")).upper().strip()
    body_present = payload.get("body") is not None or payload.get("payload") is not None
    if method in {"POST", "PUT", "PATCH"} and not body_present:
        return [f"HTTP {method} handoff requires body or payload for governed execution."]
    return []


def _validate_messaging_payload(payload: dict[str, Any]) -> list[str]:
    recipients = payload.get("to") or []
    if not recipients:
        return ["Messaging handoff requires at least one primary recipient."]
    return []


_POST_VALIDATORS: dict[str, Callable[[dict[str, Any]], list[str]]] = {
    "filesystem:*": _validate_filesystem_payload,
    "http:request": _validate_http_payload,
    "messaging:send": _validate_messaging_payload,
}


_STATIC_HANDOFF_REGISTRY: dict[tuple[str, str], HandoffSchema] = {
    ("shell", "execute"): HandoffSchema(
        schema_id="handoff.shell.execute",
        schema_version="1.0",
        tool_family="shell",
        action="execute",
        required_fields=["command"],
        optional_fields=["working_dir", "cwd", "env", "timeout"],
        field_types={
            "command": "string",
            "working_dir": "string",
            "cwd": "string",
            "env": "object",
            "timeout": "integer",
        },
    ),
    ("http", "request"): HandoffSchema(
        schema_id="handoff.http.request",
        schema_version="1.0",
        tool_family="http",
        action="request",
        required_fields=["url"],
        optional_fields=["method", "headers", "body", "payload", "payload_size_bytes"],
        field_types={
            "url": "string",
            "method": "string",
            "headers": "object",
            "body": "string",
            "payload": "string",
            "payload_size_bytes": "integer",
        },
    ),
    ("messaging", "send"): HandoffSchema(
        schema_id="handoff.messaging.send",
        schema_version="1.0",
        tool_family="messaging",
        action="send",
        required_fields=["to"],
        optional_fields=["cc", "subject", "body", "has_attachment"],
        field_types={
            "to": "string_array",
            "cc": "string_array",
            "subject": "string",
            "body": "string",
            "has_attachment": "boolean",
        },
    ),
    ("filesystem", "*"): HandoffSchema(
        schema_id="handoff.filesystem.operation",
        schema_version="1.0",
        tool_family="filesystem",
        action="*",
        required_fields=["path"],
        optional_fields=["operation", "destination", "dst", "target_path", "content", "size_bytes"],
        field_types={
            "path": "string",
            "operation": "string",
            "destination": "string",
            "dst": "string",
            "target_path": "string",
            "content": "string",
            "size_bytes": "integer",
        },
    ),
}


def build_handoff_envelope(
    *,
    authority_context: RunAuthorityContext,
    tool_family: str,
    action: str,
    args: dict[str, Any],
    timestamp: datetime,
) -> HandoffEnvelope:
    return HandoffEnvelope(
        run_id=authority_context.run_id,
        session_id=authority_context.session_id,
        trace_id=authority_context.trace_id,
        actor_id=authority_context.actor_identity.actor_id,
        agent_id=authority_context.agent_identity.agent_id,
        delegation_id=authority_context.delegation_chain.delegation_chain_id,
        authority_scope=dict(authority_context.delegation_chain.authority_scope or {}),
        contract_id=None,
        handoff_id=f"hnd_{uuid.uuid4().hex[:16]}",
        schema_version=None,
        source_component="agent_firewall.handoff_firewall",
        timestamp=timestamp,
        payload=dict(args),
        payload_reference={
            "tool_family": tool_family,
            "action": action,
            "payload_keys": sorted(str(key) for key in args.keys()),
        },
        validation_state=HandoffValidationState.PENDING,
        disposition=None,
    )


def resolve_handoff_schema(tool_family: str, action: str) -> HandoffSchema | None:
    return _STATIC_HANDOFF_REGISTRY.get((tool_family, action)) or _STATIC_HANDOFF_REGISTRY.get((tool_family, "*"))


def validate_handoff(envelope: HandoffEnvelope, schema: HandoffSchema | None) -> HandoffValidationResult:
    if schema is None:
        return HandoffValidationResult(
            handoff_id=envelope.handoff_id,
            schema_id=None,
            schema_version=None,
            validation_state=HandoffValidationState.FAILED,
            valid=False,
            errors=[f"No static handoff schema registered for {envelope.payload_reference.get('tool_family')}:{envelope.payload_reference.get('action')}."],
            disposition=Disposition.BLOCK,
            payload_reference=dict(envelope.payload_reference),
        )

    errors: list[str] = []
    payload = envelope.payload
    allowed_fields = set(schema.required_fields + schema.optional_fields)

    for field in schema.required_fields:
        if field not in payload or payload.get(field) is None:
            errors.append(f"Missing required handoff field '{field}'.")

    if schema.strict:
        unexpected = sorted(str(key) for key in payload.keys() if key not in allowed_fields)
        for field in unexpected:
            errors.append(f"Unexpected handoff field '{field}' for schema {schema.schema_id}@{schema.schema_version}.")

    for field_name, type_name in schema.field_types.items():
        if field_name not in payload or payload.get(field_name) is None:
            continue
        value = payload[field_name]
        if type_name == "string" and not isinstance(value, str):
            errors.append(f"Handoff field '{field_name}' must be a string.")
        elif type_name == "integer" and not isinstance(value, int):
            errors.append(f"Handoff field '{field_name}' must be an integer.")
        elif type_name == "boolean" and not isinstance(value, bool):
            errors.append(f"Handoff field '{field_name}' must be a boolean.")
        elif type_name == "object" and not isinstance(value, dict):
            errors.append(f"Handoff field '{field_name}' must be an object.")
        elif type_name == "string_array" and not _is_string_list(value):
            errors.append(f"Handoff field '{field_name}' must be an array of strings.")

    validator = _POST_VALIDATORS.get(f"{schema.tool_family}:{schema.action}") or _POST_VALIDATORS.get(f"{schema.tool_family}:*")
    if validator is not None:
        errors.extend(validator(payload))

    return HandoffValidationResult(
        handoff_id=envelope.handoff_id,
        schema_id=schema.schema_id,
        schema_version=schema.schema_version,
        validation_state=(
            HandoffValidationState.PASSED if not errors else HandoffValidationState.FAILED
        ),
        valid=not errors,
        errors=errors,
        disposition=Disposition.ALLOW if not errors else schema.failure_disposition,
        payload_reference=dict(envelope.payload_reference),
    )
