"""Helpers for extracting OpenClaw metadata and stable identifiers."""

from __future__ import annotations

from typing import Any

from adapters.openclaw.config import SUPPORTED_OPENCLAW_VERSION


def extract_tool_name(tool_call: dict[str, Any]) -> str:
    """Return the normalized tool name from an OpenClaw tool call."""

    return str(tool_call.get("tool_name") or tool_call.get("name") or "").strip()


def extract_tool_input(tool_call: dict[str, Any]) -> dict[str, Any] | None:
    """Return the tool input payload if it is dict-shaped."""

    payload = tool_call.get("tool_input")
    if payload is None:
        payload = tool_call.get("input")
    if payload is None:
        return {}
    if isinstance(payload, dict):
        return dict(payload)
    return None


def extract_tool_use_id(tool_call: dict[str, Any]) -> str | None:
    """Return the stable tool-use identifier if present."""

    value = tool_call.get("tool_use_id") or tool_call.get("id")
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def extract_conversation_id(tool_call: dict[str, Any]) -> str | None:
    """Return the OpenClaw conversation identifier if present."""

    value = tool_call.get("conversation_id") or tool_call.get("thread_id")
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def resolve_agent_id(tool_call: dict[str, Any], agent_id_field: str) -> str:
    """Resolve the agent identifier with a stable fallback."""

    candidates = [
        tool_call.get(agent_id_field),
        tool_call.get("assistant_id"),
        tool_call.get("agent_id"),
        extract_conversation_id(tool_call),
    ]
    for candidate in candidates:
        if candidate is None:
            continue
        text = str(candidate).strip()
        if text:
            return text
    return "openclaw-unknown-agent"


def build_openclaw_metadata(
    tool_call: dict[str, Any],
    agent_id_field: str,
    supported_version: str = SUPPORTED_OPENCLAW_VERSION,
) -> dict[str, Any]:
    """Build the metadata envelope attached to the ZDG request."""

    metadata = {
        "schema_version": str(
            tool_call.get("openclaw_version")
            or tool_call.get("schema_version")
            or supported_version
        ),
        "tool_name": extract_tool_name(tool_call),
        "tool_use_id": extract_tool_use_id(tool_call),
        "conversation_id": extract_conversation_id(tool_call),
        "assistant_id": tool_call.get("assistant_id"),
        "agent_id_source": agent_id_field,
        "model": tool_call.get("model"),
        "timestamp": tool_call.get("timestamp"),
    }
    return {key: value for key, value in metadata.items() if value not in (None, "")}
