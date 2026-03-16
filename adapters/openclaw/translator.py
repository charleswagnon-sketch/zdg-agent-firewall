"""Translation between OpenClaw tool calls and ZDG action requests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from adapters.openclaw.config import SUPPORTED_OPENCLAW_VERSION
from adapters.openclaw.metadata import (
    build_openclaw_metadata,
    extract_conversation_id,
    extract_tool_input,
    extract_tool_name,
    extract_tool_use_id,
    resolve_agent_id,
)
from core.schemas import ActionRequest, ActionResponse


@dataclass(frozen=True)
class ToolMapping:
    """One OpenClaw-to-ZDG mapping definition."""

    name: str
    tool_family: str
    action: str
    args_map: dict[str, Any]
    args_passthrough: bool = False


@dataclass(frozen=True)
class TranslatedToolCall:
    """Result of translating one OpenClaw tool call."""

    tool_name: str
    tool_use_id: str | None
    action_request: ActionRequest | None
    blocked_response: dict[str, Any] | None = None


class OpenClawTranslator:
    """Translator for OpenClaw tool-call payloads."""

    def __init__(self, tool_map_path: str | Path, agent_id_field: str = "assistant_id") -> None:
        self.tool_map_path = Path(tool_map_path)
        self.agent_id_field = agent_id_field
        self.openclaw_version, self.tool_map = load_tool_map(self.tool_map_path)

    def translate_tool_call(self, tool_call: dict[str, Any]) -> TranslatedToolCall:
        """Translate one OpenClaw tool call into an ActionRequest."""

        tool_name = extract_tool_name(tool_call)
        tool_use_id = extract_tool_use_id(tool_call)
        if not tool_name:
            return TranslatedToolCall(
                tool_name="",
                tool_use_id=tool_use_id,
                action_request=None,
                blocked_response=self.blocked_response(
                    tool_call,
                    reason_code="DEFAULT_DENY",
                    reason="OpenClaw tool call is missing a supported tool_name.",
                ),
            )

        tool_input = extract_tool_input(tool_call)
        if tool_input is None:
            return TranslatedToolCall(
                tool_name=tool_name,
                tool_use_id=tool_use_id,
                action_request=None,
                blocked_response=self.blocked_response(
                    tool_call,
                    reason_code="DEFAULT_DENY",
                    reason="OpenClaw tool_input must be an object for governed execution.",
                ),
            )

        mapping = self._resolve_mapping(tool_name)
        if mapping is None:
            return TranslatedToolCall(
                tool_name=tool_name,
                tool_use_id=tool_use_id,
                action_request=None,
                blocked_response=self.blocked_response(
                    tool_call,
                    reason_code="DEFAULT_DENY",
                    reason=(
                        f"OpenClaw tool '{tool_name}' is not supported by the governed adapter. "
                        "Unsupported tools fail closed."
                    ),
                ),
            )

        args = self._build_args(mapping, tool_input, tool_name)
        metadata = {
            "openclaw": build_openclaw_metadata(
                tool_call,
                agent_id_field=self.agent_id_field,
                supported_version=self.openclaw_version,
            )
        }
        action_request = ActionRequest(
            session_id=extract_conversation_id(tool_call),
            agent_id=resolve_agent_id(tool_call, self.agent_id_field),
            runtime="openclaw",
            tool_family=mapping.tool_family,
            action=mapping.action,
            args=args,
            metadata=metadata,
            idempotency_key=tool_use_id,
        )
        return TranslatedToolCall(
            tool_name=tool_name,
            tool_use_id=tool_use_id,
            action_request=action_request,
        )

    def translate_action_response(
        self,
        tool_call: dict[str, Any],
        action_response: ActionResponse | dict[str, Any],
    ) -> dict[str, Any]:
        """Translate a ZDG ActionResponse into an OpenClaw-shaped result."""

        response = action_response
        if isinstance(action_response, dict):
            response = ActionResponse.model_validate(action_response)

        base = {
            "tool_name": extract_tool_name(tool_call),
            "tool_use_id": extract_tool_use_id(tool_call),
            "status": "completed" if response.decision.value == "ALLOW" else "blocked",
            "decision": response.decision.value,
            "reason_code": response.reason_code.value,
            "reason": response.reason,
            "zdg": {
                "trace_id": response.trace_id,
                "attempt_id": response.attempt_id,
                "decision_id": response.decision_id,
                "agent_id": response.agent_id,
                "session_id": response.session_id,
                "tool_family": response.tool_family,
                "action": response.action,
                "policy_bundle_id": response.policy_bundle_id,
                "policy_bundle_version": response.policy_bundle_version,
                "ruleset_hash": response.ruleset_hash,
                "payload_hash": response.payload_hash,
                "triggered_rules": response.triggered_rules,
                "risk_score": response.risk_score,
                "idempotent_replay": response.idempotent_replay,
                "approval_consumed": response.approval_consumed,
                "timestamp": response.timestamp.isoformat(),
            },
        }

        if response.decision.value == "ALLOW":
            base["result"] = response.execution.model_dump() if response.execution else None
            return base

        if response.decision.value == "APPROVAL_REQUIRED":
            base["status"] = "approval_required"
            base["approval"] = {
                "approval_id": response.approval_id,
                "approval_expires_at": (
                    response.approval_expires_at.isoformat()
                    if response.approval_expires_at is not None
                    else None
                ),
            }
            return base

        base["error"] = {
            "reason_code": response.reason_code.value,
            "reason": response.reason,
        }
        return base

    def blocked_response(
        self,
        tool_call: dict[str, Any],
        reason_code: str,
        reason: str,
        http_status: int | None = None,
    ) -> dict[str, Any]:
        """Return a structured denial before or around the ZDG call."""

        response = {
            "tool_name": extract_tool_name(tool_call),
            "tool_use_id": extract_tool_use_id(tool_call),
            "status": "blocked",
            "decision": "BLOCK",
            "reason_code": reason_code,
            "reason": reason,
            "error": {
                "reason_code": reason_code,
                "reason": reason,
            },
            "zdg": {
                "transport_status": http_status,
                "tool_family": None,
                "action": None,
            },
        }
        return response

    def passthrough_response(self, tool_call: dict[str, Any], reason: str) -> dict[str, Any]:
        """Return a non-production fail-open marker for development use only."""

        return {
            "tool_name": extract_tool_name(tool_call),
            "tool_use_id": extract_tool_use_id(tool_call),
            "status": "passthrough",
            "decision": "ALLOW",
            "reason_code": "ADAPTER_FAIL_OPEN",
            "reason": reason,
            "passthrough_allowed": True,
            "zdg": {
                "transport_status": None,
                "tool_family": None,
                "action": None,
            },
        }

    def _resolve_mapping(self, tool_name: str) -> ToolMapping | None:
        for mapping in self.tool_map:
            if mapping.name.endswith("*"):
                if tool_name.startswith(mapping.name[:-1]):
                    return mapping
                continue
            if mapping.name == tool_name:
                return mapping
        return None

    def _build_args(
        self,
        mapping: ToolMapping,
        tool_input: dict[str, Any],
        tool_name: str,
    ) -> dict[str, Any]:
        if mapping.args_passthrough:
            args = dict(tool_input)
            args.setdefault("openclaw_tool_name", tool_name)
            return args

        args: dict[str, Any] = {}
        for target_key, spec in mapping.args_map.items():
            found, value = _resolve_value(tool_input, spec)
            if found:
                args[target_key] = value
        return args


def load_tool_map(path: str | Path) -> tuple[str, tuple[ToolMapping, ...]]:
    """Load and validate the OpenClaw tool map from YAML."""

    source = Path(path)
    loaded = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    openclaw_version = str(loaded.get("openclaw_version") or SUPPORTED_OPENCLAW_VERSION)
    raw_map = loaded.get("openclaw_tool_map") or {}

    mappings: list[ToolMapping] = []
    for name, config in raw_map.items():
        mappings.append(
            ToolMapping(
                name=str(name),
                tool_family=str(config["tool_family"]),
                action=str(config["action"]),
                args_map=dict(config.get("args_map") or {}),
                args_passthrough=bool(config.get("args_passthrough", False)),
            )
        )
    return openclaw_version, tuple(mappings)


def _resolve_value(tool_input: dict[str, Any], spec: Any) -> tuple[bool, Any]:
    if isinstance(spec, str):
        if spec in tool_input:
            return True, tool_input[spec]
        return False, None

    if isinstance(spec, dict):
        if "const" in spec:
            return True, spec["const"]
        if "source" in spec:
            source = str(spec["source"])
            if source in tool_input:
                return True, tool_input[source]
            return False, None
        if "sources" in spec:
            for source in spec["sources"]:
                key = str(source)
                if key in tool_input:
                    return True, tool_input[key]
            return False, None

    return False, None
