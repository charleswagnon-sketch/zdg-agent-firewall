"""Unit tests for the OpenClaw translator."""

from __future__ import annotations

from pathlib import Path

from adapters.openclaw.config import SUPPORTED_OPENCLAW_VERSION
from adapters.openclaw.translator import OpenClawTranslator, load_tool_map


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TOOL_MAP_PATH = PROJECT_ROOT / "adapters" / "openclaw" / "tool_map.yaml"


def _translator(agent_id_field: str = "assistant_id") -> OpenClawTranslator:
    return OpenClawTranslator(tool_map_path=TOOL_MAP_PATH, agent_id_field=agent_id_field)


def test_tool_map_version_is_pinned():
    version, tool_map = load_tool_map(TOOL_MAP_PATH)

    assert version == SUPPORTED_OPENCLAW_VERSION
    assert any(mapping.name == "bash" for mapping in tool_map)
def test_bash_translation_is_deterministic():
    translator = _translator()
    tool_call = {
        "tool_name": "bash",
        "tool_use_id": "toolu_bash_001",
        "conversation_id": "conv-123",
        "assistant_id": "assistant-123",
        "model": "openclaw-test",
        "tool_input": {
            "command": "ls -la ~/workspace",
            "working_dir": "~/workspace",
            "restart": False,
        },
    }

    first = translator.translate_tool_call(tool_call)
    second = translator.translate_tool_call(tool_call)

    assert first.blocked_response is None
    assert second.blocked_response is None
    assert first.action_request is not None
    assert first.action_request.model_dump() == second.action_request.model_dump()
    assert first.action_request.idempotency_key == "toolu_bash_001"
    assert first.action_request.session_id == "conv-123"
    assert first.action_request.agent_id == "assistant-123"
    assert first.action_request.runtime == "openclaw"
    assert first.action_request.tool_family == "shell"
    assert first.action_request.action == "execute"
    assert first.action_request.args == {
        "command": "ls -la ~/workspace",
        "cwd": "~/workspace",
    }
    assert first.action_request.metadata["openclaw"]["tool_name"] == "bash"


def test_text_editor_write_maps_action_and_operation():
    translator = _translator()
    tool_call = {
        "tool_name": "text_editor.write",
        "tool_use_id": "toolu_write_001",
        "conversation_id": "conv-write",
        "assistant_id": "assistant-write",
        "tool_input": {
            "path": "/tmp/note.txt",
            "content": "hello world",
        },
    }

    translated = translator.translate_tool_call(tool_call)

    assert translated.blocked_response is None
    assert translated.action_request is not None
    assert translated.action_request.tool_family == "filesystem"
    assert translated.action_request.action == "write"
    assert translated.action_request.args["path"] == "/tmp/note.txt"
    assert translated.action_request.args["content"] == "hello world"
    assert translated.action_request.args["operation"] == "write"
def test_mcp_tool_passthrough_keeps_payload_and_marks_tool_name():
    translator = _translator()
    tool_call = {
        "tool_name": "mcp__internal_search",
        "assistant_id": "assistant-http",
        "tool_input": {
            "method": "GET",
            "url": "http://localhost/search?q=zdg",
        },
    }

    translated = translator.translate_tool_call(tool_call)

    assert translated.blocked_response is None
    assert translated.action_request is not None
    assert translated.action_request.tool_family == "http"
    assert translated.action_request.action == "request"
    assert translated.action_request.args["method"] == "GET"
    assert translated.action_request.args["url"] == "http://localhost/search?q=zdg"
    assert translated.action_request.args["openclaw_tool_name"] == "mcp__internal_search"


def test_unsupported_tool_fails_closed_without_action_request():
    translator = _translator()
    tool_call = {
        "tool_name": "computer.click",
        "tool_use_id": "toolu_gui_001",
        "assistant_id": "assistant-gui",
        "tool_input": {"x": 10, "y": 10},
    }

    translated = translator.translate_tool_call(tool_call)

    assert translated.action_request is None
    assert translated.blocked_response is not None
    assert translated.blocked_response["decision"] == "BLOCK"
    assert translated.blocked_response["reason_code"] == "DEFAULT_DENY"


def test_configured_agent_id_field_is_respected():
    translator = _translator(agent_id_field="worker_id")
    tool_call = {
        "tool_name": "bash",
        "conversation_id": "conv-custom-agent",
        "assistant_id": "assistant-fallback",
        "worker_id": "worker-77",
        "tool_input": {"command": "pwd"},
    }

    translated = translator.translate_tool_call(tool_call)

    assert translated.action_request is not None
    assert translated.action_request.agent_id == "worker-77"
    assert translated.action_request.metadata["openclaw"]["agent_id_source"] == "worker_id"
