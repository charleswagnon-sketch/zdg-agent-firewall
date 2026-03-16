"""Unit tests for the OpenClaw adapter middleware."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import httpx

from adapters.openclaw.client import ZDGClient
from adapters.openclaw.config import OpenClawSettings
from adapters.openclaw.middleware import OpenClawMiddleware
from adapters.openclaw.translator import OpenClawTranslator
from core.modes import Decision, ReasonCode
from core.schemas import ActionResponse, ExecutionOutcome


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TOOL_MAP_PATH = PROJECT_ROOT / "adapters" / "openclaw" / "tool_map.yaml"


def _settings(fail_mode: str = "closed") -> OpenClawSettings:
    return OpenClawSettings(
        openclaw_tool_map_path=str(TOOL_MAP_PATH),
        openclaw_zdg_base_url="http://zdg.test",
        openclaw_zdg_timeout=1.0,
        openclaw_fail_mode=fail_mode,
    )


def _translator() -> OpenClawTranslator:
    return OpenClawTranslator(tool_map_path=TOOL_MAP_PATH)


def _tool_call(tool_name: str = "bash") -> dict:
    return {
        "tool_name": tool_name,
        "tool_use_id": "toolu_123",
        "conversation_id": "conv-123",
        "assistant_id": "assistant-123",
        "model": "openclaw-test",
        "tool_input": {"command": "ls -la ~/workspace"},
    }


def _action_response(decision: Decision = Decision.ALLOW, reason_code: ReasonCode = ReasonCode.ALLOW) -> ActionResponse:
    return ActionResponse(
        trace_id="zdg_trace_1",
        attempt_id="atm_123",
        decision_id="dec_123",
        session_id="conv-123",
        agent_id="assistant-123",
        tool_family="shell",
        action="execute",
        decision=decision,
        reason_code=reason_code,
        reason="test reason",
        risk_score=0,
        triggered_rules=[],
        payload_hash="sha256:" + "a" * 64,
        policy_bundle_id="local-default-v1",
        policy_bundle_version="1.0.0",
        ruleset_hash="sha256:" + "b" * 64,
        execution=ExecutionOutcome(
            executed=False,
            mock=True,
            execution_status="mock_success",
            output_summary="[MOCK] Would execute",
            raw_output={"exit_code": 0, "stdout": "[mock output]"},
        ),
        timestamp=datetime(2026, 3, 9, 12, 0, 0),
    )


def _transport_for_json(payload: dict, status_code: int = 200) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=payload)

    return httpx.MockTransport(handler)
def test_allow_response_translates_to_completed_result():
    response = _action_response()
    middleware = OpenClawMiddleware(
        settings=_settings(),
        translator=_translator(),
        zdg_client=ZDGClient(
            base_url="http://zdg.test",
            transport=_transport_for_json(response.model_dump(mode="json")),
        ),
    )

    result = middleware.process_tool_call(_tool_call())

    assert result["status"] == "completed"
    assert result["decision"] == "ALLOW"
    assert result["result"]["mock"] is True
    assert result["zdg"]["attempt_id"] == "atm_123"


def test_block_response_translates_to_structured_denial():
    response = _action_response(decision=Decision.BLOCK, reason_code=ReasonCode.RISK_THRESHOLD_BLOCK)
    middleware = OpenClawMiddleware(
        settings=_settings(),
        translator=_translator(),
        zdg_client=ZDGClient(
            base_url="http://zdg.test",
            transport=_transport_for_json(response.model_dump(mode="json")),
        ),
    )

    result = middleware.process_tool_call(_tool_call())

    assert result["status"] == "blocked"
    assert result["decision"] == "BLOCK"
    assert result["error"]["reason_code"] == "RISK_THRESHOLD_BLOCK"


def test_approval_required_translates_to_hold_response():
    response = _action_response(decision=Decision.APPROVAL_REQUIRED, reason_code=ReasonCode.APPROVAL_REQUIRED_THRESHOLD)
    response.approval_id = "apv_123"
    middleware = OpenClawMiddleware(
        settings=_settings(),
        translator=_translator(),
        zdg_client=ZDGClient(
            base_url="http://zdg.test",
            transport=_transport_for_json(response.model_dump(mode="json")),
        ),
    )

    result = middleware.process_tool_call(_tool_call())

    assert result["status"] == "approval_required"
    assert result["decision"] == "APPROVAL_REQUIRED"
    assert result["approval"]["approval_id"] == "apv_123"


def test_timeout_in_closed_mode_fails_closed():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out")

    middleware = OpenClawMiddleware(
        settings=_settings(fail_mode="closed"),
        translator=_translator(),
        zdg_client=ZDGClient(
            base_url="http://zdg.test",
            transport=httpx.MockTransport(handler),
        ),
    )

    result = middleware.process_tool_call(_tool_call())

    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "ZDG_UNREACHABLE"
def test_timeout_in_open_mode_returns_passthrough_marker():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out")

    middleware = OpenClawMiddleware(
        settings=_settings(fail_mode="open"),
        translator=_translator(),
        zdg_client=ZDGClient(
            base_url="http://zdg.test",
            transport=httpx.MockTransport(handler),
        ),
    )

    result = middleware.process_tool_call(_tool_call())

    assert result["status"] == "passthrough"
    assert result["reason_code"] == "ADAPTER_FAIL_OPEN"
    assert result["passthrough_allowed"] is True


def test_malformed_zdg_response_fails_closed():
    middleware = OpenClawMiddleware(
        settings=_settings(),
        translator=_translator(),
        zdg_client=ZDGClient(
            base_url="http://zdg.test",
            transport=_transport_for_json({"not": "an action response"}),
        ),
    )

    result = middleware.process_tool_call(_tool_call())

    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "MALFORMED_ZDG_RESPONSE"


def test_unsupported_tool_short_circuits_without_calling_zdg():
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, json=_action_response().model_dump(mode="json"))

    middleware = OpenClawMiddleware(
        settings=_settings(),
        translator=_translator(),
        zdg_client=ZDGClient(
            base_url="http://zdg.test",
            transport=httpx.MockTransport(handler),
        ),
    )

    result = middleware.process_tool_call(
        {
            "tool_name": "computer.click",
            "assistant_id": "assistant-gui",
            "tool_input": {"x": 1, "y": 2},
        }
    )

    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "DEFAULT_DENY"
    assert call_count == 0
