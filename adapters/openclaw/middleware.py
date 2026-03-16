"""OpenClaw adapter orchestration layer."""

from __future__ import annotations

from typing import Any

import anyio

from adapters.openclaw.client import (
    ZDGClient,
    ZDGClientConnectionError,
    ZDGClientHTTPError,
    ZDGClientProtocolError,
    ZDGClientTimeout,
)
from adapters.openclaw.config import OpenClawSettings, get_openclaw_settings
from adapters.openclaw.translator import OpenClawTranslator


class OpenClawMiddleware:
    """Translate OpenClaw tool calls to ZDG and back again."""

    def __init__(
        self,
        settings: OpenClawSettings | None = None,
        translator: OpenClawTranslator | None = None,
        zdg_client: ZDGClient | None = None,
    ) -> None:
        self.settings = settings or get_openclaw_settings()
        self.translator = translator or OpenClawTranslator(
            tool_map_path=self.settings.tool_map_path_resolved,
            agent_id_field=self.settings.openclaw_agent_id_field,
        )
        self.zdg_client = zdg_client or ZDGClient(
            base_url=self.settings.openclaw_zdg_base_url,
            timeout=self.settings.openclaw_zdg_timeout,
        )

    def process_tool_call(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        """Govern a single OpenClaw tool call through the ZDG API."""

        translated = self.translator.translate_tool_call(tool_call)
        if translated.blocked_response is not None:
            return translated.blocked_response

        try:
            response = self.zdg_client.submit_action(translated.action_request)
        except ZDGClientHTTPError as exc:
            return self.translator.blocked_response(
                tool_call,
                reason_code=exc.reason_code,
                reason=exc.reason,
                http_status=exc.status_code,
            )
        except ZDGClientTimeout as exc:
            if self.settings.openclaw_fail_mode == "open":
                return self.translator.passthrough_response(tool_call, str(exc))
            return self.translator.blocked_response(
                tool_call,
                reason_code="ZDG_UNREACHABLE",
                reason=str(exc),
            )
        except ZDGClientConnectionError as exc:
            if self.settings.openclaw_fail_mode == "open":
                return self.translator.passthrough_response(tool_call, str(exc))
            return self.translator.blocked_response(
                tool_call,
                reason_code="ZDG_UNREACHABLE",
                reason=str(exc),
            )
        except ZDGClientProtocolError as exc:
            return self.translator.blocked_response(
                tool_call,
                reason_code="MALFORMED_ZDG_RESPONSE",
                reason=str(exc),
            )

        return self.translator.translate_action_response(tool_call, response)

    async def aprocess_tool_call(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        """Async wrapper for integrations that should not block an event loop."""

        return await anyio.to_thread.run_sync(self.process_tool_call, tool_call)
