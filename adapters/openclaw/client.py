"""HTTP client for delegating governed OpenClaw calls to ZDG."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
from pydantic import ValidationError

from core.schemas import ActionRequest, ActionResponse


class ZDGClientError(Exception):
    """Base error for adapter-to-ZDG communication failures."""


class ZDGClientTimeout(ZDGClientError):
    """Raised when the ZDG API times out."""


class ZDGClientConnectionError(ZDGClientError):
    """Raised when the ZDG API cannot be reached."""


class ZDGClientProtocolError(ZDGClientError):
    """Raised when the ZDG API returns malformed payloads."""


@dataclass(frozen=True)
class ZDGClientHTTPError(ZDGClientError):
    """Raised when the ZDG API returns a non-success HTTP response."""

    status_code: int
    reason_code: str
    reason: str

    def __str__(self) -> str:
        return f"ZDG returned HTTP {self.status_code}: {self.reason_code} ({self.reason})"


class ZDGClient:
    """Small HTTP client for the governed /v1/action boundary."""

    def __init__(
        self,
        base_url: str,
        timeout: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.transport = transport

    def submit_action(self, action_request: ActionRequest | dict[str, Any]) -> ActionResponse:
        """Send a translated action request to ZDG and parse the response."""

        payload = action_request
        if isinstance(action_request, ActionRequest):
            payload = action_request.model_dump(mode="json", exclude_none=True)

        try:
            with httpx.Client(
                base_url=self.base_url,
                timeout=self.timeout,
                trust_env=False,
                transport=self.transport,
            ) as client:
                response = client.post("/v1/action", json=payload)
        except httpx.TimeoutException as exc:
            raise ZDGClientTimeout(f"Timed out calling ZDG at {self.base_url}") from exc
        except httpx.HTTPError as exc:
            raise ZDGClientConnectionError(f"Could not reach ZDG at {self.base_url}: {exc}") from exc

        data = _parse_json(response)
        if response.status_code >= 400:
            detail = data.get("detail") if isinstance(data, dict) else None
            if isinstance(detail, dict):
                reason_code = str(detail.get("reason_code") or f"HTTP_{response.status_code}")
                reason = str(detail.get("reason") or "ZDG rejected the request.")
            else:
                reason_code = f"HTTP_{response.status_code}"
                reason = response.text or "ZDG rejected the request."
            raise ZDGClientHTTPError(
                status_code=response.status_code,
                reason_code=reason_code,
                reason=reason,
            )

        try:
            return ActionResponse.model_validate(data)
        except ValidationError as exc:
            raise ZDGClientProtocolError(f"ZDG returned an invalid ActionResponse: {exc}") from exc


def _parse_json(response: httpx.Response) -> dict[str, Any]:
    try:
        data = response.json()
    except ValueError as exc:
        raise ZDGClientProtocolError(f"ZDG returned non-JSON content: {exc}") from exc
    if not isinstance(data, dict):
        raise ZDGClientProtocolError("ZDG returned a non-object JSON payload.")
    return data
