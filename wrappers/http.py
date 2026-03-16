"""wrappers/http.py - Governed HTTP/API request wrapper."""

from __future__ import annotations

import ipaddress
import re
import socket
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import httpx

from wrappers.base import BaseWrapper, WrapperResult


@dataclass
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    payload_size_bytes: int = 0


_RAW_IP_RE = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}(:\d+)?(/|$)")
_BLOCKED_HEADERS = {"host", "content-length", "connection", "transfer-encoding"}
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class HttpWrapper(BaseWrapper):
    """Governed wrapper for outbound HTTP requests."""

    tool_family = "http"

    def normalize(self, args: dict[str, Any]) -> HttpRequest:
        url = str(args.get("url", "")).strip()
        if not url:
            raise ValueError("HTTP wrapper requires a non-empty 'url'")
        method = str(args.get("method", "GET")).upper().strip()
        headers = {str(k): str(v) for k, v in (args.get("headers") or {}).items()}
        body = args.get("body") or args.get("payload")
        if body is not None:
            body = str(body)
        size = args.get("payload_size_bytes", 0)
        if body and not size:
            size = len(body.encode("utf-8"))
        return HttpRequest(
            method=method,
            url=url,
            headers=headers,
            body=body,
            payload_size_bytes=int(size) if size else 0,
        )

    def execute(self, request: HttpRequest) -> WrapperResult:
        if _RAW_IP_RE.match(request.url):
            return WrapperResult(
                executed=False,
                mock=False,
                output_summary="Wrapper blocked: raw IP destination not permitted",
                blocked_reason="RAW_IP_DESTINATION",
            )

        try:
            parsed = urllib.parse.urlparse(request.url)
            host = (parsed.hostname or "").lower()
        except Exception:
            host = "unknown"

        if not self.context.is_real_exec_enabled(self.tool_family):
            summary = f"[MOCK] Would send {request.method} to {host} ({request.payload_size_bytes} bytes)"
            return WrapperResult(
                executed=False,
                mock=True,
                output_summary=summary,
                raw_output={
                    "method": request.method,
                    "url": request.url,
                    "status_code": 200,
                    "mock": True,
                    "response_preview": "[mock response]",
                },
            )

        validation_error = _validate_http_url(request.url, tuple(self.context.approved_domains))
        if validation_error:
            return WrapperResult(
                executed=False,
                mock=False,
                output_summary=f"Wrapper blocked: {validation_error}",
                blocked_reason=validation_error,
            )

        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in _BLOCKED_HEADERS
        }

        current_url = request.url
        current_method = request.method
        current_body = request.body
        redirect_count = 0

        try:
            with httpx.Client(
                timeout=self.context.http_timeout_seconds,
                trust_env=False,
                follow_redirects=False,
            ) as client:
                while True:
                    with client.stream(
                        current_method,
                        current_url,
                        headers=headers,
                        content=(current_body.encode("utf-8") if current_body is not None else None),
                    ) as response:
                        if response.status_code in _REDIRECT_STATUSES:
                            if redirect_count >= self.context.http_max_redirects:
                                reason = f"HTTP redirect limit exceeded ({self.context.http_max_redirects})"
                                return WrapperResult(
                                    executed=False,
                                    mock=False,
                                    output_summary=f"Wrapper blocked: {reason}",
                                    blocked_reason=reason,
                                )
                            location = response.headers.get("location")
                            if not location:
                                reason = "HTTP redirect response missing Location header"
                                return WrapperResult(
                                    executed=False,
                                    mock=False,
                                    output_summary=f"Wrapper blocked: {reason}",
                                    blocked_reason=reason,
                                )
                            next_url = urllib.parse.urljoin(current_url, location)
                            validation_error = _validate_http_url(next_url, tuple(self.context.approved_domains))
                            if validation_error:
                                return WrapperResult(
                                    executed=False,
                                    mock=False,
                                    output_summary=f"Wrapper blocked: {validation_error}",
                                    blocked_reason=validation_error,
                                )
                            redirect_count += 1
                            current_url = next_url
                            if response.status_code == 303 or (
                                response.status_code in {301, 302} and current_method not in {"GET", "HEAD"}
                            ):
                                current_method = "GET"
                                current_body = None
                            continue

                        body_bytes, truncated = _read_capped_body(
                            response,
                            self.context.http_max_response_bytes,
                        )
                        preview = body_bytes.decode("utf-8", errors="replace")
                        summary = (
                            f"Executed HTTP {current_method} to {urllib.parse.urlparse(current_url).hostname or 'unknown'} "
                            f"(status={response.status_code})"
                        )
                        return WrapperResult(
                            executed=True,
                            mock=False,
                            output_summary=summary,
                            raw_output={
                                "method": current_method,
                                "url": current_url,
                                "status_code": response.status_code,
                                "redirect_count": redirect_count,
                                "response_bytes": len(body_bytes),
                                "response_truncated": truncated,
                                "response_preview": preview[:512],
                            },
                        )
        except httpx.HTTPError as exc:
            reason = f"HTTP execution failed: {exc}"
            return WrapperResult(
                executed=False,
                mock=False,
                output_summary=f"Wrapper blocked: {reason}",
                blocked_reason=reason,
            )


def _read_capped_body(response: httpx.Response, max_bytes: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    truncated = False
    for chunk in response.iter_bytes():
        if total + len(chunk) > max_bytes:
            remaining = max_bytes - total
            if remaining > 0:
                chunks.append(chunk[:remaining])
                total += remaining
            truncated = True
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks), truncated


def _validate_http_url(url: str, approved_domains: tuple[str, ...]) -> str | None:
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as exc:  # noqa: BLE001
        return f"HTTP URL could not be parsed: {exc}"

    if parsed.scheme not in {"http", "https"}:
        return f"HTTP wrapper only permits http/https URLs, not '{parsed.scheme or 'unknown'}'"

    host = (parsed.hostname or "").lower()
    if not host:
        return "HTTP URL is missing a hostname"

    try:
        ipaddress.ip_address(host)
        return "RAW_IP_DESTINATION"
    except ValueError:
        pass

    if _host_matches_approved(host, approved_domains):
        return None

    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return f"HTTP destination resolution failed: {exc}"

    for info in infos:
        try:
            resolved_ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (
            resolved_ip.is_private
            or resolved_ip.is_loopback
            or resolved_ip.is_link_local
            or resolved_ip.is_reserved
            or resolved_ip.is_multicast
            or resolved_ip.is_unspecified
        ):
            return f"HTTP destination resolves to a non-public address: {resolved_ip}"

    return None


def _host_matches_approved(host: str, approved_domains: tuple[str, ...]) -> bool:
    for domain in approved_domains:
        normalized = domain.lower()
        if host == normalized or host.endswith("." + normalized):
            return True
    return False