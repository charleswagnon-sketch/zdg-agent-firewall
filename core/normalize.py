"""
core/normalize.py - Canonical payload normalization.

All incoming tool requests are normalized before hashing, risk scoring,
or policy evaluation. Identical semantically equivalent requests must
always produce the same payload_hash regardless of serialization order.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.parse
from typing import Any

from core.modes import DANGEROUS_FAMILIES, NormalizationStatus
from core.schemas import NormalizationStep, NormalizationTrace


_PATH_FIELDS: dict[str, set[str]] = {
    "filesystem": {"path", "src", "dst", "destination", "working_dir"},
    "shell": {"working_dir", "cwd"},
}

_URL_FIELDS: dict[str, set[str]] = {
    "http": {"url", "endpoint", "destination", "target"},
}

_RECIPIENT_FIELDS: set[str] = {"to", "cc", "bcc", "recipients"}

_DATETIME_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")


class NormalizationError(Exception):
    """Raised when a payload cannot be reduced to a valid canonical form."""

    def __init__(self, field: str, detail: str) -> None:
        self.field = field
        self.detail = detail
        super().__init__(f"Normalization failed on field '{field}': {detail}")


def canonical_json(obj: Any) -> str:
    """Serialize to canonical JSON: sorted keys, no whitespace, ASCII-safe."""

    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def payload_hash(normalized: dict[str, Any]) -> str:
    """SHA256 digest of the canonical JSON representation."""

    digest = hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def normalize(
    tool_family: str,
    action: str,
    args: dict[str, Any] | None,
) -> tuple[dict[str, Any], str, NormalizationStatus, str | None]:
    """Backward-compatible normalization API used by the existing route code."""

    trace = normalize_with_trace(tool_family=tool_family, action=action, args=args)
    return (
        trace.normalized_payload,
        trace.payload_hash,
        trace.status,
        trace.failure_reason,
    )


def normalize_with_trace(
    tool_family: str,
    action: str,
    args: dict[str, Any] | None,
) -> NormalizationTrace:
    """Return the normalized payload plus step-by-step trace metadata."""

    steps: list[NormalizationStep] = []

    try:
        if not isinstance(args, dict):
            raise NormalizationError("args", "Args payload must be a JSON object.")

        raw: dict[str, Any] = {
            "action": action,
            "args": dict(args),
            "tool_family": tool_family,
        }
        current = dict(raw)

        trimmed = _trim_strings_deep(current)
        steps.append(_step("trim_strings", current, trimmed, "Trim leading and trailing whitespace from strings."))

        stripped = _strip_nulls_deep(trimmed)
        steps.append(_step("strip_empty_values", trimmed, stripped, "Remove null, empty string, empty list, and empty dict fields."))

        family_normalized = dict(stripped)
        if isinstance(family_normalized.get("args"), dict):
            family_normalized["args"] = _normalize_args(family_normalized["args"], tool_family)
        steps.append(_step("normalize_family_fields", stripped, family_normalized, "Normalize paths, URLs, recipients, and datetime-like strings."))

        sorted_payload = _sort_keys_deep(family_normalized)
        steps.append(_step("sort_keys", family_normalized, sorted_payload, "Sort dictionary keys lexicographically at every nesting level."))

        canon = canonical_json(sorted_payload)
        return NormalizationTrace(
            normalized_payload=sorted_payload,
            payload_hash=payload_hash(sorted_payload),
            status=NormalizationStatus.COMPLETE,
            failure_reason=None,
            canonical_json=canon,
            steps=steps,
        )

    except NormalizationError as exc:
        steps.append(
            NormalizationStep(
                step="normalization_error",
                applied=True,
                detail=f"Normalization failed on field '{exc.field}': {exc.detail}",
            )
        )
        if tool_family in DANGEROUS_FAMILIES:
            blocked_payload: dict[str, Any] = {}
            return NormalizationTrace(
                normalized_payload=blocked_payload,
                payload_hash="sha256:" + "0" * 64,
                status=NormalizationStatus.FAILED,
                failure_reason=exc.detail,
                canonical_json=canonical_json(blocked_payload),
                steps=steps,
            )
        partial = {"action": action, "tool_family": tool_family, "args": {}}
        return NormalizationTrace(
            normalized_payload=partial,
            payload_hash=payload_hash(partial),
            status=NormalizationStatus.PARTIAL,
            failure_reason=exc.detail,
            canonical_json=canonical_json(partial),
            steps=steps,
        )
    except Exception as exc:  # noqa: BLE001
        reason = f"Unexpected normalization error: {exc}"
        steps.append(
            NormalizationStep(
                step="unexpected_error",
                applied=True,
                detail=reason,
            )
        )
        if tool_family in DANGEROUS_FAMILIES:
            blocked_payload = {}
            return NormalizationTrace(
                normalized_payload=blocked_payload,
                payload_hash="sha256:" + "0" * 64,
                status=NormalizationStatus.FAILED,
                failure_reason=reason,
                canonical_json=canonical_json(blocked_payload),
                steps=steps,
            )
        partial = {"action": action, "tool_family": tool_family, "args": {}}
        return NormalizationTrace(
            normalized_payload=partial,
            payload_hash=payload_hash(partial),
            status=NormalizationStatus.PARTIAL,
            failure_reason=reason,
            canonical_json=canonical_json(partial),
            steps=steps,
        )


def _step(name: str, before: Any, after: Any, detail: str) -> NormalizationStep:
    return NormalizationStep(
        step=name,
        applied=canonical_json(before) != canonical_json(after),
        detail=detail,
    )


def _sort_keys_deep(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _sort_keys_deep(obj[k]) for k in sorted(obj)}
    if isinstance(obj, list):
        return [_sort_keys_deep(item) for item in obj]
    return obj


def _strip_nulls_deep(obj: Any) -> Any:
    if isinstance(obj, dict):
        cleaned = {}
        for key, value in obj.items():
            value = _strip_nulls_deep(value)
            if value is None or value == "" or value == [] or value == {}:
                continue
            cleaned[key] = value
        return cleaned
    if isinstance(obj, list):
        return [_strip_nulls_deep(item) for item in obj if item is not None]
    return obj


def _trim_strings_deep(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {key: _trim_strings_deep(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_trim_strings_deep(item) for item in obj]
    if isinstance(obj, str):
        return obj.strip()
    return obj


def _normalize_args(args: dict[str, Any], tool_family: str) -> dict[str, Any]:
    result = dict(args)
    path_fields = _PATH_FIELDS.get(tool_family, set())
    url_fields = _URL_FIELDS.get(tool_family, set())

    for field, value in result.items():
        if field in _RECIPIENT_FIELDS and isinstance(value, list):
            result[field] = sorted(str(recipient).strip().lower() for recipient in value)
            continue

        if not isinstance(value, str):
            continue

        if field in path_fields:
            result[field] = _normalize_path(value)
            continue

        if field in url_fields:
            result[field] = _normalize_url(value)
            continue

        if _DATETIME_PATTERN.match(value):
            result[field] = _normalize_datetime(value)

    return result


def _normalize_path(path: str) -> str:
    expanded = os.path.expanduser(path.strip())
    return os.path.normpath(expanded)


def _normalize_url(url: str) -> str:
    url = url.strip()
    try:
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        query_params = urllib.parse.parse_qsl(parsed.query)
        query_sorted = urllib.parse.urlencode(sorted(query_params))
        return urllib.parse.urlunparse((scheme, netloc, path, "", query_sorted, ""))
    except Exception:  # noqa: BLE001
        return url.lower()


def _normalize_datetime(value: str) -> str:
    from datetime import datetime, timezone

    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        except ValueError:
            continue
    return value