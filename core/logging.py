"""core/logging.py - Structured, redacted logging helpers for ZDG."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

_RESERVED_KEYS = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "thread",
    "threadName",
}

_HARD_REDACT_KEYS = {
    "comment",
    "operator",
}

_TEXT_SUMMARY_KEYS = {
    "body",
    "command",
    "payload",
    "raw_output",
    "response_json",
    "stderr",
    "stdout",
    "subject",
}

_RECIPIENT_KEYS = {"to", "cc", "bcc"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in _RESERVED_KEYS or key.startswith("_"):
                continue
            payload[key] = _redact_value(key, value)
        return json.dumps(payload, sort_keys=True, default=str)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        extras: list[str] = []
        for key, value in record.__dict__.items():
            if key in _RESERVED_KEYS or key.startswith("_"):
                continue
            extras.append(f"{key}={_redact_value(key, value)!r}")
        suffix = " " + " ".join(extras) if extras else ""
        return f"[{record.levelname}] {record.getMessage()}{suffix}"


def configure_logging(log_format: str) -> logging.Logger:
    logger = logging.getLogger("zdg")
    logger.handlers.clear()
    handler = logging.StreamHandler()
    if log_format == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(TextFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


def log_request(logger: logging.Logger, **fields: Any) -> None:
    logger.info("request", extra=fields)


def log_decision(logger: logging.Logger, **fields: Any) -> None:
    logger.info("decision", extra=fields)


def log_execution(logger: logging.Logger, **fields: Any) -> None:
    logger.info("execution", extra=fields)


def log_policy_reload(logger: logging.Logger, **fields: Any) -> None:
    logger.info("policy_reload", extra=fields)


def _redact_value(key: str, value: Any) -> Any:
    if key in _HARD_REDACT_KEYS:
        return "[redacted]"
    if key == "args":
        return _summarize_args(value)
    if key == "headers":
        return _summarize_headers(value)
    if key in _RECIPIENT_KEYS:
        return _summarize_recipients(value)
    if key in _TEXT_SUMMARY_KEYS:
        return _summarize_text(value)
    if isinstance(value, dict):
        return {nested_key: _redact_value(nested_key, nested_value) for nested_key, nested_value in value.items()}
    if isinstance(value, list):
        return [_redact_value(key, item) for item in value]
    return value


def _summarize_args(value: Any) -> Any:
    if isinstance(value, dict):
        return {nested_key: _redact_value(nested_key, nested_value) for nested_key, nested_value in value.items()}
    return _summarize_text(value)


def _summarize_headers(value: Any) -> Any:
    if isinstance(value, dict):
        return {"keys": sorted(str(header) for header in value.keys())}
    return _summarize_text(value)


def _summarize_recipients(value: Any) -> Any:
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, (list, tuple, set)):
        items = [str(item) for item in value]
    else:
        return _summarize_text(value)

    domains = sorted(
        {
            address.split("@", 1)[1].lower()
            for address in items
            if "@" in address and address.split("@", 1)[1]
        }
    )
    return {
        "count": len(items),
        "domains": domains,
    }


def _summarize_text(value: Any, preview_chars: int = 40) -> Any:
    if value is None:
        return None
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, sort_keys=True, default=str)
        except TypeError:
            text = str(value)

    compact = " ".join(text.split())
    preview = compact[:preview_chars]
    if len(compact) > preview_chars:
        preview += "..."
    return {
        "preview": preview,
        "chars": len(compact),
    }