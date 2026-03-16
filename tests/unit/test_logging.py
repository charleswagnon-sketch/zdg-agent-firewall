"""Unit tests for structured logging helpers."""

from __future__ import annotations

import json
import logging



def test_json_formatter_summarizes_sensitive_fields_with_diagnostic_context():
    from core.logging import JsonFormatter

    record = logging.LogRecord(
        name="zdg",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="decision",
        args=(),
        exc_info=None,
    )
    record.command = "rm -rf /tmp/build-cache"
    record.headers = {"Authorization": "Bearer secret", "Content-Type": "application/json"}
    record.to = ["alice@example.com", "bob@internal.example.com"]
    record.operator = "ops@example.com"
    record.decision = "BLOCK"
    record.reason_code = "RISK_THRESHOLD_BLOCK"

    formatted = JsonFormatter().format(record)
    payload = json.loads(formatted)

    assert payload["message"] == "decision"
    assert payload["decision"] == "BLOCK"
    assert payload["reason_code"] == "RISK_THRESHOLD_BLOCK"
    assert payload["command"] == {
        "preview": "rm -rf /tmp/build-cache",
        "chars": len("rm -rf /tmp/build-cache"),
    }
    assert payload["headers"] == {"keys": ["Authorization", "Content-Type"]}
    assert payload["to"] == {
        "count": 2,
        "domains": ["example.com", "internal.example.com"],
    }
    assert payload["operator"] == "[redacted]"