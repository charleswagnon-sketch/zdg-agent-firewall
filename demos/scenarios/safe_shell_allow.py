"""Demo scenario: safe shell allow."""

from __future__ import annotations

import uuid
from typing import Any

import httpx



def run(client: httpx.Client, admin_token: str | None = None) -> dict[str, Any]:
    agent_id = f"demo-shell-{uuid.uuid4().hex[:8]}"
    response = client.post(
        "/v1/action",
        json={
            "agent_id": agent_id,
            "tool_family": "shell",
            "action": "execute",
            "args": {"command": "echo safe"},
        },
    )
    body = response.json()
    passed = response.status_code == 200 and body.get("decision") == "ALLOW"
    return {
        "name": "safe-shell-allow",
        "passed": passed,
        "status_code": response.status_code,
        "decision": body.get("decision"),
        "attempt_id": body.get("attempt_id"),
    }
