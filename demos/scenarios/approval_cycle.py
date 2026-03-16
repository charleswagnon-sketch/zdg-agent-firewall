"""Demo scenario: approval lifecycle and one-time consumption."""

from __future__ import annotations

import uuid
from typing import Any

import httpx



def run(client: httpx.Client, admin_token: str | None = None) -> dict[str, Any]:
    if not admin_token:
        raise ValueError("approval-cycle scenario requires an admin token.")

    agent_id = f"demo-approval-{uuid.uuid4().hex[:8]}"
    request_body = {
        "agent_id": agent_id,
        "tool_family": "messaging",
        "action": "send",
        "args": {
            "to": [f"user{i}@internal.example.com" for i in range(8)],
            "subject": "Demo approval cycle",
        },
    }

    initial = client.post("/v1/action", json=request_body)
    initial_body = initial.json()
    if initial.status_code != 200 or initial_body.get("decision") != "APPROVAL_REQUIRED":
        return {
            "name": "approval-cycle",
            "passed": False,
            "status_code": initial.status_code,
            "decision": initial_body.get("decision"),
        }

    approval_id = initial_body["approval_id"]
    resolved = client.post(
        f"/v1/approval/{approval_id}",
        headers={"X-ZDG-Admin-Token": admin_token},
        json={
            "approve": True,
            "operator": "ops@example.com",
            "payload_hash": initial_body["payload_hash"],
            "comment": "demo approved",
        },
    )
    resolved_body = resolved.json()
    approved = client.post("/v1/action", json={**request_body, "approval_id": approval_id})
    approved_body = approved.json()

    passed = (
        resolved.status_code == 200
        and resolved_body.get("status") == "approved"
        and approved.status_code == 200
        and approved_body.get("decision") == "ALLOW"
        and approved_body.get("approval_consumed") is True
    )
    return {
        "name": "approval-cycle",
        "passed": passed,
        "approval_id": approval_id,
        "resolved_status": resolved_body.get("status"),
        "decision": approved_body.get("decision"),
        "approval_consumed": approved_body.get("approval_consumed"),
    }
