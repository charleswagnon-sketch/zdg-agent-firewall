"""Demo scenario: export and verify a session audit chain."""

from __future__ import annotations

import uuid
from typing import Any

import httpx



def run(client: httpx.Client, admin_token: str | None = None) -> dict[str, Any]:
    if not admin_token:
        raise ValueError("audit-export-verify scenario requires an admin token.")

    agent_id = f"demo-audit-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/v1/sessions",
        headers={"X-ZDG-Admin-Token": admin_token},
        json={
            "agent_id": agent_id,
            "metadata": {"scenario": "audit-export-verify"},
            "operator": "ops@example.com",
        },
    )
    created_body = created.json()
    if created.status_code != 200:
        return {"name": "audit-export-verify", "passed": False, "status_code": created.status_code}

    session_id = created_body["session_id"]
    action = client.post(
        "/v1/action",
        json={
            "session_id": session_id,
            "agent_id": agent_id,
            "tool_family": "shell",
            "action": "execute",
            "args": {"command": "echo safe"},
        },
    )
    export_response = client.get(
        f"/v1/audit/export?chain_id=session:{session_id}&format=json",
        headers={"X-ZDG-Admin-Token": admin_token},
    )
    export_body = export_response.json()
    verify_response = client.post(
        "/v1/audit/verify",
        headers={"X-ZDG-Admin-Token": admin_token},
        json=export_body,
    )
    verify_body = verify_response.json()

    passed = (
        action.status_code == 200
        and export_response.status_code == 200
        and verify_response.status_code == 200
        and verify_body.get("ok") is True
    )
    return {
        "name": "audit-export-verify",
        "passed": passed,
        "chain_id": export_body.get("chain_id"),
        "event_count": export_body.get("event_count"),
        "verified": verify_body.get("ok"),
    }
