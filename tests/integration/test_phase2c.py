"""Phase 2C integration tests for gated real execution."""

from __future__ import annotations

from pathlib import Path

from sqlmodel import Session, select

from db.models import AuditEvent, ExecutionResult, ToolAttempt
from db.sqlite import get_engine


def _authority_payload(*, agent_id: str, tool_family: str, action: str, session_id: str | None = None) -> dict:
    authority_scope = {
        "tool_family": tool_family,
        "action": action,
    }
    if session_id is not None:
        authority_scope["session_id"] = session_id
    return {
        "actor_identity": {
            "actor_id": "ops@example.com",
            "actor_type": "human",
            "tenant_id": "tenant-integration",
            "role_bindings": ["operator"],
        },
        "delegation_chain": {
            "delegation_chain_id": f"dlg_{agent_id}_{tool_family}_{action}",
            "root_actor_id": "ops@example.com",
            "delegated_agent_ids": [agent_id],
            "authority_scope": authority_scope,
            "delegation_reason": "integration_test",
        },
    }


def test_real_filesystem_write_executes_within_allowed_root(make_client, tmp_path):
    workspace = tmp_path / "workspace"
    target = workspace / "note.txt"

    with make_client(zdg_real_exec_filesystem=True) as client:
        response = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-fs-write",
                "tool_family": "filesystem",
                "action": "write",
                "idempotency_key": "fs-write-1",
                "args": {
                    "operation": "write",
                    "path": str(target),
                    "content": "hello from zdg",
                },
                **_authority_payload(agent_id="agent-fs-write", tool_family="filesystem", action="write"),
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["decision"] == "ALLOW"
        assert target.read_text(encoding="utf-8") == "hello from zdg"

        with Session(get_engine()) as session:
            result = session.exec(
                select(ExecutionResult).where(ExecutionResult.attempt_id == body["attempt_id"])
            ).first()
            assert result is not None
            assert result.executed is True
            assert result.execution_status == "success"

            events = session.exec(
                select(AuditEvent).where(AuditEvent.related_attempt_id == body["attempt_id"])
            ).all()
            event_types = {event.event_type for event in events}
            assert "ACTION_ALLOWED" in event_types
            assert "EXECUTION_COMPLETED" in event_types


def test_real_mutating_execution_requires_idempotency_key(make_client, tmp_path):
    workspace = tmp_path / "workspace"
    target = workspace / "missing-idem.txt"

    with make_client(zdg_real_exec_filesystem=True) as client:
        response = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-fs-no-idem",
                "tool_family": "filesystem",
                "action": "write",
                "args": {
                    "operation": "write",
                    "path": str(target),
                    "content": "should not write",
                },
            },
        )

        assert response.status_code == 400
        assert response.json()["detail"]["reason_code"] == "IDEMPOTENCY_KEY_REQUIRED"
        assert not target.exists()

        with Session(get_engine()) as session:
            assert session.exec(select(ToolAttempt)).all() == []


def test_real_messaging_writes_maildir_message(make_client, tmp_path):
    maildir = tmp_path / "maildir"

    with make_client(
        zdg_real_exec_messaging=True,
        zdg_maildir_path=str(maildir),
    ) as client:
        response = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-maildir",
                "tool_family": "messaging",
                "action": "send",
                "idempotency_key": "msg-send-1",
                "args": {
                    "to": ["user@internal.example.com"],
                    "subject": "Maildir test",
                    "body": "hello from the firewall",
                },
                **_authority_payload(agent_id="agent-maildir", tool_family="messaging", action="send"),
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["decision"] == "ALLOW"

        delivered = list((maildir / "new").glob("*.eml"))
        assert len(delivered) == 1
        message_text = delivered[0].read_text(encoding="utf-8")
        assert "Subject: Maildir test" in message_text
        assert "hello from the firewall" in message_text
        assert "X-ZDG-Trace-Id:" in message_text

        with Session(get_engine()) as session:
            result = session.exec(
                select(ExecutionResult).where(ExecutionResult.attempt_id == body["attempt_id"])
            ).first()
            assert result is not None
            assert result.executed is True
            assert result.execution_status == "success"


def test_filesystem_real_exec_blocks_symlink_escape(make_client, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside secret", encoding="utf-8")
    symlink_path = workspace / "linked.txt"
    symlink_path.symlink_to(outside)

    with make_client(zdg_real_exec_filesystem=True) as client:
        response = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-fs-symlink",
                "tool_family": "filesystem",
                "action": "read",
                "args": {
                    "operation": "read",
                    "path": str(symlink_path),
                },
                **_authority_payload(agent_id="agent-fs-symlink", tool_family="filesystem", action="read"),
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["decision"] == "BLOCK"
        assert body["reason_code"] == "WRAPPER_BLOCKED"

        with Session(get_engine()) as session:
            result = session.exec(
                select(ExecutionResult).where(ExecutionResult.attempt_id == body["attempt_id"])
            ).first()
            assert result is not None
            assert result.executed is False
            assert result.execution_status == "blocked"

            events = session.exec(
                select(AuditEvent).where(AuditEvent.related_attempt_id == body["attempt_id"])
            ).all()
            event_types = {event.event_type for event in events}
            assert "ACTION_BLOCKED" in event_types
            assert "EXECUTION_FAILED" in event_types
