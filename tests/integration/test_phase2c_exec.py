"""Phase 2C integration tests for real shell and HTTP execution."""

from __future__ import annotations

import json
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

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


@contextmanager
def _local_http_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/ok":
                body = b"hello from local http"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/redirect-raw":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/ok")
                self.end_headers()
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://localhost:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_real_shell_exec_runs_inside_workspace(make_client, tmp_path):
    workspace = tmp_path / "workspace"
    target = workspace / "shell.txt"

    with make_client(zdg_real_exec_shell=True) as client:
        response = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-shell-real",
                "tool_family": "shell",
                "action": "execute",
                "idempotency_key": "shell-real-1",
                "args": {
                    "command": "python3 -c \"open('shell.txt','w').write('ok')\"",
                    "cwd": str(workspace),
                },
                **_authority_payload(agent_id="agent-shell-real", tool_family="shell", action="execute"),
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["decision"] == "ALLOW"
        assert body["execution"]["executed"] is True
        assert body["execution"]["mock"] is False
        assert body["execution"]["execution_status"] == "success"
        assert body["execution"]["raw_output"]["exit_code"] == 0
        assert body["credential_grant"]["lease_state"] == "revoked"
        assert target.read_text(encoding="utf-8") == "ok"

        with Session(get_engine()) as session:
            result = session.exec(
                select(ExecutionResult).where(ExecutionResult.attempt_id == body["attempt_id"])
            ).first()
            assert result is not None
            assert result.executed is True
            assert result.mock is False
            assert result.execution_status == "success"
            assert result.raw_output_json is not None
            assert json.loads(result.raw_output_json)["exit_code"] == 0
            events = session.exec(
                select(AuditEvent).where(AuditEvent.related_attempt_id == body["attempt_id"])
            ).all()
            event_types = {event.event_type for event in events}
            assert {"CREDENTIAL_ISSUED", "CREDENTIAL_ACTIVATED", "CREDENTIAL_REVOKED"}.issubset(event_types)
            issued_event = next(event for event in events if event.event_type == "CREDENTIAL_ISSUED")
            issued_payload = json.loads(issued_event.event_payload)
            assert issued_payload["run_id"] == body["attempt_id"]
            assert issued_payload["trace_id"] == body["trace_id"]
            assert issued_payload["actor_id"] == "ops@example.com"
            assert issued_payload["agent_id"] == "agent-shell-real"
            assert issued_payload["delegation_id"] == "dlg_agent-shell-real_shell_execute"
            assert issued_payload["authority_scope"]["tool_family"] == "shell"
            assert issued_payload["authority_scope"]["action"] == "execute"
            assert issued_payload["authority_scope"]["run_id"] == body["attempt_id"]
            assert issued_payload["authority_scope"]["trace_id"] == body["trace_id"]
            assert issued_payload["source_component"] == "agent_firewall.credentialing"

            revoked_event = next(event for event in events if event.event_type == "CREDENTIAL_REVOKED")
            revoked_payload = json.loads(revoked_event.event_payload)
            assert revoked_payload["run_id"] == body["attempt_id"]
            assert revoked_payload["trace_id"] == body["trace_id"]
            assert revoked_payload["source_component"] == "agent_firewall.credentialing"
            assert revoked_payload["timestamp"] is not None


def test_real_shell_execution_requires_idempotency_key(make_client):
    with make_client(zdg_real_exec_shell=True) as client:
        response = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-shell-no-idem",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "python3 -c \"print('hi')\""},
            },
        )

        assert response.status_code == 400
        assert response.json()["detail"]["reason_code"] == "IDEMPOTENCY_KEY_REQUIRED"

        with Session(get_engine()) as session:
            assert session.exec(select(ToolAttempt)).all() == []


def test_real_shell_execution_blocks_shell_metacharacters(make_client):
    with make_client(zdg_real_exec_shell=True) as client:
        response = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-shell-meta",
                "tool_family": "shell",
                "action": "execute",
                "idempotency_key": "shell-meta-1",
                "args": {"command": "echo safe && echo nope"},
                **_authority_payload(agent_id="agent-shell-meta", tool_family="shell", action="execute"),
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


def test_real_shell_execution_requires_explicit_authority_binding(make_client):
    with make_client(zdg_real_exec_shell=True) as client:
        response = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-shell-authority-missing",
                "tool_family": "shell",
                "action": "execute",
                "idempotency_key": "shell-authority-1",
                "args": {"command": "python3 -c \"print('hi')\""},
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["decision"] == "BLOCK"
        assert body["reason_code"] == "AUTHORITY_BINDING_REQUIRED"
        assert body["execution"] is None


def test_real_http_get_executes_against_localhost(make_client):
    with _local_http_server() as base_url:
        with make_client(zdg_real_exec_http=True) as client:
            response = client.post(
                "/v1/action",
                json={
                    "agent_id": "agent-http-real",
                    "tool_family": "http",
                    "action": "request",
                    "args": {
                        "method": "GET",
                        "url": f"{base_url}/ok",
                    },
                    **_authority_payload(agent_id="agent-http-real", tool_family="http", action="request"),
                },
            )

            assert response.status_code == 200
            body = response.json()
            assert body["decision"] == "ALLOW"
            assert body["execution"]["executed"] is True
            assert body["execution"]["execution_status"] == "success"
            assert body["execution"]["raw_output"]["status_code"] == 200

            with Session(get_engine()) as session:
                result = session.exec(
                    select(ExecutionResult).where(ExecutionResult.attempt_id == body["attempt_id"])
                ).first()
                assert result is not None
                assert result.executed is True
                assert result.mock is False
                assert result.execution_status == "success"
                assert result.raw_output_json is not None
                assert json.loads(result.raw_output_json)["status_code"] == 200


def test_real_http_mutation_requires_idempotency_key(make_client):
    with _local_http_server() as base_url:
        with make_client(zdg_real_exec_http=True) as client:
            response = client.post(
                "/v1/action",
                json={
                    "agent_id": "agent-http-no-idem",
                    "tool_family": "http",
                    "action": "request",
                    "args": {
                        "method": "POST",
                        "url": f"{base_url}/ok",
                        "body": "hello",
                    },
                },
            )

            assert response.status_code == 400
            assert response.json()["detail"]["reason_code"] == "IDEMPOTENCY_KEY_REQUIRED"


def test_real_http_redirect_validation_blocks_raw_ip_hop(make_client):
    with _local_http_server() as base_url:
        with make_client(zdg_real_exec_http=True) as client:
            response = client.post(
                "/v1/action",
                json={
                    "agent_id": "agent-http-redirect",
                    "tool_family": "http",
                    "action": "request",
                    "args": {
                        "method": "GET",
                        "url": f"{base_url}/redirect-raw",
                    },
                    **_authority_payload(agent_id="agent-http-redirect", tool_family="http", action="request"),
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

