"""Phase 3B integration tests for agent/session lifecycle and portable audit APIs."""

from __future__ import annotations

from copy import deepcopy

from datetime import datetime, timedelta, timezone
import json

from sqlmodel import Session, select

from core.modes import CredentialLeaseState
from db.models import AuditEvent, CredentialGrantRecord
from db.sqlite import get_engine



def test_agent_and_session_admin_routes(make_client, admin_headers):
    with make_client() as client:
        registered = client.post(
            "/v1/agents",
            headers=admin_headers,
            json={
                "agent_id": "agent-admin-routes",
                "agent_type": "openclaw",
                "metadata": {"owner": "platform"},
                "operator": "ops@example.com",
            },
        )
        assert registered.status_code == 200
        assert registered.json()["status"] == "active"

        listed = client.get("/v1/agents", headers=admin_headers)
        assert listed.status_code == 200
        assert listed.json()["count"] == 1

        created = client.post(
            "/v1/sessions",
            headers=admin_headers,
            json={
                "agent_id": "agent-admin-routes",
                "metadata": {"cohort": "pilot"},
                "operator": "ops@example.com",
                "creation_source": "api",
            },
        )
        assert created.status_code == 200
        session_id = created.json()["session_id"]

        fetched = client.get(f"/v1/sessions/{session_id}", headers=admin_headers)
        assert fetched.status_code == 200
        assert fetched.json()["agent_id"] == "agent-admin-routes"



def test_session_and_agent_lifecycle_block_actions(make_client, admin_headers):
    with make_client() as client:
        client.post(
            "/v1/agents",
            headers=admin_headers,
            json={
                "agent_id": "agent-lifecycle",
                "agent_type": "openclaw",
                "metadata": {},
                "operator": "ops@example.com",
            },
        )
        created = client.post(
            "/v1/sessions",
            headers=admin_headers,
            json={
                "agent_id": "agent-lifecycle",
                "metadata": {"purpose": "integration"},
                "operator": "ops@example.com",
            },
        )
        session_id = created.json()["session_id"]

        allowed = client.post(
            "/v1/action",
            json={
                "session_id": session_id,
                "agent_id": "agent-lifecycle",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo safe"},
            },
        )
        assert allowed.status_code == 200
        assert allowed.json()["decision"] == "ALLOW"

        suspended = client.post(
            f"/v1/sessions/{session_id}/suspend",
            headers=admin_headers,
            json={"operator": "ops@example.com", "reason": "Pause"},
        )
        assert suspended.status_code == 200

        blocked_session = client.post(
            "/v1/action",
            json={
                "session_id": session_id,
                "agent_id": "agent-lifecycle",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo safe"},
            },
        )
        assert blocked_session.status_code == 200
        assert blocked_session.json()["decision"] == "BLOCK"
        assert blocked_session.json()["reason_code"] == "SESSION_SUSPENDED"

        unsuspended = client.post(
            f"/v1/sessions/{session_id}/unsuspend",
            headers=admin_headers,
            json={"operator": "ops@example.com", "reason": "Resume"},
        )
        assert unsuspended.status_code == 200

        agent_suspended = client.post(
            "/v1/agents/agent-lifecycle/suspend",
            headers=admin_headers,
            json={"operator": "ops@example.com", "reason": "Agent pause"},
        )
        assert agent_suspended.status_code == 200

        blocked_agent = client.post(
            "/v1/action",
            json={
                "session_id": session_id,
                "agent_id": "agent-lifecycle",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo safe"},
            },
        )
        assert blocked_agent.status_code == 200
        assert blocked_agent.json()["decision"] == "BLOCK"
        assert blocked_agent.json()["reason_code"] == "AGENT_SUSPENDED"



def test_lifecycle_block_precedes_idempotent_replay(make_client, admin_headers):
    with make_client() as client:
        client.post(
            "/v1/agents",
            headers=admin_headers,
            json={
                "agent_id": "agent-replay-guard",
                "agent_type": "openclaw",
                "metadata": {},
                "operator": "ops@example.com",
            },
        )
        created = client.post(
            "/v1/sessions",
            headers=admin_headers,
            json={
                "agent_id": "agent-replay-guard",
                "metadata": {},
                "operator": "ops@example.com",
            },
        )
        session_id = created.json()["session_id"]

        request_body = {
            "session_id": session_id,
            "agent_id": "agent-replay-guard",
            "tool_family": "shell",
            "action": "execute",
            "idempotency_key": "idem-lifecycle-1",
            "args": {"command": "echo safe"},
        }

        first = client.post("/v1/action", json=request_body)
        assert first.status_code == 200
        assert first.json()["decision"] == "ALLOW"

        client.post(
            f"/v1/sessions/{session_id}/close",
            headers=admin_headers,
            json={"operator": "ops@example.com", "reason": "Closed"},
        )

        replay = client.post("/v1/action", json=request_body)
        assert replay.status_code == 200
        assert replay.json()["decision"] == "BLOCK"
        assert replay.json()["reason_code"] == "SESSION_CLOSED"
        assert replay.json()["idempotent_replay"] is False



def test_portable_audit_export_verify_and_diff(make_client, admin_headers):
    with make_client() as client:
        created = client.post(
            "/v1/sessions",
            headers=admin_headers,
            json={
                "agent_id": "agent-audit",
                "metadata": {"cohort": "pilot"},
                "operator": "ops@example.com",
            },
        )
        assert created.status_code == 200
        session_id = created.json()["session_id"]
        chain_id = f"session:{session_id}"

        action = client.post(
            "/v1/action",
            json={
                "session_id": session_id,
                "agent_id": "agent-audit",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo safe"},
            },
        )
        assert action.status_code == 200

        exported = client.get(
            f"/v1/audit/export?chain_id={chain_id}&format=json",
            headers=admin_headers,
        )
        assert exported.status_code == 200
        export_body = exported.json()
        assert export_body["chain_id"] == chain_id
        assert export_body["event_count"] >= 2

        verified = client.post(
            "/v1/audit/verify",
            headers=admin_headers,
            json=export_body,
        )
        assert verified.status_code == 200
        assert verified.json()["ok"] is True

        ndjson_export = client.get(
            f"/v1/audit/export?chain_id={chain_id}&format=ndjson",
            headers=admin_headers,
        )
        assert ndjson_export.status_code == 200
        assert "application/x-ndjson" in ndjson_export.headers["content-type"]

        verified_ndjson = client.post(
            "/v1/audit/verify",
            headers={**admin_headers, "Content-Type": "text/plain"},
            content=ndjson_export.text,
        )
        assert verified_ndjson.status_code == 200
        assert verified_ndjson.json()["ok"] is True

        tampered = deepcopy(export_body)
        tampered["events"] = tampered["events"][:-1]

        diffed = client.post(
            "/v1/audit/diff",
            headers=admin_headers,
            json={"left_export": export_body, "right_export": tampered},
        )
        assert diffed.status_code == 200
        diff_body = diffed.json()
        assert diff_body["left_chain_id"] == chain_id
        assert diff_body["right_chain_id"] == chain_id
        assert diff_body["common_prefix_length"] == len(tampered["events"])
        assert diff_body["left_unique_count"] == 1


def test_session_suspend_revokes_active_session_credentials(make_client, admin_headers):
    with make_client() as client:
        client.post(
            "/v1/agents",
            headers=admin_headers,
            json={
                "agent_id": "agent-credential-revoke-session",
                "agent_type": "openclaw",
                "metadata": {},
                "operator": "ops@example.com",
            },
        )
        created = client.post(
            "/v1/sessions",
            headers=admin_headers,
            json={
                "agent_id": "agent-credential-revoke-session",
                "metadata": {},
                "operator": "ops@example.com",
            },
        )
        session_id = created.json()["session_id"]
        issued_at = datetime.now(timezone.utc).replace(tzinfo=None)

        with Session(get_engine()) as session:
            session.add(
                CredentialGrantRecord(
                    grant_id="grt_session_revoke",
                    run_id="run_session_revoke",
                    session_id=session_id,
                    trace_id="trace_session_revoke",
                    actor_id="ops@example.com",
                    agent_id="agent-credential-revoke-session",
                    delegation_chain_id="dlg_session_revoke",
                    tool_family="shell",
                    action="execute",
                    privilege_scope_json="{}",
                    lease_state=CredentialLeaseState.ACTIVE.value,
                    issued_at=issued_at,
                    activated_at=issued_at,
                    expires_at=issued_at + timedelta(minutes=5),
                )
            )
            session.commit()

        response = client.post(
            f"/v1/sessions/{session_id}/suspend",
            headers=admin_headers,
            json={"operator": "ops@example.com", "reason": "Pause"},
        )
        assert response.status_code == 200

        with Session(get_engine()) as session:
            grant = session.exec(
                select(CredentialGrantRecord).where(CredentialGrantRecord.grant_id == "grt_session_revoke")
            ).one()
            assert grant.lease_state == CredentialLeaseState.REVOKED.value
            events = session.exec(
                select(AuditEvent).where(AuditEvent.event_type == "CREDENTIAL_REVOKED")
            ).all()
            matching = [event for event in events if "grt_session_revoke" in event.event_payload]
            assert matching
            payload = json.loads(matching[0].event_payload)
            assert payload["run_id"] == "run_session_revoke"
            assert payload["trace_id"] == "trace_session_revoke"
            assert payload["actor_id"] == "ops@example.com"
            assert payload["agent_id"] == "agent-credential-revoke-session"
            assert payload["delegation_id"] == "dlg_session_revoke"
            assert payload["source_component"] == "agent_firewall.credentialing"
            assert payload["timestamp"] is not None


def test_killswitch_activate_revokes_matching_tool_family_credentials(make_client, admin_headers):
    with make_client() as client:
        issued_at = datetime.now(timezone.utc).replace(tzinfo=None)
        with Session(get_engine()) as session:
            session.add(
                CredentialGrantRecord(
                    grant_id="grt_killswitch_revoke",
                    run_id="run_killswitch_revoke",
                    session_id="ses_killswitch_revoke",
                    trace_id="trace_killswitch_revoke",
                    actor_id="ops@example.com",
                    agent_id="agent-killswitch-revoke",
                    delegation_chain_id="dlg_killswitch_revoke",
                    tool_family="shell",
                    action="execute",
                    privilege_scope_json="{}",
                    lease_state=CredentialLeaseState.ACTIVE.value,
                    issued_at=issued_at,
                    activated_at=issued_at,
                    expires_at=issued_at + timedelta(minutes=5),
                )
            )
            session.commit()

        response = client.post(
            "/v1/killswitch/activate",
            headers=admin_headers,
            json={
                "operator": "ops@example.com",
                "scope": "tool_family",
                "scope_value": "shell",
                "comment": "Manual stop",
            },
        )
        assert response.status_code == 200

        with Session(get_engine()) as session:
            grant = session.exec(
                select(CredentialGrantRecord).where(CredentialGrantRecord.grant_id == "grt_killswitch_revoke")
            ).one()
            assert grant.lease_state == CredentialLeaseState.REVOKED.value
            events = session.exec(
                select(AuditEvent).where(AuditEvent.event_type == "CREDENTIAL_REVOKED")
            ).all()
            matching = [event for event in events if "grt_killswitch_revoke" in event.event_payload]
            assert matching
            payload = json.loads(matching[0].event_payload)
            assert payload["run_id"] == "run_killswitch_revoke"
            assert payload["trace_id"] == "trace_killswitch_revoke"
            assert payload["agent_id"] == "agent-killswitch-revoke"
            assert payload["source_component"] == "agent_firewall.credentialing"

