"""Phase 2A integration tests for shared evaluation trace behavior."""

from __future__ import annotations

from sqlmodel import Session, select

from db.models import Approval, AuditEvent, PolicyDecision, ToolAttempt
from db.sqlite import get_engine


def test_investigate_returns_trace_without_persistence(make_client, admin_headers):
    with make_client() as client:
        response = client.post(
            "/v1/investigate",
            headers=admin_headers,
            json={
                "agent_id": "agent-investigate",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo safe"},
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["payload_hash"].startswith("sha256:")
        assert body["normalization_status"] == "COMPLETE"
        assert body["normalization_steps"]
        assert body["final_decision"]["decision"] == "ALLOW"
        assert body["final_decision"]["reason_code"] == "ALLOW"
        assert body["final_decision"]["policy_bundle_version"]

        with Session(get_engine()) as session:
            assert len(session.exec(select(ToolAttempt)).all()) == 0
            assert len(session.exec(select(PolicyDecision)).all()) == 0
            assert len(session.exec(select(AuditEvent)).all()) == 0


def test_approval_resolution_and_consumption_allows_one_later_action(make_client, admin_headers):
    with make_client() as client:
        request_body = {
            "agent_id": "agent-approval-consume",
            "tool_family": "messaging",
            "action": "send",
            "args": {
                "to": [f"user{i}@internal.example.com" for i in range(8)],
                "subject": "Quarterly update",
            },
        }

        initial = client.post("/v1/action", json=request_body)
        assert initial.status_code == 200
        initial_body = initial.json()
        assert initial_body["decision"] == "APPROVAL_REQUIRED"
        approval_id = initial_body["approval_id"]

        resolved = client.post(
            f"/v1/approval/{approval_id}",
            headers=admin_headers,
            json={
                "approve": True,
                "operator": "ops@example.com",
                "payload_hash": initial_body["payload_hash"],
            },
        )
        assert resolved.status_code == 200

        approved = client.post(
            "/v1/action",
            json={
                **request_body,
                "approval_id": approval_id,
            },
        )
        assert approved.status_code == 200
        approved_body = approved.json()
        assert approved_body["decision"] == "ALLOW"
        assert approved_body["reason_code"] == "APPROVED_MATCHED"
        assert approved_body["approval_id"] == approval_id
        assert approved_body["approval_consumed"] is True

        with Session(get_engine()) as session:
            approval = session.get(Approval, approval_id)
            assert approval is not None
            assert approval.consumed_at is not None
            assert approval.consumed_attempt_id == approved_body["attempt_id"]

            events = session.exec(
                select(AuditEvent).where(AuditEvent.related_attempt_id == approved_body["attempt_id"])
            ).all()
            event_types = {event.event_type for event in events}
            assert "APPROVAL_CONSUMED" in event_types
            assert "ACTION_ALLOWED" in event_types


def test_consumed_approval_cannot_be_reused(make_client, admin_headers):
    with make_client() as client:
        request_body = {
            "agent_id": "agent-approval-reuse",
            "tool_family": "messaging",
            "action": "send",
            "args": {
                "to": [f"user{i}@internal.example.com" for i in range(8)],
                "subject": "Quarterly update",
            },
        }

        initial = client.post("/v1/action", json=request_body)
        approval_id = initial.json()["approval_id"]
        payload_hash = initial.json()["payload_hash"]

        client.post(
            f"/v1/approval/{approval_id}",
            headers=admin_headers,
            json={
                "approve": True,
                "operator": "ops@example.com",
                "payload_hash": payload_hash,
            },
        )

        first_use = client.post("/v1/action", json={**request_body, "approval_id": approval_id})
        assert first_use.status_code == 200
        assert first_use.json()["approval_consumed"] is True

        second_use = client.post("/v1/action", json={**request_body, "approval_id": approval_id})
        assert second_use.status_code == 409
        assert second_use.json()["detail"]["reason_code"] == "APPROVAL_ALREADY_USED"


def test_idempotent_replay_returns_cached_response(make_client):
    with make_client() as client:
        request_body = {
            "agent_id": "agent-idempotent",
            "tool_family": "shell",
            "action": "execute",
            "idempotency_key": "idem-safe-shell-1",
            "args": {"command": "echo safe"},
        }

        first = client.post("/v1/action", json=request_body)
        second = client.post("/v1/action", json=request_body)

        assert first.status_code == 200
        assert second.status_code == 200
        first_body = first.json()
        second_body = second.json()
        assert first_body["attempt_id"] == second_body["attempt_id"]
        assert first_body["decision_id"] == second_body["decision_id"]
        assert first_body["execution"]["output_summary"] == second_body["execution"]["output_summary"]
        assert second_body["idempotent_replay"] is True

        with Session(get_engine()) as session:
            assert len(session.exec(select(ToolAttempt)).all()) == 1


def test_approval_flow_scopes_idempotency_by_approval_context(make_client, admin_headers):
    with make_client() as client:
        request_body = {
            "agent_id": "agent-approval-idempotent",
            "tool_family": "messaging",
            "action": "send",
            "idempotency_key": "idem-approval-1",
            "args": {
                "to": [f"user{i}@internal.example.com" for i in range(8)],
                "subject": "Quarterly update",
            },
        }

        initial = client.post("/v1/action", json=request_body)
        assert initial.status_code == 200
        initial_body = initial.json()
        assert initial_body["decision"] == "APPROVAL_REQUIRED"
        approval_id = initial_body["approval_id"]

        resolved = client.post(
            f"/v1/approval/{approval_id}",
            headers=admin_headers,
            json={
                "approve": True,
                "operator": "ops@example.com",
                "payload_hash": initial_body["payload_hash"],
            },
        )
        assert resolved.status_code == 200

        approved = client.post(
            "/v1/action",
            json={
                **request_body,
                "approval_id": approval_id,
            },
        )
        assert approved.status_code == 200
        approved_body = approved.json()
        assert approved_body["decision"] == "ALLOW"
        assert approved_body["reason_code"] == "APPROVED_MATCHED"
        assert approved_body["approval_consumed"] is True

        approved_replay = client.post(
            "/v1/action",
            json={
                **request_body,
                "approval_id": approval_id,
            },
        )
        assert approved_replay.status_code == 200
        replay_body = approved_replay.json()
        assert replay_body["decision"] == "ALLOW"
        assert replay_body["idempotent_replay"] is True
        assert replay_body["attempt_id"] == approved_body["attempt_id"]

        pending_replay = client.post("/v1/action", json=request_body)
        assert pending_replay.status_code == 200
        pending_body = pending_replay.json()
        assert pending_body["decision"] == "APPROVAL_REQUIRED"
        assert pending_body["idempotent_replay"] is True
        assert pending_body["attempt_id"] == initial_body["attempt_id"]

        with Session(get_engine()) as session:
            assert len(session.exec(select(ToolAttempt)).all()) == 2


def test_killswitch_precedence_is_respected_end_to_end(make_client, admin_headers):
    with make_client() as client:
        activate_tool = client.post(
            "/v1/killswitch/activate",
            headers=admin_headers,
            json={
                "operator": "ops@example.com",
                "scope": "tool_family",
                "scope_value": "shell",
                "comment": "tool family halt",
            },
        )
        assert activate_tool.status_code == 200

        activate_agent = client.post(
            "/v1/killswitch/activate",
            headers=admin_headers,
            json={
                "operator": "ops@example.com",
                "scope": "agent",
                "scope_value": "agent-ks",
                "comment": "agent halt",
            },
        )
        assert activate_agent.status_code == 200

        agent_block = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-ks",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo safe"},
            },
        )
        assert agent_block.status_code == 200
        assert agent_block.json()["reason_code"] == "KILLSWITCH_ACTIVE"
        assert agent_block.json()["killswitch_scope"] == "agent"

        activate_global = client.post(
            "/v1/killswitch/activate",
            headers=admin_headers,
            json={
                "operator": "ops@example.com",
                "scope": "global",
                "comment": "global halt",
            },
        )
        assert activate_global.status_code == 200

        global_block = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-ks",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo safe"},
            },
        )
        assert global_block.status_code == 200
        assert global_block.json()["killswitch_scope"] == "global"
