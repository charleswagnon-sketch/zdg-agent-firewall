"""Phase 2B integration tests for admin auth and policy reload."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlmodel import Session, select

from db.models import AuditEvent
from db.sqlite import get_engine


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_BUNDLE = PROJECT_ROOT / "policies" / "bundles" / "local_default.yaml"


def test_admin_endpoints_require_token(make_client):
    with make_client() as client:
        metrics = client.get("/v1/metrics")
        investigate = client.post(
            "/v1/investigate",
            json={
                "agent_id": "agent-auth",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo safe"},
            },
        )

        assert metrics.status_code == 401
        assert investigate.status_code == 401


def test_admin_endpoints_fail_closed_when_token_is_not_configured(make_client, admin_headers):
    # Startup validation now fails early (RuntimeError) rather than returning 503 at runtime.
    # Fail-closed: app refuses to start with no admin token configured.
    with pytest.raises(RuntimeError, match="ZDG_ADMIN_TOKEN"):
        with make_client(zdg_admin_token="") as client:
            pass


def test_policy_reload_swaps_bundle_and_audits_event(make_client, admin_headers, tmp_path):
    bundle_path = tmp_path / "reloadable_bundle.yaml"
    bundle_path.write_text(SOURCE_BUNDLE.read_text(encoding="utf-8"), encoding="utf-8")

    with make_client(zdg_policy_bundle_path=str(bundle_path)) as client:
        before = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-reload-before",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo safe"},
            },
        )
        assert before.status_code == 200
        assert before.json()["policy_bundle_version"] == "1.0.0"

        updated = bundle_path.read_text(encoding="utf-8")
        updated = updated.replace('bundle_id: "local-default-v1"', 'bundle_id: "local-default-v2"')
        updated = updated.replace('version: "1.0.0"', 'version: "2.0.0"')
        bundle_path.write_text(updated, encoding="utf-8")

        reload_response = client.post("/v1/policy/reload", headers=admin_headers)
        assert reload_response.status_code == 200
        reload_body = reload_response.json()
        assert reload_body["reloaded"] is True
        assert reload_body["old_version"] == "1.0.0"
        assert reload_body["new_version"] == "2.0.0"

        after = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-reload-after",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo safe"},
            },
        )
        assert after.status_code == 200
        assert after.json()["policy_bundle_version"] == "2.0.0"

        with Session(get_engine()) as session:
            events = session.exec(
                select(AuditEvent).where(AuditEvent.event_type == "POLICY_RELOAD")
            ).all()
            assert len(events) == 1
            assert "2.0.0" in events[0].event_payload


def test_policy_reload_rejects_invalid_bundle_and_keeps_prior_bundle(make_client, admin_headers, tmp_path):
    bundle_path = tmp_path / "invalid_reload_bundle.yaml"
    bundle_path.write_text(SOURCE_BUNDLE.read_text(encoding="utf-8"), encoding="utf-8")

    with make_client(zdg_policy_bundle_path=str(bundle_path)) as client:
        invalid = bundle_path.read_text(encoding="utf-8")
        invalid = invalid.replace("approval_min: 30", "approval_min: 20")
        bundle_path.write_text(invalid, encoding="utf-8")

        reload_response = client.post("/v1/policy/reload", headers=admin_headers)
        assert reload_response.status_code == 400

        action = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-invalid-reload",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo safe"},
            },
        )
        assert action.status_code == 200
        assert action.json()["policy_bundle_version"] == "1.0.0"

        with Session(get_engine()) as session:
            events = session.exec(
                select(AuditEvent).where(AuditEvent.event_type == "POLICY_RELOAD")
            ).all()
            assert events == []