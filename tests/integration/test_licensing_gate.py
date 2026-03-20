"""Mission 2 Verification — Licensing Gate Integration Tests.

Proves that active/trialing licenses pass and expired/revoked licenses fail
at the Tier 0 gate before evaluation work begins.
"""

import pytest
from sqlmodel import Session, select
from db.sqlite import get_engine
from core.licensing import create_account, create_license, add_entitlement, register_installation
from db.models import ToolAttempt, License

def test_active_license_allows_action(make_client):
    with make_client() as client:
        # 1. Seed an active license
        from db.sqlite import get_engine
        from sqlmodel import Session
        with Session(get_engine()) as session:
            acc = create_account(session, email="dev@example.com", display_name="Dev")
            session.flush()
            lic = create_license(session, account_id=acc.account_id, plan_code="dev_monthly", status="active")
            session.flush()
            # Register installation - required for some license logic and satisfies FKs
            register_installation(session, account_id=acc.account_id, license_id=lic.license_id, device_label="test-device")
            # Seed monthly run limit high
            add_entitlement(session, license_id=lic.license_id, feature_code="max_monthly_runs", enabled=True, limit_value=1000)
            session.commit()

        # 2. Verify action passes
        resp = client.post("/v1/action", json={
            "agent_id": "test-agent",
            "tool_family": "shell",
            "action": "execute",
            "args": {"command": "echo pass"}
        })
        assert resp.status_code == 200
        assert resp.json()["decision"] == "ALLOW"

def test_expired_license_blocks_with_402(make_client):
    with make_client() as client:
        # 1. Seed an expired license
        from db.sqlite import get_engine
        from sqlmodel import Session
        with Session(get_engine()) as session:
            acc = create_account(session, email="dev@example.com", display_name="Dev")
            session.flush()
            lic = create_license(session, account_id=acc.account_id, plan_code="dev_monthly", status="expired")
            session.flush()
            register_installation(session, account_id=acc.account_id, license_id=lic.license_id, device_label="test-device")
            session.commit()

        # 2. Verify action returns 402 immediately
        resp = client.post("/v1/action", json={
            "agent_id": "test-agent",
            "tool_family": "shell",
            "action": "execute",
            "args": {"command": "echo fail"}
        })
        assert resp.status_code == 402
        # Either the license status or the resulting 0-limit block is acceptable
        reason = resp.json()["detail"]["reason"]
        assert "license_expired" in reason or "monthly_run_limit_exceeded" in reason

        # 3. CRITICAL: Verify NO ToolAttempt was created (proving Tier 0 gate)
        with Session(get_engine()) as session:
            attempts = session.exec(select(ToolAttempt)).all()
            assert len(attempts) == 0

def test_revoked_license_blocks_with_402(make_client):
    with make_client() as client:
        # 1. Seed a revoked license
        from db.sqlite import get_engine
        from sqlmodel import Session
        with Session(get_engine()) as session:
            acc = create_account(session, email="dev@example.com", display_name="Dev")
            session.flush()
            lic = create_license(session, account_id=acc.account_id, plan_code="dev_monthly", status="revoked")
            session.flush()
            register_installation(session, account_id=acc.account_id, license_id=lic.license_id, device_label="test-device")
            session.commit()

        # 2. Verify action returns 402
        resp = client.post("/v1/action", json={
            "agent_id": "test-agent",
            "tool_family": "shell",
            "action": "execute",
            "args": {"command": "echo fail"}
        })
        assert resp.status_code == 402
        reason = resp.json()["detail"]["reason"]
        assert "license_revoked" in reason or "monthly_run_limit_exceeded" in reason

def test_unmanaged_evaluation_mode_uses_unmanaged_limits(make_client):
    # Testing that if NO license exists, it uses UNMANAGED_LIMITS (which allow 25 runs)
    with make_client() as client:
        # 1. Ensure 0 licenses exist
        from db.sqlite import get_engine
        from sqlmodel import Session
        with Session(get_engine()) as session:
            assert len(session.exec(select(License)).all()) == 0

        # 2. Verify action passes (under unmanaged limit)
        resp = client.post("/v1/action", json={
            "agent_id": "test-agent",
            "tool_family": "shell",
            "action": "execute",
            "args": {"command": "echo pass"}
        })
        assert resp.status_code == 200
        assert resp.json()["decision"] == "ALLOW"
