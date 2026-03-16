"""
FRDEV-SEC-01 — Security and launch-risk fix regression suite.

Covers fixes applied during the FRDEV-SEC-01 review pass:
  - Input validation on chain_id and attempt_id (pattern + max_length)
  - events.py filtering pushed to SQL (correctness + no in-memory truncation)
  - events.py JSON parse failure is logged, not silently swallowed
  - auth.py logs failed admin token attempts without leaking token material
  - runs.py validates datetime format before fromisoformat()

Test coverage:
  SEC-001  audit/export rejects chain_id with invalid characters (422)
  SEC-002  audit/export rejects chain_id exceeding max_length (422)
  SEC-003  audit/replay rejects attempt_id with invalid characters (422)
  SEC-004  audit/replay rejects attempt_id exceeding max_length (422)
  SEC-005  GET /v1/events — event_type filter applied at SQL level (correct count)
  SEC-006  GET /v1/events — agent_id filter applied at SQL level (correct count)
  SEC-007  GET /v1/events — tool_family filter applied at SQL level (correct count)
  SEC-008  GET /v1/events — combined filters narrow results correctly
  SEC-009  GET /v1/events — agent_id max_length enforced (422)
  SEC-010  GET /v1/events — event_type max_length enforced (422)
  SEC-011  auth.py — failed token attempt logged (method, path, token_present)
  SEC-012  auth.py — failed token log does not contain the token value
  SEC-013  runs.py — invalid started_after format returns 400 with clear message
  SEC-014  runs.py — invalid started_before format returns 400 with clear message
  SEC-015  runs.py — valid ISO datetime in started_after is accepted
"""
from __future__ import annotations

import json
import logging

import pytest

ADMIN = {"X-ZDG-Admin-Token": "integration-admin-token"}


# ── SEC-001–004: Input validation on chain_id / attempt_id ───────────────────

def test_audit_export_rejects_invalid_chain_id_chars(make_client):
    """SEC-001: chain_id with shell-special chars rejected with 422."""
    with make_client() as client:
        r = client.get("/v1/audit/export", params={"chain_id": "../../etc/passwd"}, headers=ADMIN)
        assert r.status_code == 422


def test_audit_export_rejects_chain_id_too_long(make_client):
    """SEC-002: chain_id exceeding 256 chars rejected with 422."""
    with make_client() as client:
        long_id = "a" * 257
        r = client.get("/v1/audit/export", params={"chain_id": long_id}, headers=ADMIN)
        assert r.status_code == 422


def test_audit_replay_rejects_invalid_attempt_id_chars(make_client):
    """SEC-003: attempt_id with invalid chars rejected with 422."""
    with make_client() as client:
        r = client.get("/v1/audit/replay", params={"attempt_id": "foo;bar"}, headers=ADMIN)
        assert r.status_code == 422


def test_audit_replay_rejects_attempt_id_too_long(make_client):
    """SEC-004: attempt_id exceeding 256 chars rejected with 422."""
    with make_client() as client:
        long_id = "a" * 257
        r = client.get("/v1/audit/replay", params={"attempt_id": long_id}, headers=ADMIN)
        assert r.status_code == 422


# ── SEC-005–010: events.py SQL-level filtering ───────────────────────────────

def _seed_events(client, admin):
    """Seed a few governed runs to populate audit events."""
    payload = {
        "agent_id": "agent-alpha",
        "session_id": "sess-1",
        "action": "read_file",
        "tool_family": "filesystem",
        "context": {"path": "/tmp/test.txt"},
    }
    client.post("/v1/action", json=payload)
    payload2 = {
        "agent_id": "agent-beta",
        "session_id": "sess-2",
        "action": "send_email",
        "tool_family": "messaging",
        "context": {"to": "test@example.com", "body": "hi"},
    }
    client.post("/v1/action", json=payload2)


def test_events_event_type_filter_sql(make_client):
    """SEC-005: event_type filter hits DB, not Python post-fetch."""
    with make_client() as client:
        _seed_events(client, ADMIN)
        r_all = client.get("/v1/events", headers=ADMIN)
        assert r_all.status_code == 200
        all_count = r_all.json()["count"]

        r_filtered = client.get("/v1/events", params={"event_type": "ACTION_ATTEMPTED"}, headers=ADMIN)
        assert r_filtered.status_code == 200
        filtered_count = r_filtered.json()["count"]

        # ACTION_ATTEMPTED is a subset of all events
        assert filtered_count <= all_count
        for ev in r_filtered.json()["events"]:
            assert ev["event_type"] == "ACTION_ATTEMPTED"


def test_events_agent_id_filter_sql(make_client):
    """SEC-006: agent_id filter applied correctly — only matching events returned."""
    with make_client() as client:
        _seed_events(client, ADMIN)
        r = client.get("/v1/events", params={"agent_id": "agent-alpha"}, headers=ADMIN)
        assert r.status_code == 200
        for ev in r.json()["events"]:
            assert ev["payload"].get("agent_id") == "agent-alpha"


def test_events_tool_family_filter_sql(make_client):
    """SEC-007: tool_family filter applied correctly."""
    with make_client() as client:
        _seed_events(client, ADMIN)
        r = client.get("/v1/events", params={"tool_family": "filesystem"}, headers=ADMIN)
        assert r.status_code == 200
        for ev in r.json()["events"]:
            assert ev["payload"].get("tool_family") == "filesystem"


def test_events_combined_filters(make_client):
    """SEC-008: combined agent_id + event_type filters narrow results."""
    with make_client() as client:
        _seed_events(client, ADMIN)
        r = client.get(
            "/v1/events",
            params={"agent_id": "agent-alpha", "event_type": "ACTION_ATTEMPTED"},
            headers=ADMIN,
        )
        assert r.status_code == 200
        for ev in r.json()["events"]:
            assert ev["event_type"] == "ACTION_ATTEMPTED"
            assert ev["payload"].get("agent_id") == "agent-alpha"


def test_events_agent_id_max_length(make_client):
    """SEC-009: agent_id exceeding 256 chars rejected with 422."""
    with make_client() as client:
        r = client.get("/v1/events", params={"agent_id": "a" * 257}, headers=ADMIN)
        assert r.status_code == 422


def test_events_event_type_max_length(make_client):
    """SEC-010: event_type exceeding 128 chars rejected with 422."""
    with make_client() as client:
        r = client.get("/v1/events", params={"event_type": "x" * 129}, headers=ADMIN)
        assert r.status_code == 422


# ── SEC-011–012: auth.py failure logging ────────────────────────────────────

def test_auth_failure_logged(make_client, caplog):
    """SEC-011: failed admin token attempt is logged with method and path."""
    with make_client() as client:
        with caplog.at_level(logging.WARNING, logger="api.auth"):
            r = client.get("/v1/events", headers={"X-ZDG-Admin-Token": "wrong-token"})
        assert r.status_code == 401
        assert any("admin_auth_failed" in rec.message for rec in caplog.records)
        log_msg = next(rec.message for rec in caplog.records if "admin_auth_failed" in rec.message)
        assert "GET" in log_msg
        assert "/v1/events" in log_msg


def test_auth_failure_log_no_token_material(make_client, caplog):
    """SEC-012: failed token log does not include the submitted token value."""
    with make_client() as client:
        bad_token = "supersecret-bad-token-12345"
        with caplog.at_level(logging.WARNING, logger="api.auth"):
            client.get("/v1/events", headers={"X-ZDG-Admin-Token": bad_token})
        for rec in caplog.records:
            assert bad_token not in rec.message


# ── SEC-013–015: runs.py datetime validation ─────────────────────────────────

def test_runs_invalid_started_after_returns_400(make_client):
    """SEC-013: invalid started_after format returns 400 with clear message."""
    with make_client() as client:
        r = client.get("/v1/audit/runs", params={"started_after": "not-a-date"}, headers=ADMIN)
        assert r.status_code == 400
        assert "started_after" in r.json().get("detail", {}).get("reason", "")


def test_runs_invalid_started_before_returns_400(make_client):
    """SEC-014: invalid started_before format returns 400 with clear message."""
    with make_client() as client:
        r = client.get("/v1/audit/runs", params={"started_before": "tomorrow"}, headers=ADMIN)
        assert r.status_code == 400
        assert "started_before" in r.json().get("detail", {}).get("reason", "")


def test_runs_valid_iso_started_after_accepted(make_client):
    """SEC-015: valid ISO datetime in started_after returns 200."""
    with make_client() as client:
        r = client.get(
            "/v1/audit/runs",
            params={"started_after": "2024-01-01T00:00:00"},
            headers=ADMIN,
        )
        assert r.status_code == 200
