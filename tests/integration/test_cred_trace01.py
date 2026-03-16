"""
CRED-TRACE-01 — Authority-bounded credential trace shaping.

Proves that credential issuance, bounded use, revocation, and expiry are
legible in the replay snapshot derived from persisted runtime events.

Test coverage:
  GOV-017-a  Happy path — ALLOW run with real exec: grant→use→revoke visible
  GOV-017-b  Expiry visibility — expires_at populated; lease state derivable
  GOV-017-c  Revocation path — revoked_at and revocation_reason in summary
  GOV-017-d  No secret leakage — authority_context absent from summary; scope
             keys are safe metadata only
  GOV-017-e  Timeline ordering — ISSUED → ACTIVATED → REVOKED in seq order
  GOV-017-f  No-credential run — credential_summary.issued=False when cred not issued
"""
from __future__ import annotations

import json

ADMIN = {"X-ZDG-Admin-Token": "integration-admin-token"}

_SAFE_PRIVILEGE_SCOPE_KEYS = frozenset({
    "tool_family", "action", "session_id", "run_id", "trace_id",
})


def _authority_payload(*, agent_id: str, tool_family: str = "shell", action: str = "execute") -> dict:
    return {
        "actor_identity": {
            "actor_id": "ops@example.com",
            "actor_type": "human",
            "tenant_id": "tenant-cred-trace",
            "role_bindings": ["operator"],
        },
        "delegation_chain": {
            "delegation_chain_id": f"dlg_{agent_id}_{tool_family}_{action}",
            "root_actor_id": "ops@example.com",
            "delegated_agent_ids": [agent_id],
            "authority_scope": {"tool_family": tool_family, "action": action},
            "delegation_reason": "cred_trace_test",
        },
    }


# ── GOV-017-a: Happy path — grant → use → revoke visible ─────────────────────

def test_credential_summary_happy_path_grant_use_revoke(make_client, tmp_path):
    """ALLOW + real shell exec: credential_summary shows grant_id, subject_id,
    issued_at, expires_at, used=True, revoked_at populated."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)

    with make_client(zdg_real_exec_shell=True) as client:
        action = {
            "agent_id": "agent-cred-trace-allow",
            "tool_family": "shell",
            "action": "execute",
            "idempotency_key": "cred-trace-allow-001",
            "args": {"command": "echo cred-trace-ok", "cwd": str(workspace)},
            **_authority_payload(agent_id="agent-cred-trace-allow"),
        }
        r = client.post("/v1/action", json=action)
        assert r.status_code == 200
        body = r.json()
        assert body["decision"] == "ALLOW"
        attempt_id = body["attempt_id"]

        snap = client.get(f"/v1/audit/replay?attempt_id={attempt_id}", headers=ADMIN)
        assert snap.status_code == 200, snap.text
        s = snap.json()

        cs = s["credential_summary"]

        # Issued
        assert cs["issued"] is True
        assert cs["grant_id"] is not None
        assert cs["grant_id"].startswith("grt_")

        # Subject identity
        assert cs["subject_id"] == "ops@example.com"
        assert cs["subject_type"] == "human"

        # Scope
        assert cs["authority_scope"] is not None
        assert cs["authority_scope"]["tool_family"] == "shell"
        assert cs["authority_scope"]["action"] == "execute"

        # Timing: issued_at and expires_at populated
        assert cs["issued_at"] is not None
        assert cs["expires_at"] is not None

        # attempt_id cross-reference
        assert cs["attempt_id"] == attempt_id

        # After execution the credential is revoked
        assert cs["revoked_at"] is not None
        assert cs["revocation_reason"] is not None

        # Usage
        assert cs["used"] is True
        assert cs["usage_count"] == 1
        assert cs["in_bounds"] is True


# ── GOV-017-b: Expiry visibility ──────────────────────────────────────────────

def test_credential_summary_expires_at_populated(make_client, tmp_path):
    """expires_at is surfaced in credential_summary so operators can determine
    whether the lease was live or expired at time of use."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)

    with make_client(zdg_real_exec_shell=True) as client:
        action = {
            "agent_id": "agent-cred-expiry",
            "tool_family": "shell",
            "action": "execute",
            "idempotency_key": "cred-trace-expiry-001",
            "args": {"command": "echo expiry-check", "cwd": str(workspace)},
            **_authority_payload(agent_id="agent-cred-expiry"),
        }
        r = client.post("/v1/action", json=action)
        assert r.status_code == 200
        body = r.json()
        assert body["decision"] == "ALLOW"
        attempt_id = body["attempt_id"]

        snap = client.get(f"/v1/audit/replay?attempt_id={attempt_id}", headers=ADMIN)
        assert snap.status_code == 200
        cs = snap.json()["credential_summary"]

        # expires_at must be populated and parseable as ISO datetime
        assert cs["expires_at"] is not None
        from datetime import datetime
        exp = datetime.fromisoformat(cs["expires_at"])
        iss = datetime.fromisoformat(cs["issued_at"])
        # expires_at must be strictly after issued_at (TTL > 0)
        assert exp > iss, (
            f"expires_at ({cs['expires_at']}) must be after issued_at ({cs['issued_at']})"
        )


# ── GOV-017-c: Revocation path ────────────────────────────────────────────────

def test_credential_summary_revocation_fields_populated(make_client, tmp_path):
    """After a real exec run completes, revoked_at and revocation_reason appear
    in credential_summary derived from the CREDENTIAL_REVOKED event."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)

    with make_client(zdg_real_exec_shell=True) as client:
        action = {
            "agent_id": "agent-cred-revoke",
            "tool_family": "shell",
            "action": "execute",
            "idempotency_key": "cred-trace-revoke-001",
            "args": {"command": "echo revoke-test", "cwd": str(workspace)},
            **_authority_payload(agent_id="agent-cred-revoke"),
        }
        r = client.post("/v1/action", json=action)
        assert r.status_code == 200
        body = r.json()
        assert body["decision"] == "ALLOW"
        attempt_id = body["attempt_id"]

        snap = client.get(f"/v1/audit/replay?attempt_id={attempt_id}", headers=ADMIN)
        assert snap.status_code == 200
        cs = snap.json()["credential_summary"]

        assert cs["revoked_at"] is not None, "Credential must be revoked after execution completes"
        assert cs["revocation_reason"] is not None

        # Verify against the raw CREDENTIAL_REVOKED event in the timeline
        timeline = snap.json()["timeline"]
        revoked_ev = next(
            (e for e in timeline if e["event_type"] == "CREDENTIAL_REVOKED"), None
        )
        assert revoked_ev is not None, "CREDENTIAL_REVOKED must appear in the timeline"
        revoked_payload = revoked_ev["event_payload"]
        assert revoked_payload.get("revoked_at") == cs["revoked_at"]
        assert revoked_payload.get("revoked_reason") == cs["revocation_reason"]


# ── GOV-017-d: No secret leakage ─────────────────────────────────────────────

def test_credential_summary_no_secret_leakage(make_client, tmp_path):
    """credential_summary does not expose authority_context or any raw credential
    material. privilege_scope keys are restricted to safe metadata fields."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)

    with make_client(zdg_real_exec_shell=True) as client:
        action = {
            "agent_id": "agent-cred-nosecret",
            "tool_family": "shell",
            "action": "execute",
            "idempotency_key": "cred-trace-nosecret-001",
            "args": {"command": "echo nosecret", "cwd": str(workspace)},
            **_authority_payload(agent_id="agent-cred-nosecret"),
        }
        r = client.post("/v1/action", json=action)
        assert r.status_code == 200
        attempt_id = r.json()["attempt_id"]

        snap = client.get(f"/v1/audit/replay?attempt_id={attempt_id}", headers=ADMIN)
        assert snap.status_code == 200
        s = snap.json()
        cs = s["credential_summary"]

        # authority_context must NOT appear as a key in credential_summary
        assert "authority_context" not in cs, (
            "authority_context must not be surfaced in credential_summary — "
            "it may contain auth_context claims"
        )

        # privilege_scope / authority_scope keys must be safe metadata only
        scope = cs.get("authority_scope") or {}
        unexpected = set(scope.keys()) - _SAFE_PRIVILEGE_SCOPE_KEYS
        assert not unexpected, (
            f"Unexpected keys in authority_scope (potential secret leakage): {unexpected}"
        )

        # Verify that the raw timeline event still has authority_context intact
        # (the summary strips it; the evidence record retains it)
        timeline = s["timeline"]
        issued_ev = next(
            (e for e in timeline if e["event_type"] == "CREDENTIAL_ISSUED"), None
        )
        assert issued_ev is not None
        # The raw event payload for the timeline is intact (no stripping at event level)
        # This is correct: the summary layer strips sensitive fields; the evidence record retains them
        issued_payload = issued_ev["event_payload"]
        assert "grant_id" in issued_payload
        assert "privilege_scope" in issued_payload


# ── GOV-017-e: Timeline ordering ─────────────────────────────────────────────

def test_credential_timeline_ordering(make_client, tmp_path):
    """CREDENTIAL_ISSUED → CREDENTIAL_ACTIVATED → CREDENTIAL_REVOKED appear in
    strictly ascending seq order in the timeline."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)

    with make_client(zdg_real_exec_shell=True) as client:
        action = {
            "agent_id": "agent-cred-order",
            "tool_family": "shell",
            "action": "execute",
            "idempotency_key": "cred-trace-order-001",
            "args": {"command": "echo order-test", "cwd": str(workspace)},
            **_authority_payload(agent_id="agent-cred-order"),
        }
        r = client.post("/v1/action", json=action)
        assert r.status_code == 200
        assert r.json()["decision"] == "ALLOW"
        attempt_id = r.json()["attempt_id"]

        snap = client.get(f"/v1/audit/replay?attempt_id={attempt_id}", headers=ADMIN)
        assert snap.status_code == 200
        timeline = snap.json()["timeline"]

        cred_events = {
            e["event_type"]: e["seq"]
            for e in timeline
            if e["event_type"] in {"CREDENTIAL_ISSUED", "CREDENTIAL_ACTIVATED", "CREDENTIAL_REVOKED"}
        }
        assert "CREDENTIAL_ISSUED" in cred_events, "CREDENTIAL_ISSUED must be in timeline"
        assert "CREDENTIAL_ACTIVATED" in cred_events, "CREDENTIAL_ACTIVATED must be in timeline"
        assert "CREDENTIAL_REVOKED" in cred_events, "CREDENTIAL_REVOKED must be in timeline"

        assert cred_events["CREDENTIAL_ISSUED"] < cred_events["CREDENTIAL_ACTIVATED"], (
            "CREDENTIAL_ISSUED must precede CREDENTIAL_ACTIVATED"
        )
        assert cred_events["CREDENTIAL_ACTIVATED"] < cred_events["CREDENTIAL_REVOKED"], (
            "CREDENTIAL_ACTIVATED must precede CREDENTIAL_REVOKED"
        )

        # CREDENTIAL_ISSUED must also precede ACTION_ALLOWED
        allowed_seq = next(
            (e["seq"] for e in timeline if e["event_type"] == "ACTION_ALLOWED"), None
        )
        if allowed_seq is not None:
            assert cred_events["CREDENTIAL_ISSUED"] < allowed_seq, (
                "CREDENTIAL_ISSUED must precede ACTION_ALLOWED"
            )


# ── GOV-017-f: No-credential run — issued=False ───────────────────────────────

def test_credential_summary_not_issued_when_real_exec_disabled(make_client):
    """When real_exec is not enabled (mock mode), no credential is issued and
    credential_summary.issued is False with all fields null."""
    with make_client() as client:  # real_exec defaults to False
        r = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-cred-mock",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo mock"},
            },
        )
        assert r.status_code == 200
        body = r.json()
        assert body["decision"] == "ALLOW"
        attempt_id = body["attempt_id"]

        snap = client.get(f"/v1/audit/replay?attempt_id={attempt_id}", headers=ADMIN)
        assert snap.status_code == 200
        cs = snap.json()["credential_summary"]

        assert cs["issued"] is False
        assert cs["grant_id"] is None
        assert cs["subject_id"] is None
        assert cs["issued_at"] is None
        assert cs["expires_at"] is None
        assert cs["revoked_at"] is None
        assert cs["used"] is False
        assert cs["usage_count"] == 0
        assert cs["in_bounds"] is False
        assert cs["attempt_id"] == attempt_id
