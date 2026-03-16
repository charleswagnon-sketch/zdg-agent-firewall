"""
FRDEV-TRIAL-01 — Closed external developer trial prep suite.

Tests trial provisioning helpers, support bundle safety, feedback capture,
and first-run UX behavior.

Test coverage:
  TRIAL-001  Support bundle — admin token required (401 without token)
  TRIAL-002  Support bundle — returns 200 with expected top-level keys
  TRIAL-003  Support bundle — admin_token_set is a boolean, not the token value
  TRIAL-004  Support bundle — no raw payloads, authority_context, or credential material in response
  TRIAL-005  Support bundle — app version and policy bundle fields present
  TRIAL-006  Support bundle — platform fields present (python_version, os, arch)
  TRIAL-007  Support bundle — config_health booleans present
  TRIAL-008  Support bundle — license summary present (unmanaged_mode at minimum)
  TRIAL-009  Support bundle — recent_runs present with total_count and attempt_ids list
  TRIAL-010  Support bundle — trial_feedback count present
  TRIAL-011  Feedback — admin token required (401 without token)
  TRIAL-012  Feedback — submit bug_report returns 201 with feedback_id
  TRIAL-013  Feedback — submit feature_request and general types accepted
  TRIAL-014  Feedback — invalid feedback_type returns 422
  TRIAL-015  Feedback — empty description rejected (below min_length=1)
  TRIAL-016  Feedback count increases in support bundle after submission
"""
from __future__ import annotations

ADMIN = {"X-ZDG-Admin-Token": "integration-admin-token"}


# ── TRIAL-001: Auth required ───────────────────────────────────────────────────

def test_support_bundle_requires_admin(make_client):
    """TRIAL-001: Support bundle requires admin token."""
    with make_client() as client:
        r = client.get("/v1/support/bundle")
        assert r.status_code == 401


# ── TRIAL-002: Bundle structure ────────────────────────────────────────────────

def test_support_bundle_top_level_keys(make_client):
    """TRIAL-002: Bundle returns 200 with expected top-level keys."""
    with make_client() as client:
        r = client.get("/v1/support/bundle", headers=ADMIN)
        assert r.status_code == 200
        data = r.json()
        for key in ("bundle_id", "generated_at", "app", "platform", "config_health",
                    "license", "recent_runs", "trial_feedback"):
            assert key in data, f"Missing top-level key: {key!r}"
        assert data["bundle_id"].startswith("sup_")


# ── TRIAL-003: Admin token safety ─────────────────────────────────────────────

def test_support_bundle_admin_token_is_boolean(make_client):
    """TRIAL-003: admin_token_set is a boolean, not the actual token value."""
    with make_client() as client:
        r = client.get("/v1/support/bundle", headers=ADMIN)
        assert r.status_code == 200
        data = r.json()
        config = data["config_health"]
        assert "admin_token_set" in config
        assert isinstance(config["admin_token_set"], bool)
        assert config["admin_token_set"] is True  # token is set in test client
        # Must not contain the actual token value anywhere
        bundle_str = r.text
        assert "integration-admin-token" not in bundle_str


# ── TRIAL-004: No sensitive fields ────────────────────────────────────────────

def test_support_bundle_no_sensitive_fields(make_client):
    """TRIAL-004: Bundle contains no raw payloads, authority_context, or credential material."""
    with make_client() as client:
        r = client.get("/v1/support/bundle", headers=ADMIN)
        assert r.status_code == 200
        data = r.json()
        bundle_str = r.text.lower()
        for forbidden in ("raw_payload", "authority_context", "credential", "secret", "password", "token_value"):
            assert forbidden not in bundle_str, f"Forbidden field found in bundle: {forbidden!r}"
        # recent_runs must not contain payload data, only attempt_ids
        assert "attempt_ids" in data["recent_runs"]
        assert "payload" not in str(data["recent_runs"])


# ── TRIAL-005: App fields ──────────────────────────────────────────────────────

def test_support_bundle_app_fields(make_client):
    """TRIAL-005: App version and policy bundle fields present."""
    with make_client() as client:
        r = client.get("/v1/support/bundle", headers=ADMIN)
        assert r.status_code == 200
        app = r.json()["app"]
        assert "version" in app
        assert app["version"]  # non-empty
        assert "policy_bundle_id" in app
        assert "policy_bundle_version" in app


# ── TRIAL-006: Platform fields ────────────────────────────────────────────────

def test_support_bundle_platform_fields(make_client):
    """TRIAL-006: Platform fields present."""
    with make_client() as client:
        r = client.get("/v1/support/bundle", headers=ADMIN)
        assert r.status_code == 200
        platform = r.json()["platform"]
        assert "python_version" in platform
        assert "os" in platform
        assert "arch" in platform
        assert platform["python_version"]  # non-empty


# ── TRIAL-007: Config health booleans ─────────────────────────────────────────

def test_support_bundle_config_health(make_client):
    """TRIAL-007: config_health contains expected boolean/value fields."""
    with make_client() as client:
        r = client.get("/v1/support/bundle", headers=ADMIN)
        assert r.status_code == 200
        config = r.json()["config_health"]
        for bool_field in ("admin_token_set", "real_exec_enabled", "contract_expiry_sweep_enabled"):
            assert bool_field in config, f"Missing config_health field: {bool_field!r}"
            assert isinstance(config[bool_field], bool), f"{bool_field!r} must be a bool"
        # chain_id and env are informational (not secret)
        assert "chain_id" in config
        assert "env" in config


# ── TRIAL-008: License summary ────────────────────────────────────────────────

def test_support_bundle_license_summary(make_client):
    """TRIAL-008: License summary present with at minimum unmanaged_mode."""
    with make_client() as client:
        r = client.get("/v1/support/bundle", headers=ADMIN)
        assert r.status_code == 200
        lic = r.json()["license"]
        assert "unmanaged_mode" in lic
        assert isinstance(lic["unmanaged_mode"], bool)


# ── TRIAL-009: Recent runs ────────────────────────────────────────────────────

def test_support_bundle_recent_runs(make_client):
    """TRIAL-009: recent_runs present with total_count and attempt_ids list."""
    with make_client() as client:
        r = client.get("/v1/support/bundle", headers=ADMIN)
        assert r.status_code == 200
        runs = r.json()["recent_runs"]
        assert "total_count" in runs
        assert "attempt_ids" in runs
        assert isinstance(runs["attempt_ids"], list)
        assert isinstance(runs["total_count"], int)


# ── TRIAL-010: Feedback count ─────────────────────────────────────────────────

def test_support_bundle_feedback_count(make_client):
    """TRIAL-010: trial_feedback count present and is integer."""
    with make_client() as client:
        r = client.get("/v1/support/bundle", headers=ADMIN)
        assert r.status_code == 200
        feedback = r.json()["trial_feedback"]
        assert "count" in feedback
        assert isinstance(feedback["count"], int)


# ── TRIAL-011: Feedback auth required ─────────────────────────────────────────

def test_feedback_requires_admin(make_client):
    """TRIAL-011: Feedback endpoint requires admin token."""
    with make_client() as client:
        r = client.post("/v1/support/feedback", json={
            "feedback_type": "general",
            "description": "Test feedback",
        })
        assert r.status_code == 401


# ── TRIAL-012: Submit bug_report ──────────────────────────────────────────────

def test_feedback_submit_bug_report(make_client):
    """TRIAL-012: Submit bug_report returns 201 with feedback_id."""
    with make_client() as client:
        r = client.post("/v1/support/feedback", headers=ADMIN, json={
            "feedback_type": "bug_report",
            "description": "Replay view fails with special characters in attempt_id.",
            "context": {"steps": ["Open console", "Click Runs", "Click Open"]},
        })
        assert r.status_code == 201
        data = r.json()
        assert data["feedback_id"].startswith("fbk_")
        assert data["feedback_type"] == "bug_report"
        assert "created_at" in data


# ── TRIAL-013: All valid feedback types accepted ──────────────────────────────

def test_feedback_all_valid_types(make_client):
    """TRIAL-013: All three valid feedback_type values are accepted."""
    with make_client() as client:
        for ftype in ("bug_report", "feature_request", "general"):
            r = client.post("/v1/support/feedback", headers=ADMIN, json={
                "feedback_type": ftype,
                "description": f"Test {ftype} submission.",
            })
            assert r.status_code == 201, f"Expected 201 for type {ftype!r}, got {r.status_code}: {r.text}"
            assert r.json()["feedback_type"] == ftype


# ── TRIAL-014: Invalid feedback_type rejected ─────────────────────────────────

def test_feedback_invalid_type_rejected(make_client):
    """TRIAL-014: Invalid feedback_type returns 422."""
    with make_client() as client:
        r = client.post("/v1/support/feedback", headers=ADMIN, json={
            "feedback_type": "not_a_valid_type",
            "description": "This should be rejected.",
        })
        assert r.status_code == 422
        detail = r.json()["detail"]
        assert "Invalid feedback_type" in str(detail)


# ── TRIAL-015: Empty description rejected ────────────────────────────────────

def test_feedback_empty_description_rejected(make_client):
    """TRIAL-015: Empty description is rejected (min_length=1)."""
    with make_client() as client:
        r = client.post("/v1/support/feedback", headers=ADMIN, json={
            "feedback_type": "general",
            "description": "",
        })
        assert r.status_code == 422


# ── TRIAL-016: Feedback count increments in bundle ───────────────────────────

def test_feedback_count_increments_in_bundle(make_client):
    """TRIAL-016: Feedback count in support bundle increases after each submission."""
    with make_client() as client:
        before = client.get("/v1/support/bundle", headers=ADMIN).json()["trial_feedback"]["count"]

        client.post("/v1/support/feedback", headers=ADMIN, json={
            "feedback_type": "general",
            "description": "First feedback entry.",
        })
        client.post("/v1/support/feedback", headers=ADMIN, json={
            "feedback_type": "bug_report",
            "description": "Second feedback entry.",
        })

        after = client.get("/v1/support/bundle", headers=ADMIN).json()["trial_feedback"]["count"]
        assert after == before + 2
