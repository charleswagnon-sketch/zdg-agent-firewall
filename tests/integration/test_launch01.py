"""
FRDEV-LAUNCH-01 — Developer activation and launch packaging suite.

Tests plan catalog defaults, activation seeding behavior, status messages,
and the /v1/license/plans discovery endpoint.

Test coverage:
  LAUNCH-001  Plan catalog — get_plan_definition returns correct shape for canonical plans
  LAUNCH-002  Plan catalog — unknown plan_code returns None from get_plan_definition
  LAUNCH-003  Activate free plan — no explicit entitlements → plan defaults seeded (debug_bundle_export disabled)
  LAUNCH-004  Activate dev_monthly — no explicit entitlements → debug_bundle_export enabled, entitlements_added=6
  LAUNCH-005  Activate dev_annual — same feature set as dev_monthly
  LAUNCH-006  Activate with explicit entitlements — explicit list used as-is, plan defaults NOT applied
  LAUNCH-007  Activate unknown plan_code with no entitlements — accepted, no rows seeded (permissive)
  LAUNCH-008  GET /v1/license status_message — unmanaged mode returns expected message
  LAUNCH-009  GET /v1/license status_message — active license returns plan-specific message
  LAUNCH-010  GET /v1/license status_message — expired license returns expired message
  LAUNCH-011  GET /v1/license/plans — returns all three canonical plan codes
  LAUNCH-012  GET /v1/license/plans — each plan entry has plan_code, description, and entitlements list
  LAUNCH-013  GET /v1/license/plans — admin token required (401 without token)
  LAUNCH-014  Activate free plan — debug_bundle_export=False → audit/export returns 402
  LAUNCH-015  Activate dev_monthly — debug_bundle_export=True → audit/export returns 200
"""
from __future__ import annotations

ADMIN = {"X-ZDG-Admin-Token": "integration-admin-token"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _activate(client, *, email="dev@example.com", plan_code="dev_monthly", status="active",
              entitlements=None, **kwargs):
    """Helper: POST /v1/license/activate and assert 201."""
    body = {
        "email": email,
        "plan_code": plan_code,
        "status": status,
        **({"entitlements": entitlements} if entitlements is not None else {}),
        **kwargs,
    }
    r = client.post("/v1/license/activate", json=body, headers=ADMIN)
    assert r.status_code == 201, f"activate failed: {r.status_code} {r.text}"
    return r.json()


# ── LAUNCH-001: Plan catalog shape ────────────────────────────────────────────

def test_plan_catalog_canonical_plans():
    """LAUNCH-001: get_plan_definition returns correct shape for canonical plans."""
    from core.licensing import PLAN_CATALOG, get_plan_definition

    for code in ("free", "dev_monthly", "dev_annual"):
        plan = get_plan_definition(code)
        assert plan is not None, f"Plan {code!r} missing from catalog"
        assert "description" in plan
        assert "entitlements" in plan
        assert isinstance(plan["entitlements"], list)
        assert len(plan["entitlements"]) > 0

        # Every entitlement entry has the required keys
        for ent in plan["entitlements"]:
            assert "feature_code" in ent
            assert "enabled" in ent
            assert "limit_value" in ent

    # All three plans define the same feature codes
    free_codes = {e["feature_code"] for e in PLAN_CATALOG["free"]["entitlements"]}
    monthly_codes = {e["feature_code"] for e in PLAN_CATALOG["dev_monthly"]["entitlements"]}
    assert free_codes == monthly_codes, "free and dev_monthly must cover the same feature_codes"


# ── LAUNCH-002: Unknown plan_code ─────────────────────────────────────────────

def test_plan_catalog_unknown_plan_returns_none():
    """LAUNCH-002: get_plan_definition returns None for unknown plan_code."""
    from core.licensing import get_plan_definition

    assert get_plan_definition("enterprise_plus") is None
    assert get_plan_definition("") is None
    assert get_plan_definition("DEVELOPER") is None  # case-sensitive


# ── LAUNCH-003: Free plan defaults seeded ────────────────────────────────────

def test_activate_free_plan_seeds_defaults(make_client):
    """LAUNCH-003: Activating 'free' with no explicit entitlements seeds plan defaults."""
    with make_client() as client:
        resp = _activate(client, plan_code="free")
        assert resp["plan_code"] == "free"
        assert resp["entitlements_added"] == 6  # all 6 feature codes in free plan

        status = client.get("/v1/license", headers=ADMIN).json()
        ents = {e["feature_code"]: e for e in status["entitlements"]}

        # debug_bundle_export is disabled on free plan
        assert "debug_bundle_export" in ents
        assert ents["debug_bundle_export"]["enabled"] is False

        # replay_history_days is 7 on free plan
        assert "replay_history_days" in ents
        assert ents["replay_history_days"]["limit_value"] == 7

        # spend_analytics is disabled on free plan
        assert ents["spend_analytics"]["enabled"] is False


# ── LAUNCH-004: dev_monthly defaults ─────────────────────────────────────────

def test_activate_dev_monthly_seeds_defaults(make_client):
    """LAUNCH-004: Activating 'dev_monthly' seeds debug_bundle_export=True, 6 entitlements."""
    with make_client() as client:
        resp = _activate(client, plan_code="dev_monthly")
        assert resp["entitlements_added"] == 6

        status = client.get("/v1/license", headers=ADMIN).json()
        ents = {e["feature_code"]: e for e in status["entitlements"]}

        assert ents["debug_bundle_export"]["enabled"] is True
        assert ents["replay_history_days"]["limit_value"] == 90
        assert ents["spend_analytics"]["enabled"] is True
        assert ents["advanced_filters"]["enabled"] is True


# ── LAUNCH-005: dev_annual defaults ──────────────────────────────────────────

def test_activate_dev_annual_seeds_same_as_monthly(make_client):
    """LAUNCH-005: dev_annual seeds the same entitlements as dev_monthly."""
    with make_client() as client:
        resp = _activate(client, plan_code="dev_annual")
        assert resp["entitlements_added"] == 6

        status = client.get("/v1/license", headers=ADMIN).json()
        ents = {e["feature_code"]: e for e in status["entitlements"]}

        assert ents["debug_bundle_export"]["enabled"] is True
        assert ents["replay_history_days"]["limit_value"] == 90


# ── LAUNCH-006: Explicit entitlements override plan defaults ─────────────────

def test_activate_explicit_entitlements_override_plan_defaults(make_client):
    """LAUNCH-006: Explicit entitlements list is used as-is; plan defaults are NOT applied."""
    with make_client() as client:
        explicit = [{"feature_code": "debug_bundle_export", "enabled": True}]
        resp = _activate(client, plan_code="dev_monthly", entitlements=explicit)
        assert resp["entitlements_added"] == 1  # only the one explicit row

        status = client.get("/v1/license", headers=ADMIN).json()
        ents = {e["feature_code"]: e for e in status["entitlements"]}

        # Only debug_bundle_export was seeded — no replay_history_days or others
        assert "debug_bundle_export" in ents
        assert "replay_history_days" not in ents
        assert "spend_analytics" not in ents


# ── LAUNCH-007: Unknown plan with no entitlements ────────────────────────────

def test_activate_unknown_plan_no_entitlements_accepted(make_client):
    """LAUNCH-007: Unknown plan_code with no entitlements accepted — no rows seeded."""
    with make_client() as client:
        resp = _activate(client, plan_code="custom_internal_v1")
        assert resp["plan_code"] == "custom_internal_v1"
        assert resp["entitlements_added"] == 0

        status = client.get("/v1/license", headers=ADMIN).json()
        # No entitlement rows → opt-in gating = all features accessible
        assert status["entitlements"] == []
        assert status["unmanaged_mode"] is False


# ── LAUNCH-008: status_message — unmanaged mode ───────────────────────────────

def test_status_message_unmanaged_mode(make_client):
    """LAUNCH-008: GET /v1/license returns status_message for unmanaged mode."""
    with make_client() as client:
        status = client.get("/v1/license", headers=ADMIN).json()
        assert status["unmanaged_mode"] is True
        assert "status_message" in status
        msg = status["status_message"]
        assert "unmanaged" in msg.lower() or "no license" in msg.lower()
        assert "accessible" in msg.lower()


# ── LAUNCH-009: status_message — active license ───────────────────────────────

def test_status_message_active_license(make_client):
    """LAUNCH-009: status_message for an active license names the plan."""
    with make_client() as client:
        _activate(client, plan_code="dev_monthly")
        status = client.get("/v1/license", headers=ADMIN).json()
        msg = status["status_message"]
        assert "active" in msg.lower()
        assert "dev_monthly" in msg


# ── LAUNCH-010: status_message — expired license ──────────────────────────────

def test_status_message_expired_license(make_client):
    """LAUNCH-010: status_message for an expired license describes blocked state."""
    with make_client() as client:
        data = _activate(client, plan_code="dev_monthly")
        client.post("/v1/license/expire", json={"license_id": data["license_id"]}, headers=ADMIN)

        status = client.get("/v1/license", headers=ADMIN).json()
        msg = status["status_message"]
        assert "expired" in msg.lower()
        assert "blocked" in msg.lower() or "reactivate" in msg.lower()


# ── LAUNCH-011: /plans returns all canonical plans ────────────────────────────

def test_plans_endpoint_returns_all_canonical_plans(make_client):
    """LAUNCH-011: GET /v1/license/plans returns all three canonical plan codes."""
    with make_client() as client:
        r = client.get("/v1/license/plans", headers=ADMIN)
        assert r.status_code == 200
        data = r.json()
        assert "plans" in data
        plan_codes = {p["plan_code"] for p in data["plans"]}
        assert "free" in plan_codes
        assert "dev_monthly" in plan_codes
        assert "dev_annual" in plan_codes


# ── LAUNCH-012: /plans entry shape ────────────────────────────────────────────

def test_plans_endpoint_entry_shape(make_client):
    """LAUNCH-012: Each /v1/license/plans entry has plan_code, description, and entitlements."""
    with make_client() as client:
        r = client.get("/v1/license/plans", headers=ADMIN)
        data = r.json()
        for plan in data["plans"]:
            assert "plan_code" in plan
            assert "description" in plan
            assert isinstance(plan["description"], str) and len(plan["description"]) > 0
            assert "entitlements" in plan
            assert isinstance(plan["entitlements"], list)
            assert len(plan["entitlements"]) > 0
            for ent in plan["entitlements"]:
                assert "feature_code" in ent
                assert "enabled" in ent


# ── LAUNCH-013: /plans requires admin token ───────────────────────────────────

def test_plans_endpoint_requires_admin_token(make_client):
    """LAUNCH-013: GET /v1/license/plans returns 401 without admin token."""
    with make_client() as client:
        r = client.get("/v1/license/plans")
        assert r.status_code == 401


# ── LAUNCH-014: Free plan blocks audit/export ─────────────────────────────────

def test_free_plan_blocks_audit_export(make_client):
    """LAUNCH-014: Activating 'free' plan seeds debug_bundle_export=False → 402 on export."""
    with make_client() as client:
        _activate(client, plan_code="free")
        r = client.get("/v1/audit/export?chain_id=zdg-local-chain-01", headers=ADMIN)
        assert r.status_code == 402
        detail = r.json()["detail"]
        assert detail["feature"] == "debug_bundle_export"


# ── LAUNCH-015: dev_monthly plan allows audit/export ─────────────────────────

def test_dev_monthly_plan_allows_audit_export(make_client):
    """LAUNCH-015: Activating 'dev_monthly' seeds debug_bundle_export=True → 200 on export."""
    with make_client() as client:
        _activate(client, plan_code="dev_monthly")
        r = client.get("/v1/audit/export?chain_id=zdg-local-chain-01", headers=ADMIN)
        assert r.status_code == 200
