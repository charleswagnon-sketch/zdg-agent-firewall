"""
FRDEV-LIMITS-01 — Runtime entitlement cap enforcement suite.

Tests that max_monthly_runs and max_monthly_exports caps are truly enforced,
that denial messages are clear, that usage_summary is accurate, and that the
existing unmanaged/expired/revoked semantics are preserved.

Test coverage:
  LIMITS-001  Unmanaged mode — runs cap not enforced (can submit unlimited runs)
  LIMITS-002  Evaluation mode — exports blocked (limit=0); usage_summary shows evaluation limits
  LIMITS-003  Active license, limit_value=2 runs → 3rd run returns 402
  LIMITS-004  402 detail includes feature='max_monthly_runs' and reason string
  LIMITS-005  Runs below cap proceed normally (decision field present)
  LIMITS-006  Cap-exceeded requests do not increment the ToolAttempt counter
  LIMITS-007  After cap hit: license/usage_summary shows exceeded=True
  LIMITS-008  Expired license — runs blocked immediately (limit=0)
  LIMITS-009  Revoked license — runs blocked immediately (limit=0)
  LIMITS-010  Export cap enforced: 3rd export blocked when limit_value=2
  LIMITS-011  Export 402 detail has feature='max_monthly_exports'
  LIMITS-012  Export usage recorded: usage_summary.max_monthly_exports.used increments
  LIMITS-013  Evaluation mode — exports blocked (max_monthly_exports=0), never succeed without a license
  LIMITS-014  dev_monthly plan — full entitlement set; runs and exports work
  LIMITS-015  usage_summary.window is current calendar month (YYYY-MM format)
  LIMITS-016  free plan — max_monthly_exports=0, blocked even with debug_bundle_export enabled override
"""
from __future__ import annotations

ADMIN = {"X-ZDG-Admin-Token": "integration-admin-token"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _activate(client, *, email="dev@example.com", plan_code="dev_monthly", status="active",
              entitlements=None, **kwargs):
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


def _submit(client, *, agent_id="agent-limits-test", expect_200=True):
    """Submit a governed run. Returns the full response."""
    r = client.post(
        "/v1/action",
        json={
            "agent_id": agent_id,
            "tool_family": "shell",
            "action": "execute",
            "args": {"command": "echo cap-test"},
        },
    )
    if expect_200:
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
    return r


def _export(client, expect_200=True):
    """Call audit/export. Returns the full response."""
    r = client.get("/v1/audit/export?chain_id=zdg-local-chain-01", headers=ADMIN)
    if expect_200:
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
    return r


def _usage(client):
    """Fetch usage_summary from GET /v1/license."""
    r = client.get("/v1/license", headers=ADMIN)
    assert r.status_code == 200
    return r.json().get("usage_summary", {})


# ── LIMITS-001: Unmanaged runs unlimited ──────────────────────────────────────

def test_unmanaged_mode_runs_not_capped(make_client):
    """LIMITS-001: No license registered → runs cap never fires."""
    with make_client() as client:
        status = client.get("/v1/license", headers=ADMIN).json()
        assert status["unmanaged_mode"] is True

        # Submit several runs — none should be blocked by a cap
        for _ in range(3):
            r = _submit(client)
            assert r.json()["decision"] in ("ALLOW", "BLOCK")  # policy, not quota


# ── LIMITS-002: Evaluation mode — exports blocked, usage_summary shows limits ──

def test_unmanaged_mode_exports_and_usage_summary(make_client):
    """LIMITS-002: Evaluation mode — exports blocked; usage_summary shows evaluation limits."""
    with make_client() as client:
        _submit(client)
        _submit(client)

        # Export must be blocked in evaluation mode (max_monthly_exports=0)
        r = _export(client, expect_200=False)
        assert r.status_code == 402

        status = client.get("/v1/license", headers=ADMIN).json()
        assert status["unmanaged_mode"] is True
        usage = status["usage_summary"]
        assert "window" in usage
        # Runs are counted and limit is the evaluation cap (not None)
        assert usage["max_monthly_runs"]["used"] >= 2
        assert usage["max_monthly_runs"]["limit"] == 25
        assert usage["max_monthly_runs"]["exceeded"] is False
        # Exports: evaluation mode → limit=0 (always blocked)
        assert usage["max_monthly_exports"]["limit"] == 0
        assert usage["max_monthly_exports"]["exceeded"] is False


# ── LIMITS-003: Runs cap enforced ────────────────────────────────────────────

def test_runs_cap_enforced_at_limit(make_client):
    """LIMITS-003: limit_value=2 for max_monthly_runs → 3rd run returns 402."""
    with make_client() as client:
        _activate(client, entitlements=[
            {"feature_code": "max_monthly_runs", "enabled": True, "limit_value": 2},
        ])
        _submit(client)  # run 1 — ok
        _submit(client)  # run 2 — ok
        r = _submit(client, expect_200=False)  # run 3 — blocked
        assert r.status_code == 402


# ── LIMITS-004: 402 detail shape ─────────────────────────────────────────────

def test_runs_cap_402_detail_shape(make_client):
    """LIMITS-004: 402 detail has feature='max_monthly_runs' and readable reason."""
    with make_client() as client:
        _activate(client, entitlements=[
            {"feature_code": "max_monthly_runs", "enabled": True, "limit_value": 1},
        ])
        _submit(client)  # consumes the limit
        r = _submit(client, expect_200=False)
        assert r.status_code == 402
        detail = r.json()["detail"]
        assert detail["feature"] == "max_monthly_runs"
        assert "max_monthly_runs" in detail["reason"]
        # reason string encodes used/limit context
        assert "1/1" in detail["reason"]


# ── LIMITS-005: Runs below cap succeed ───────────────────────────────────────

def test_runs_below_cap_succeed(make_client):
    """LIMITS-005: Runs below the cap proceed with normal decision fields."""
    with make_client() as client:
        _activate(client, entitlements=[
            {"feature_code": "max_monthly_runs", "enabled": True, "limit_value": 5},
        ])
        for _ in range(3):
            r = _submit(client)
            data = r.json()
            assert "decision" in data
            assert "attempt_id" in data


# ── LIMITS-006: Cap-exceeded requests don't increment counter ─────────────────

def test_runs_cap_exceeded_does_not_increment_counter(make_client):
    """LIMITS-006: Runs blocked by cap (402) do not create a ToolAttempt."""
    with make_client() as client:
        _activate(client, entitlements=[
            {"feature_code": "max_monthly_runs", "enabled": True, "limit_value": 2},
        ])
        _submit(client)  # run 1
        _submit(client)  # run 2 — hits limit

        # These extra submissions are all blocked by the cap
        for _ in range(3):
            r = _submit(client, expect_200=False)
            assert r.status_code == 402

        # The runs index should show exactly 2 runs (the successful ones)
        runs = client.get("/v1/audit/runs", headers=ADMIN).json()
        assert runs["count"] == 2


# ── LIMITS-007: usage_summary exceeded=True when cap hit ─────────────────────

def test_usage_summary_exceeded_true_when_cap_hit(make_client):
    """LIMITS-007: After hitting the cap, usage_summary shows exceeded=True."""
    with make_client() as client:
        _activate(client, entitlements=[
            {"feature_code": "max_monthly_runs", "enabled": True, "limit_value": 2},
        ])
        _submit(client)
        _submit(client)
        # Hit the cap
        _submit(client, expect_200=False)

        usage = _usage(client)
        runs_info = usage["max_monthly_runs"]
        assert runs_info["used"] == 2
        assert runs_info["limit"] == 2
        assert runs_info["exceeded"] is True


# ── LIMITS-008: Expired license → runs blocked ───────────────────────────────

def test_expired_license_blocks_runs(make_client):
    """LIMITS-008: Expired license → get_feature_limit returns 0 → 402 immediately."""
    with make_client() as client:
        data = _activate(client, plan_code="dev_monthly")
        client.post(
            "/v1/license/expire",
            json={"license_id": data["license_id"]},
            headers=ADMIN,
        )
        r = _submit(client, expect_200=False)
        assert r.status_code == 402
        assert r.json()["detail"]["feature"] == "max_monthly_runs"


# ── LIMITS-009: Revoked license → runs blocked ───────────────────────────────

def test_revoked_license_blocks_runs(make_client):
    """LIMITS-009: Revoked license → 402 on runs."""
    with make_client() as client:
        data = _activate(client, plan_code="dev_monthly")
        client.post(
            "/v1/license/revoke",
            json={"license_id": data["license_id"], "reason": "limits-test"},
            headers=ADMIN,
        )
        r = _submit(client, expect_200=False)
        assert r.status_code == 402
        assert r.json()["detail"]["feature"] == "max_monthly_runs"


# ── LIMITS-010: Export cap enforced ──────────────────────────────────────────

def test_export_cap_enforced_at_limit(make_client):
    """LIMITS-010: limit_value=2 for max_monthly_exports → 3rd export returns 402."""
    with make_client() as client:
        _activate(client, entitlements=[
            {"feature_code": "debug_bundle_export",  "enabled": True,  "limit_value": None},
            {"feature_code": "max_monthly_exports",  "enabled": True,  "limit_value": 2},
        ])
        _export(client)  # export 1
        _export(client)  # export 2
        r = _export(client, expect_200=False)  # export 3 — blocked
        assert r.status_code == 402


# ── LIMITS-011: Export 402 detail shape ──────────────────────────────────────

def test_export_cap_402_detail_shape(make_client):
    """LIMITS-011: Export 402 detail has feature='max_monthly_exports' and reason."""
    with make_client() as client:
        _activate(client, entitlements=[
            {"feature_code": "debug_bundle_export",  "enabled": True,  "limit_value": None},
            {"feature_code": "max_monthly_exports",  "enabled": True,  "limit_value": 1},
        ])
        _export(client)  # consumes the 1 allowed export
        r = _export(client, expect_200=False)
        assert r.status_code == 402
        detail = r.json()["detail"]
        assert detail["feature"] == "max_monthly_exports"
        assert "max_monthly_exports" in detail["reason"]


# ── LIMITS-012: Export usage recorded in usage_summary ───────────────────────

def test_export_usage_recorded_in_usage_summary(make_client):
    """LIMITS-012: Each successful export increments usage_summary.max_monthly_exports.used."""
    with make_client() as client:
        _activate(client, entitlements=[
            {"feature_code": "debug_bundle_export",  "enabled": True,  "limit_value": None},
            {"feature_code": "max_monthly_exports",  "enabled": True,  "limit_value": 10},
        ])
        assert _usage(client)["max_monthly_exports"]["used"] == 0

        _export(client)
        assert _usage(client)["max_monthly_exports"]["used"] == 1

        _export(client)
        assert _usage(client)["max_monthly_exports"]["used"] == 2

        usage = _usage(client)
        assert usage["max_monthly_exports"]["exceeded"] is False
        assert usage["max_monthly_exports"]["limit"] == 10


# ── LIMITS-013: Evaluation mode exports — always blocked ──────────────────────

def test_unmanaged_exports_unlimited(make_client):
    """LIMITS-013: No license (evaluation mode) → exports always blocked (max_monthly_exports=0)."""
    with make_client() as client:
        status = client.get("/v1/license", headers=ADMIN).json()
        assert status["unmanaged_mode"] is True

        # All export attempts must return 402 in evaluation mode
        for _ in range(3):
            r = _export(client, expect_200=False)
            assert r.status_code == 402
            assert r.json()["detail"]["feature"] == "max_monthly_exports"

        usage = _usage(client)
        assert usage["max_monthly_exports"]["limit"] == 0
        assert usage["max_monthly_exports"]["exceeded"] is False


# ── LIMITS-014: dev_monthly plan full entitlements ───────────────────────────

def test_dev_monthly_plan_runs_and_exports_work(make_client):
    """LIMITS-014: dev_monthly plan — well within default caps, no blocking."""
    with make_client() as client:
        _activate(client, plan_code="dev_monthly")

        for _ in range(5):
            _submit(client)
        for _ in range(3):
            _export(client)

        usage = _usage(client)
        assert usage["max_monthly_runs"]["used"] == 5
        assert usage["max_monthly_runs"]["limit"] == 10_000
        assert usage["max_monthly_runs"]["exceeded"] is False
        assert usage["max_monthly_exports"]["used"] == 3
        assert usage["max_monthly_exports"]["limit"] == 100
        assert usage["max_monthly_exports"]["exceeded"] is False


# ── LIMITS-015: usage_summary.window format ──────────────────────────────────

def test_usage_summary_window_format(make_client):
    """LIMITS-015: usage_summary.window is current calendar month in YYYY-MM format."""
    import re
    from datetime import datetime, timezone

    with make_client() as client:
        usage = _usage(client)
        window = usage.get("window", "")
        assert re.match(r"^\d{4}-\d{2}$", window), f"unexpected window format: {window!r}"
        expected = datetime.now(timezone.utc).strftime("%Y-%m")
        assert window == expected


# ── LIMITS-016: free plan max_monthly_exports=0 blocks exports ────────────────

def test_free_plan_export_cap_zero_blocks_exports(make_client):
    """LIMITS-016: free plan seeds max_monthly_exports=0 — exports blocked (0 cap)."""
    with make_client() as client:
        # Activate free plan then manually override debug_bundle_export to True
        # so we can isolate the max_monthly_exports=0 gate specifically.
        # (Normally free plan has debug_bundle_export=False which also blocks exports,
        # but we test the cap gate here explicitly.)
        _activate(client, entitlements=[
            {"feature_code": "debug_bundle_export",  "enabled": True,  "limit_value": None},
            {"feature_code": "max_monthly_exports",  "enabled": True,  "limit_value": 0},
        ])
        r = _export(client, expect_200=False)
        assert r.status_code == 402
        assert r.json()["detail"]["feature"] == "max_monthly_exports"
