"""
RUN-CONSOLE-01 — Developer-facing Run Console integration tests.

Covers the /run-console route, asset serving, and the end-to-end flows
the console JS depends on:

  RC-001  /run-console serves the HTML shell with correct landmarks
  RC-002  /dashboard-assets/run_console.js is served as JavaScript
  RC-003  Submit → replay round-trip: POST /v1/action → GET /v1/audit/replay returns
          a shaped artifact with timeline, run_summary, and execution_summary
  RC-004  ALLOW run replay (snapshot format) has ACTION_ATTEMPTED and ACTION_ALLOWED
  RC-005  BLOCK run replay has ACTION_BLOCKED event with a reason
  RC-006  Replay format=json returns the raw audit event list (events key)
  RC-007  Runs index returns rows usable by the sidebar (attempt_id, final_decision,
          tool_family, action, agent_id, started_at)
  RC-008  Replay of an unknown attempt_id returns 404
  RC-009  Export strip: snapshot and raw JSON are both available for the same attempt
  RC-010  Evaluation mode: run console submit still works within the 25-run cap

Polish pass (UX improvements, no API changes):
  RC-011  Mock execution output is present in execution_summary for ALLOW runs
  RC-012  BLOCK run execution_summary has executed=False (not-executed state)
  RC-013  JS asset contains copy-confirmation feedback code
"""

from __future__ import annotations

ADMIN = {"X-ZDG-Admin-Token": "integration-admin-token"}


# ── RC-001: HTML shell ────────────────────────────────────────────────────────

def test_run_console_shell(make_client):
    """GET /run-console returns the Run Console HTML with required landmarks."""
    with make_client() as client:
        res = client.get("/run-console")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    html = res.text
    assert "Run Console" in html
    assert "run_console.js" in html
    assert "rc-submit-form" in html
    assert "rc-timeline-list" in html
    assert "rc-runs-list" in html


# ── RC-002: JS asset ──────────────────────────────────────────────────────────

def test_run_console_js_asset(make_client):
    """run_console.js is served as JavaScript from /dashboard-assets/."""
    with make_client() as client:
        res = client.get("/dashboard-assets/run_console.js")
    assert res.status_code == 200
    assert "javascript" in res.headers["content-type"]
    assert "submitAction" in res.text
    assert "loadReplay" in res.text
    assert "renderTimeline" in res.text


# ── RC-003: submit → replay round-trip ───────────────────────────────────────

def test_submit_and_replay_round_trip(make_client):
    """POST /v1/action followed by GET /v1/audit/replay returns a shaped artifact."""
    with make_client() as client:
        action_res = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-rc-01",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo rc-test"},
            },
        )
        assert action_res.status_code == 200
        attempt_id = action_res.json()["attempt_id"]
        assert attempt_id

        # Snapshot format (no format=json) — used by the console for display
        replay_res = client.get(
            f"/v1/audit/replay?attempt_id={attempt_id}",
            headers=ADMIN,
        )
    assert replay_res.status_code == 200
    replay = replay_res.json()

    assert "run_summary" in replay
    assert "timeline" in replay
    assert "execution_summary" in replay
    assert replay["attempt_id"] == attempt_id

    summary = replay["run_summary"]
    assert summary["tool_family"] == "shell"
    assert summary["action"] == "execute"
    assert summary["agent_id"] == "agent-rc-01"
    assert summary["final_decision"] in ("ALLOW", "BLOCK", "APPROVAL_REQUIRED")


# ── RC-004: ALLOW run timeline ────────────────────────────────────────────────

def test_allow_run_timeline_events(make_client):
    """ALLOW run replay (snapshot) has ACTION_ATTEMPTED and ACTION_ALLOWED in timeline."""
    with make_client() as client:
        res = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-rc-allow",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo allow"},
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["decision"] == "ALLOW"
        attempt_id = body["attempt_id"]

        # Snapshot format — used by JS console timeline display
        replay_res = client.get(
            f"/v1/audit/replay?attempt_id={attempt_id}",
            headers=ADMIN,
        )
    assert replay_res.status_code == 200
    timeline = replay_res.json()["timeline"]
    event_types = [e["event_type"] for e in timeline]

    assert "ACTION_ATTEMPTED" in event_types
    assert "ACTION_ALLOWED" in event_types

    # Each timeline event has required fields for the console
    for ev in timeline:
        assert "seq" in ev
        assert "event_type" in ev
        assert "label" in ev
        assert "created_at" in ev
        assert "event_payload" in ev


# ── RC-005: BLOCK run timeline ────────────────────────────────────────────────

def test_block_run_timeline_has_blocked_event(make_client):
    """BLOCK run replay has ACTION_BLOCKED event with a reason_code in payload."""
    with make_client() as client:
        # Submit to an unregistered tool family to trigger a policy block
        res = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-rc-block",
                "tool_family": "unknown_tool_xyz",
                "action": "execute",
                "args": {},
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["decision"] == "BLOCK"
        attempt_id = body["attempt_id"]

        replay_res = client.get(
            f"/v1/audit/replay?attempt_id={attempt_id}",
            headers=ADMIN,
        )
    assert replay_res.status_code == 200
    replay = replay_res.json()
    event_types = [e["event_type"] for e in replay["timeline"]]

    # The run was blocked — run_summary confirms the decision
    assert replay["run_summary"]["final_decision"] == "BLOCK"
    assert replay["run_summary"].get("terminal_reason_code")

    # At least one event in the timeline signals the block path
    block_signals = {"ACTION_BLOCKED", "UNREGISTERED_TOOL_FAMILY", "EXPLICIT_DENY"}
    assert block_signals & set(event_types), f"No block signal event in {event_types}"


# ── RC-006: raw format=json returns raw audit events ──────────────────────────

def test_replay_raw_json_format(make_client):
    """GET /v1/audit/replay?format=json returns the raw audit event list."""
    with make_client() as client:
        res = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-rc-raw",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo raw"},
            },
        )
        attempt_id = res.json()["attempt_id"]

        raw_res = client.get(
            f"/v1/audit/replay?attempt_id={attempt_id}&format=json",
            headers=ADMIN,
        )
        snap_res = client.get(
            f"/v1/audit/replay?attempt_id={attempt_id}",
            headers=ADMIN,
        )

    assert raw_res.status_code == 200
    assert snap_res.status_code == 200

    raw = raw_res.json()
    snap = snap_res.json()

    # Both share the same attempt_id
    assert raw["attempt_id"] == snap["attempt_id"] == attempt_id

    # Raw format: event list in "events" key
    assert "events" in raw
    assert isinstance(raw["events"], list)
    assert raw["event_count"] == len(raw["events"])

    # Snapshot format: structured summary with timeline
    assert "timeline" in snap
    assert "run_summary" in snap


# ── RC-007: runs index sidebar shape ─────────────────────────────────────────

def test_runs_index_sidebar_shape(make_client):
    """GET /v1/audit/runs returns rows in data["runs"] with fields used by the sidebar."""
    with make_client() as client:
        client.post(
            "/v1/action",
            json={
                "agent_id": "agent-rc-sidebar",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo sidebar"},
            },
        )
        res = client.get("/v1/audit/runs?agent_id=agent-rc-sidebar", headers=ADMIN)

    assert res.status_code == 200
    data = res.json()
    assert "runs" in data
    assert data["count"] >= 1

    row = data["runs"][0]
    for field in ("attempt_id", "final_decision", "tool_family", "action", "agent_id", "started_at"):
        assert field in row, f"Missing field: {field}"


# ── RC-008: unknown attempt_id → 404 ─────────────────────────────────────────

def test_replay_unknown_attempt_id_returns_404(make_client):
    """Replay of a nonexistent attempt_id returns HTTP 404."""
    with make_client() as client:
        res = client.get(
            "/v1/audit/replay?attempt_id=att_does_not_exist_00000&format=json",
            headers=ADMIN,
        )
    assert res.status_code == 404


# ── RC-009: snapshot and raw both available for the same attempt ──────────────

def test_export_snapshot_and_raw_same_attempt(make_client):
    """Snapshot and raw replay exports are both available for the same attempt."""
    with make_client() as client:
        res = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-rc-export",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo export"},
            },
        )
        attempt_id = res.json()["attempt_id"]

        snap = client.get(f"/v1/audit/replay?attempt_id={attempt_id}", headers=ADMIN).json()
        raw  = client.get(f"/v1/audit/replay?attempt_id={attempt_id}&format=json", headers=ADMIN).json()

    assert snap["attempt_id"] == attempt_id
    assert raw["attempt_id"] == attempt_id
    assert isinstance(snap["timeline"], list)
    assert isinstance(raw["events"], list)


# ── RC-010: evaluation mode submit works within cap ───────────────────────────

def test_evaluation_mode_run_console_submit_works(make_client):
    """Evaluation mode (no license) allows run console submits within the 25-run cap."""
    with make_client() as client:
        # Evaluation mode is the default — no license activation
        res = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-rc-eval",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo eval"},
            },
        )
    assert res.status_code == 200
    body = res.json()
    assert "decision" in body
    assert "attempt_id" in body


# ── RC-011: mock output_summary present in execution_summary ──────────────────

def test_allow_run_mock_output_summary_present(make_client):
    """ALLOW mock run: execution_summary.output_summary is non-empty.

    The console renders this as the prominent 'Mock execution output' card.
    Confirms the data contract the JS relies on is satisfied.
    """
    with make_client() as client:
        res = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-rc-mock-out",
                "tool_family": "shell",
                "action": "execute",
                "args": {"command": "echo hello-mock"},
            },
        )
        assert res.status_code == 200
        attempt_id = res.json()["attempt_id"]

        replay_res = client.get(
            f"/v1/audit/replay?attempt_id={attempt_id}",
            headers=ADMIN,
        )

    assert replay_res.status_code == 200
    replay = replay_res.json()
    exec_s = replay["execution_summary"]

    assert exec_s["executed"] is False
    assert exec_s["mock"] is True
    assert exec_s["output_summary"], "output_summary must be non-empty for mock runs"
    assert exec_s["execution_status"] == "mock_success"


# ── RC-012: BLOCK run has executed=False ──────────────────────────────────────

def test_block_run_not_executed(make_client):
    """BLOCK run: execution_summary.executed is False.

    The console shows the 'Not executed' card when decision=BLOCK and executed=False.
    """
    with make_client() as client:
        res = client.post(
            "/v1/action",
            json={
                "agent_id": "agent-rc-block-exec",
                "tool_family": "unknown_xyz",
                "action": "execute",
                "args": {},
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["decision"] == "BLOCK"
        attempt_id = body["attempt_id"]

        replay_res = client.get(
            f"/v1/audit/replay?attempt_id={attempt_id}",
            headers=ADMIN,
        )

    assert replay_res.status_code == 200
    replay = replay_res.json()
    exec_s = replay["execution_summary"]

    assert exec_s["executed"] is False, "Blocked run must not be executed"
    assert replay["run_summary"]["final_decision"] == "BLOCK"
    assert replay["run_summary"]["terminal_reason_code"]


# ── RC-013: JS asset contains copy-confirmation code ─────────────────────────

def test_js_asset_contains_copy_confirmation(make_client):
    """run_console.js contains copy-confirmation feedback for the Copy summary button."""
    with make_client() as client:
        res = client.get("/dashboard-assets/run_console.js")

    assert res.status_code == 200
    js = res.text
    # Confirmation feedback markers
    assert "Copied" in js
    assert "rc-copy-summary" in js
