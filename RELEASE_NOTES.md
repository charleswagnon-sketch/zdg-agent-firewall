# Release Notes

## v0.1.0-rc1 — 2026-03-16

First public release candidate of **ZDG-FR Developer Edition**.

### What's included

**Governed execution layer**
- `POST /v1/action` — policy evaluation, risk scoring, lifecycle gating, and audit logging for every agent action
- Four tool families: `shell`, `filesystem`, `http`, `messaging` — all mocked by default, real execution opt-in per family
- Tamper-evident, hash-linked audit chain for every run

**Replay and audit**
- `GET /v1/audit/replay` — structured snapshot with decision timeline, authority, contract, guardrail, and execution summaries
- `GET /v1/audit/replay?format=json` — raw event export with full hash integrity fields
- `GET /v1/audit/runs` — paginated run index with filtering by agent, session, tool family, and decision
- `GET /v1/audit/export` — full chain export in JSON or NDJSON
- `POST /v1/audit/verify` / `POST /v1/audit/diff` — portable chain verification and comparison

**Developer console**
- Build-free dashboard at `/dashboard` — runs index, replay viewer, investigate panel, audit export, admin controls
- Runs table with decision tone, reason labels, and whole-row click to open replay
- Replay hero strip with decision, reason, tool, and duration; secondary cards in compact grid
- Timeline payload disclosure with de-emphasized collapsed state

**Control plane**
- Kill switch (global, agent, tool family, session scope)
- Policy hot reload with candidate validation
- Approval flow — request, resolve, one-time consume
- Agent and session lifecycle (register, suspend, unsuspend, close, deregister)
- `POST /v1/investigate` — dry-run policy evaluation, no audit writes

**Licensing**
- Plan catalog: `free`, `dev_monthly`, `dev_annual`
- Entitlement gating: `replay_history_days`, `max_monthly_runs`, `max_monthly_exports`, `debug_bundle_export`, `spend_analytics`, `advanced_filters`
- Unmanaged mode (no license activated) — all features accessible

**Ops tooling**
- `cli/validate_config.py` — startup configuration validator
- `cli/db_backup.py` — export and restore
- `demos/run_demo.py` — scenario runner
- `Dockerfile`, `docker-compose.yml`, systemd service unit, Caddyfile

### Known limitations

- Single-node SQLite. Not suitable for high write concurrency or multi-node federation.
- `/v1/action` is unauthenticated. Place behind a reverse proxy with auth for any internet-facing deployment.
- Real execution runs locally on the server host. Review wrapper safety settings before enabling.
- 6 integration tests (`test_cred_trace01.py`, `test_phase2c*.py`) require `ZDG_REAL_EXEC=true` and are expected to skip/fail in default configuration.

### Test suite

423 passed, 6 pre-existing failures (real-exec gated), 0 unexpected failures.
