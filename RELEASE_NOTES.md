# Release Notes

## v0.1.0-rc3 — 2026-03-16

Third public release candidate of **ZDG-FR Developer Edition**.

### What changed

**Evaluation mode replaces permissive unmanaged mode**

If no license is activated, ZDG-FR now runs in evaluation mode instead of allowing unrestricted feature access.

Evaluation mode limits:
- 25 runs per month
- 3-day replay retention
- 0 exports
- advanced filters disabled
- spend analytics disabled

**Commercial ladder is now coherent**

- Evaluation < Free < dev_monthly / dev_annual

First run still works without license activation. Free is now more capable than evaluation mode. Paid tiers remain the full developer path.

### Runtime impact

Real behavior change for installs with no active license:
- previous behavior: permissive unmanaged mode (all features accessible, no caps)
- new behavior: restricted evaluation mode (25 runs/month, 3-day replay, no exports)

Free and paid plans are unaffected.

### Smoke test result

Evaluation/free/paid ladder verified directly: 8 passed, 0 failed.

| Tier | Coverage |
|---|---|
| Evaluation (no license) | gate points, status shape, runs accessible, exports blocked |
| Free | export cap=0 blocks |
| dev_monthly | runs and exports work |
| Active licensed mode | ungated feature access |

### Test suite

424 passed, 6 pre-existing failures, 0 new regressions.

The 6 remaining failures are pre-existing real-execution / credential-trace issues (`test_cred_trace01.py` ×4, `test_phase2c*.py` ×2) and are not introduced by rc3.

### Known limitations

- Single-node SQLite. Not suitable for high write concurrency or multi-node federation.
- `/v1/action` is unauthenticated. Place behind a reverse proxy with auth for any internet-facing deployment.
- Real execution runs locally on the server host. Review wrapper safety settings before enabling.
- 6 integration tests (`test_cred_trace01.py`, `test_phase2c*.py`) require `ZDG_REAL_EXEC=true` and are expected to skip/fail in default configuration.

---

## v0.1.0-rc2 — 2026-03-16

Second public release candidate of **ZDG-FR Developer Edition**.

### What changed

- Fixed the README clone URL to point to the actual public repository:
  - from: `https://github.com/zero-day-governance/zdg-agent-firewall`
  - to: `https://github.com/charleswagnon-sketch/zdg-agent-firewall`
- `docs/TRIAL_OPS.md` — public-facing wording pass: product name aligned to ZDG-FR Developer Edition, limitations table reframed, triage row tightened.

### Runtime impact

None. No code changes, no API changes, no behavior changes, no plan or licensing changes.

### Smoke test result

Fresh-clone smoke test passed: clone, venv create, install requirements, `.env.example` flow, app startup, `/health`, `/dashboard`, `/docs`, ALLOW run, replay, export.

### Test suite

423 passed, 6 pre-existing real-execution failures, 0 unexpected failures.

### Known limitations

- Single-node SQLite. Not suitable for high write concurrency or multi-node federation.
- `/v1/action` is unauthenticated. Place behind a reverse proxy with auth for any internet-facing deployment.
- Real execution runs locally on the server host. Review wrapper safety settings before enabling.
- 6 integration tests (`test_cred_trace01.py`, `test_phase2c*.py`) require `ZDG_REAL_EXEC=true` and are expected to skip/fail in default configuration.

---

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
- Evaluation mode (no license activated) — limited access; see rc3 for enforced limits

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
