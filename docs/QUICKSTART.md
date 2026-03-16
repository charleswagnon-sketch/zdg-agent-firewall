# ZDG Agent Firewall — Developer Quickstart

This guide covers everything needed to go from a fresh clone to a running instance with a governed run, a visible replay, and an active license. It takes about 10 minutes.

---

## 1. Prerequisites

- Python 3.11 or later
- `git`
- A terminal with `curl` (for API examples)

---

## 2. Install

```bash
git clone <repo-url> zdg-agent-firewall
cd zdg-agent-firewall
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## 3. Configure

Copy the example config and set the two required values:

```bash
cp .env.example .env
```

Open `.env` and set:

```bash
ZDG_ADMIN_TOKEN=your-secret-admin-token   # any non-empty string
ZDG_CHAIN_ID=zdg-local-chain-01           # unique ID for this deployment
```

All other defaults work for local development.

---

## 4. Start

```bash
uvicorn api.app:app --host 127.0.0.1 --port 8000
```

Expected startup output:
```
ZDG Agent Firewall started
  Version: 0.1.0
  Policy bundle: local-default-v1 v1.0.0
  DB: /path/to/zdg_firewall.db
  Ruleset hash: sha256:...
```

Verify:
```bash
curl -s http://127.0.0.1:8000/health
# {"status":"ok","version":"0.1.0"}
```

---

## 5. Check license status (initial)

New installations start in **unmanaged mode** — all features accessible, no enforcement. No license is required to start evaluating.

```bash
curl -s http://127.0.0.1:8000/v1/license \
  -H "X-ZDG-Admin-Token: your-secret-admin-token"
```

Response:
```json
{
  "unmanaged_mode": true,
  "status_message": "Unmanaged mode — no license registered. All features accessible.",
  "license": null,
  "plan_definition": null,
  "entitlements": [],
  "installations": []
}
```

---

## 6. Activate a license (optional for evaluation)

You can activate a license at any time. Canonical plan codes:

| Plan code     | Description                                          |
|---------------|------------------------------------------------------|
| `free`        | Local dev and evaluation. Exports and analytics gated. |
| `dev_monthly` | Full feature access. Monthly billing cycle.         |
| `dev_annual`  | Full feature access. Annual billing cycle.          |

> **Warning — activating `free` is more restrictive than unmanaged mode.** In unmanaged mode (no license registered) all features are accessible with no caps. Activating the `free` plan enforces explicit gates: exports are blocked, replay is limited to 7 days, and the monthly run cap is 500. If you are evaluating the product, stay in unmanaged mode or activate `dev_monthly`.

To see all plan definitions and their default entitlements:

```bash
curl -s http://127.0.0.1:8000/v1/license/plans \
  -H "X-ZDG-Admin-Token: your-secret-admin-token"
```

To activate with plan defaults (no explicit entitlements needed):

```bash
curl -s -X POST http://127.0.0.1:8000/v1/license/activate \
  -H "X-ZDG-Admin-Token: your-secret-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "you@example.com",
    "plan_code": "dev_monthly"
  }'
```

Response:
```json
{
  "account_id": "acc_...",
  "license_id": "lic_...",
  "plan_code": "dev_monthly",
  "status": "active",
  "installation_id": null,
  "entitlements_added": 6
}
```

Check status after activation:
```bash
curl -s http://127.0.0.1:8000/v1/license \
  -H "X-ZDG-Admin-Token: your-secret-admin-token"
```

The `status_message` field tells you exactly what state the license is in:
- `"License active — plan 'dev_monthly'. Entitlements enforced per plan."`
- `"License expired — gated features are blocked. Reactivate to restore access."`
- `"License revoked — all gated features are blocked."`

The `usage_summary` field shows your current cap usage for the calendar month:
```json
"usage_summary": {
  "window": "2026-03",
  "max_monthly_runs": { "used": 42, "limit": 10000, "exceeded": false },
  "max_monthly_exports": { "used": 3, "limit": 100, "exceeded": false }
}
```

---

## 7. Create a governed run

Register an agent, then submit an action:

```bash
# Register the agent
curl -s -X POST http://127.0.0.1:8000/v1/agents \
  -H "X-ZDG-Admin-Token: your-secret-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-quickstart-01",
    "agent_type": "assistant",
    "operator": "you@example.com"
  }'

# Submit an action
curl -s -X POST http://127.0.0.1:8000/v1/action \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-quickstart-01",
    "tool_family": "shell",
    "action": "execute",
    "args": {"command": "echo hello"},
    "session_id": "session-quickstart-01"
  }'
```

Response includes `final_decision` (`ALLOW` or `BLOCK`) and `attempt_id`. Save the `attempt_id` for replay.

---

## 8. View the runs index

```bash
curl -s "http://127.0.0.1:8000/v1/audit/runs" \
  -H "X-ZDG-Admin-Token: your-secret-admin-token"
```

Filter by agent:
```bash
curl -s "http://127.0.0.1:8000/v1/audit/runs?agent_id=agent-quickstart-01" \
  -H "X-ZDG-Admin-Token: your-secret-admin-token"
```

Each row has `attempt_id`, `final_decision`, `started_at`, `duration_ms`, and other run metadata.

---

## 9. Open a replay

Using the `attempt_id` from step 7:

```bash
# Snapshot view (human-readable summary)
curl -s "http://127.0.0.1:8000/v1/audit/replay?attempt_id=<attempt_id>" \
  -H "X-ZDG-Admin-Token: your-secret-admin-token"

# Raw event list (canonical evidence with hash fields intact)
curl -s "http://127.0.0.1:8000/v1/audit/replay?attempt_id=<attempt_id>&format=json" \
  -H "X-ZDG-Admin-Token: your-secret-admin-token"
```

The snapshot includes `run_summary`, `timeline` (ordered labeled events), and section summaries for contract, authority, credential, execution, and usage.

---

## 10. Export the audit chain

```bash
curl -s "http://127.0.0.1:8000/v1/audit/export?chain_id=zdg-local-chain-01" \
  -H "X-ZDG-Admin-Token: your-secret-admin-token" > audit_export.json
```

NDJSON format (one event per line):
```bash
curl -s "http://127.0.0.1:8000/v1/audit/export?chain_id=zdg-local-chain-01&format=ndjson" \
  -H "X-ZDG-Admin-Token: your-secret-admin-token"
```

> **Note:** Export requires `debug_bundle_export` entitlement. On `free` plan this feature is disabled. On `dev_monthly`/`dev_annual` or unmanaged mode it is accessible.

---

## 11. Open the console

Navigate to `http://127.0.0.1:8000/dashboard` in your browser.

1. Enter your admin token in the **Credentials** panel.
2. Click **Save access** — data loads automatically.
3. Use the **Runs** station to browse governed runs.
4. Click an `attempt_id` to open the **Replay** station.
5. Use **Replay** to download snapshot or raw JSON.
6. The **License** panel in the sidebar shows your current plan, status, and key entitlements.

---

## 12. Gating reference

When a gated feature is blocked you receive HTTP 402 with a `detail.reason` and `detail.feature` field.

| Feature code           | What it gates                     | free    | dev_monthly | dev_annual |
|------------------------|-----------------------------------|---------|-------------|------------|
| `debug_bundle_export`  | GET /v1/audit/export              | blocked | enabled     | enabled    |
| `replay_history_days`  | GET /v1/audit/replay (retention)  | 7 days  | 90 days     | 90 days    |
| `max_monthly_runs`     | POST /v1/action monthly cap       | 500     | 10,000      | 10,000     |
| `max_monthly_exports`  | GET /v1/audit/export monthly cap  | 0       | 100         | 100        |
| `spend_analytics`      | Informational                     | blocked | enabled     | enabled    |
| `advanced_filters`     | Informational                     | blocked | enabled     | enabled    |

`replay_history_days` is age-enforced server-side. Attempts older than the configured window return HTTP 402. A `limit_value` of 0 blocks all replay (used when a license is expired or revoked).

**Unmanaged mode** (no license registered): all features accessible, no limits enforced, no retention window.

Example 402 response:
```json
{
  "detail": {
    "reason": "Feature 'debug_bundle_export' not accessible: feature_disabled",
    "feature": "debug_bundle_export"
  }
}
```

---

## 13. Known limitations and current boundaries

- **Single-tenant only.** One installation per deployment. No org/team management.
- **SQLite backend.** Not designed for concurrent multi-process writes. Fine for local dev and single-server deployments.
- **Stripe billing optional.** Billing integration is available via `STRIPE_*` environment variables. When not configured, billing routes return HTTP 503. License state (activation, expiry, entitlements) is managed locally via the admin API regardless of whether Stripe is configured.
- **`max_monthly_runs` and `max_monthly_exports` are enforced.** When the cap is exceeded, subsequent requests return HTTP 402 with `detail.feature` identifying the cap. Cap-exceeded run submissions do not create a ToolAttempt (the counter stays clean). Export usage is tracked per calendar month.
- **Contract sweep is off by default.** Set `ZDG_CONTRACT_EXPIRY_SWEEP_INTERVAL_SECONDS` > 0 to enable background contract expiry.
- **Real execution is off by default.** All executor gates (`ZDG_REAL_EXEC`, `ZDG_REAL_EXEC_*`) are `false` by default. Actions go through the governance pipeline but are not dispatched to real systems unless you enable the relevant gate.

---

## Next steps

- See `POST /v1/action` in the interactive API docs (`http://127.0.0.1:8000/docs`) for full payload schema.
- Use `POST /v1/investigate` to dry-run policy evaluation without creating a governed run.
