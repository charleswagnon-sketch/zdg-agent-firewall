# ZDG Agent Firewall — Trial Operations Guide

This guide covers provisioning, support, and lifecycle management for closed external developer trials of ZDG Agent Firewall (FR Developer Edition).

---

## Prerequisites

- Firewall running and reachable (see `docs/QUICKSTART.md`)
- `ZDG_ADMIN_TOKEN` set in your environment
- Shell with `curl` and `jq`

Export your admin token once:

```bash
export ZDG_TOKEN="your-admin-token"
export ZDG_URL="http://localhost:8000"
```

All control-plane calls use `X-ZDG-Admin-Token` — not `Authorization: Bearer`.

---

## 1. Provisioning a Trial

Trial activation is a single call. There is no separate account-creation step; the account is created inline with the license.

### 1.1 Activate a trial license

```bash
curl -s -X POST "$ZDG_URL/v1/license/activate" \
  -H "X-ZDG-Admin-Token: $ZDG_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "dev@acme.example",
    "display_name": "Acme Corp",
    "plan_code": "dev_monthly",
    "entitlements": []
  }' | jq .
```

Passing `"entitlements": []` auto-seeds the plan's default entitlements (recommended for trial provisioning). The response includes `license_id` and `entitlements_added`.

### 1.2 Verify activation

```bash
curl -s "$ZDG_URL/v1/license" \
  -H "X-ZDG-Admin-Token: $ZDG_TOKEN" | jq '{status: .license.status, plan: .license.plan_code, status_message: .status_message}'
```

Expected: `"status": "active"` or `"trialing"`, `"plan_code": "dev_monthly"`.

---

## 2. Inspecting Trial State

### 2.1 Full license status

```bash
curl -s "$ZDG_URL/v1/license" \
  -H "X-ZDG-Admin-Token: $ZDG_TOKEN" | jq .
```

Key fields:
- `license.status` — active | trialing | expired | revoked
- `usage_summary` — monthly runs and exports used/limit/exceeded
- `entitlements` — feature gates and limits in effect
- `status_message` — human-readable summary

### 2.2 Diagnostic support bundle

The support bundle is safe to share with support engineers. It contains no secrets, tokens, or raw agent payloads.

```bash
curl -s "$ZDG_URL/v1/support/bundle" \
  -H "X-ZDG-Admin-Token: $ZDG_TOKEN" | jq .
```

Bundle contents:
- `app` — version, policy bundle ID and version
- `platform` — Python version, OS, arch
- `config_health` — boolean indicators (admin token set, real exec flags, sweep enabled)
- `license` — plan, status, usage summary, status message
- `recent_runs` — count + last 10 attempt IDs (no payloads)
- `trial_feedback` — count of submitted feedback entries

### 2.3 Available plans

```bash
curl -s "$ZDG_URL/v1/license/plans" \
  -H "X-ZDG-Admin-Token: $ZDG_TOKEN" | jq .
```

---

## 3. Collecting Trial Feedback

Trial users can submit structured feedback through the API or you can submit on their behalf.

```bash
curl -s -X POST "$ZDG_URL/v1/support/feedback" \
  -H "X-ZDG-Admin-Token: $ZDG_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "feedback_type": "bug_report",
    "description": "Replay view does not load when attempt_id contains special characters.",
    "context": {
      "attempt_id": "att_abc123",
      "browser": "Chrome 122",
      "steps": ["Open console", "Navigate to Runs", "Click Open on affected row"]
    }
  }' | jq .
```

Valid `feedback_type` values: `bug_report`, `feature_request`, `general`.

Feedback count appears in `GET /v1/support/bundle` under `trial_feedback.count`. Feedback is stored locally in the `trial_feedback` table.

---

## 4. Convenience Script

For common provisioning operations, use `scripts/provision_trial.sh`:

```bash
# Activate a dev_monthly trial (email required; display_name optional)
bash scripts/provision_trial.sh provision dev@acme.example "Acme Corp"

# Get current license status
bash scripts/provision_trial.sh status

# Get support bundle
bash scripts/provision_trial.sh bundle

# Revoke a license
bash scripts/provision_trial.sh revoke <license_id>
```

The script reads `ZDG_TOKEN` and `ZDG_URL` from the environment and sends `X-ZDG-Admin-Token` on every request.

---

## 5. Revoking or Reissuing a License

### 5.1 Revoke

```bash
curl -s -X POST "$ZDG_URL/v1/license/revoke" \
  -H "X-ZDG-Admin-Token: $ZDG_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"license_id": "lic_...", "reason": "Trial ended"}' | jq .
```

After revocation:
- All gated features return HTTP 402
- `max_monthly_runs` and `max_monthly_exports` caps return 0 immediately (expired/revoked → blocked)
- The license record is preserved for audit purposes

### 5.2 Reissue (new license)

Reissuing creates a fresh license. The old license remains revoked.

```bash
curl -s -X POST "$ZDG_URL/v1/license/activate" \
  -H "X-ZDG-Admin-Token: $ZDG_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "dev@acme.example",
    "display_name": "Acme Corp",
    "plan_code": "dev_monthly",
    "entitlements": []
  }' | jq .
```

---

## 6. Known Limitations (FR Dev Edition)

| Limitation | Detail |
|---|---|
| Single-instance only | SQLite backend; no HA or multi-node support |
| Local storage | All data (feedback, audit events, license records) stored in the local SQLite DB |
| No email delivery | Feedback stored locally only; no outbound notifications |
| No self-service portal | All provisioning is done via API or script |
| Monthly windows are calendar-month | Cap counters reset at UTC midnight on the 1st of each month |
| No license renewal UI | Use `POST /v1/license/activate` to reissue a fresh license |
| Unmanaged mode is permissive | If no license is active, all features are accessible with no caps enforced |

---

## 7. Triage Reference

| Symptom | First check |
|---|---|
| Agent gets HTTP 402 on `POST /v1/action` | `GET /v1/license` → check `usage_summary.max_monthly_runs` and license `status` |
| Export blocked with HTTP 402 | `GET /v1/license` → check `usage_summary.max_monthly_exports` and license `status` |
| Agent run returns decision `BLOCK` (HTTP 200) | `GET /v1/audit/runs` → locate attempt → `POST /v1/investigate` with the same payload to trace the block reason |
| Admin endpoint returns HTTP 401 | Check that `X-ZDG-Admin-Token` header is present and correct; `POST /v1/action` does not require this header |
| Policy decision unexpected | `GET /v1/audit/runs` → locate attempt → `GET /v1/audit/replay?attempt_id=...` to inspect the full decision timeline |
| Firewall won't start | Check `ZDG_ADMIN_TOKEN` and `ZDG_CHAIN_ID` are set; check `ZDG_POLICY_BUNDLE_PATH` exists |
| Support triage | `GET /v1/support/bundle` → share bundle JSON (no secrets exposed) |
