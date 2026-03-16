#!/usr/bin/env bash
# scripts/provision_trial.sh — ZDG Agent Firewall trial provisioning helper
#
# Usage:
#   provision_trial.sh provision <contact_email> [display_name] [plan_code]
#   provision_trial.sh status
#   provision_trial.sh bundle
#   provision_trial.sh revoke <license_id> [reason]
#   provision_trial.sh plans
#
# Environment:
#   ZDG_TOKEN  — admin token (required); passed as X-ZDG-Admin-Token header
#   ZDG_URL    — base URL, default http://localhost:8000
#
# Examples:
#   ZDG_TOKEN=mytoken bash scripts/provision_trial.sh provision dev@acme.example "Acme Corp"
#   ZDG_TOKEN=mytoken bash scripts/provision_trial.sh status
#   ZDG_TOKEN=mytoken bash scripts/provision_trial.sh bundle
#   ZDG_TOKEN=mytoken bash scripts/provision_trial.sh revoke lic_abc123

set -euo pipefail

ZDG_URL="${ZDG_URL:-http://localhost:8000}"
ZDG_TOKEN="${ZDG_TOKEN:-}"

if [[ -z "$ZDG_TOKEN" ]]; then
  echo "ERROR: ZDG_TOKEN is not set." >&2
  exit 1
fi

AUTH_HEADER="X-ZDG-Admin-Token: $ZDG_TOKEN"
CONTENT_HEADER="Content-Type: application/json"

_get() {
  curl -s -f -H "$AUTH_HEADER" "$ZDG_URL$1"
}

_post() {
  local path="$1"
  local body="$2"
  curl -s -f -X POST -H "$AUTH_HEADER" -H "$CONTENT_HEADER" -d "$body" "$ZDG_URL$path"
}

cmd="${1:-help}"

case "$cmd" in
  provision)
    contact_email="${2:-}"
    display_name="${3:-}"
    plan_code="${4:-dev_monthly}"

    if [[ -z "$contact_email" ]]; then
      echo "Usage: provision_trial.sh provision <contact_email> [display_name] [plan_code]" >&2
      exit 1
    fi

    echo "==> Activating $plan_code license for <$contact_email>..."
    license_resp=$(_post "/v1/license/activate" \
      "{\"email\": $(printf '%s' "$contact_email" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'), \
        \"display_name\": $(printf '%s' "$display_name" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'), \
        \"plan_code\": $(printf '%s' "$plan_code" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'), \
        \"entitlements\": []}")

    license_id=$(echo "$license_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["license_id"])')
    entitlements=$(echo "$license_resp" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("entitlements_added", 0))')
    echo "    license_id:        $license_id"
    echo "    entitlements_added: $entitlements"

    echo ""
    echo "==> Verifying status..."
    _get "/v1/license" | python3 -c '
import json, sys
d = json.load(sys.stdin)
lic = d.get("license") or {}
print(f"    status:  {lic.get(\"status\", \"-\")}")
print(f"    plan:    {lic.get(\"plan_code\", \"-\")}")
print(f"    message: {d.get(\"status_message\", \"-\")}")
'
    echo ""
    echo "Done. Share these details with the trial participant:"
    echo "  License ID: $license_id"
    echo "  Plan:       $plan_code"
    ;;

  status)
    echo "==> License status:"
    _get "/v1/license" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(json.dumps(d, indent=2))
'
    ;;

  bundle)
    echo "==> Support bundle:"
    _get "/v1/support/bundle" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(json.dumps(d, indent=2))
'
    ;;

  revoke)
    license_id="${2:-}"
    reason="${3:-Trial ended}"

    if [[ -z "$license_id" ]]; then
      echo "Usage: provision_trial.sh revoke <license_id> [reason]" >&2
      exit 1
    fi

    echo "==> Revoking license $license_id..."
    _post "/v1/license/revoke" \
      "{\"license_id\": \"$license_id\", \"reason\": $(printf '%s' "$reason" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}" \
      | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(json.dumps(d, indent=2))
'
    echo "Done. License revoked."
    ;;

  plans)
    echo "==> Available plans:"
    _get "/v1/license/plans" | python3 -c '
import json, sys
data = json.load(sys.stdin)
for plan in data["plans"]:
    print(f"  {plan[\"plan_code\"]}: {plan.get(\"description\", \"-\")}")
    for ent in plan.get("entitlements", []):
        val = ent.get("limit_value") if ent.get("limit_value") is not None else ("enabled" if ent.get("enabled", True) else "disabled")
        print(f"    - {ent[\"feature_code\"]}: {val}")
'
    ;;

  help|*)
    echo "ZDG Agent Firewall — Trial Provisioning Helper"
    echo ""
    echo "Usage:"
    echo "  provision_trial.sh provision <contact_email> [display_name] [plan_code]"
    echo "  provision_trial.sh status"
    echo "  provision_trial.sh bundle"
    echo "  provision_trial.sh revoke <license_id> [reason]"
    echo "  provision_trial.sh plans"
    echo ""
    echo "Environment variables:"
    echo "  ZDG_TOKEN  admin token (required); sent as X-ZDG-Admin-Token"
    echo "  ZDG_URL    base URL (default: http://localhost:8000)"
    ;;
esac
