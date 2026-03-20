"""Mission 1 Verification — Policy-Shift Regression Test.

Proves that replay remains historically truthful after policy logic changes.
"""

import json
import yaml
import pytest
from pathlib import Path

def test_replay_immutable_after_policy_shift(make_client, admin_headers, tmp_path):
    # 1. Create a permissive Policy Alpha file
    policy_path = tmp_path / "test_policy.yaml"
    policy_alpha = {
        "bundle_id": "policy-alpha",
        "version": "1.0.0",
        "description": "Permissive test policy",
        "governed_families": ["shell"],
        "thresholds": {"allow_max": 29, "approval_min": 30, "block_min": 60},
        "rules": [
            {
                "id": "rule-allow-all",
                "name": "allow_all_shell",
                "tool_family": "shell",
                "action_pattern": ".*",
                "effect": "ALLOW",
                "priority": 1
            }
        ]
    }
    with open(policy_path, "w") as f:
        yaml.dump(policy_alpha, f)

    with make_client(zdg_policy_bundle_path=str(policy_path)) as client:
        # 2. Execute a governed action under Policy Alpha
        action_req = {
            "agent_id": "test-agent",
            "tool_family": "shell",
            "action": "execute",
            "args": {"command": "ls -l"}
        }
        resp1 = client.post("/v1/action", json=action_req)
        assert resp1.status_code == 200
        data1 = resp1.json()
        attempt_id = data1["attempt_id"]
        alpha_hash = data1["ruleset_hash"]
        assert data1["decision"] == "ALLOW"
        assert alpha_hash.startswith("sha256:")

        # 3. Shift to Policy Omega (Restrictive) on disk and RELOAD
        policy_omega = {
            "bundle_id": "policy-omega",
            "version": "2.0.0",
            "description": "Restrictive test policy",
            "governed_families": ["shell"],
            "thresholds": {"allow_max": 29, "approval_min": 30, "block_min": 60},
            "rules": [
                {
                    "id": "rule-deny-all",
                    "name": "deny_all_shell",
                    "tool_family": "shell",
                    "action_pattern": ".*",
                    "effect": "DENY",
                    "priority": 1
                }
            ]
        }
        with open(policy_path, "w") as f:
            yaml.dump(policy_omega, f)
        
        reload_resp = client.post("/v1/policy/reload", headers=admin_headers)
        assert reload_resp.status_code == 200
        omega_hash = reload_resp.json()["new_ruleset_hash"]
        assert alpha_hash != omega_hash

        # 4. Verify a NEW action is blocked under Policy Omega
        resp2 = client.post("/v1/action", json=action_req)
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["decision"] == "BLOCK"
        assert data2["ruleset_hash"] == omega_hash

        # 5. CRITICAL: Replay the ORIGINAL historical attempt
        # Verify it still shows ALLOW and points to Policy Alpha
        replay_resp = client.get(f"/v1/audit/replay?attempt_id={attempt_id}", headers=admin_headers)
        assert replay_resp.status_code == 200
        replay_data = replay_resp.json()
        
        run_summary = replay_data["run_summary"]
        assert run_summary["final_decision"] == "ALLOW"
        assert run_summary["ruleset_hash"] == alpha_hash
        assert run_summary["policy_bundle_version"] == "1.0.0"
        
        # Verify DECISION_FINALIZED event exists in timeline
        timeline = replay_data["timeline"]
        dec_finalized = next((ev for ev in timeline if ev["event_type"] == "DECISION_FINALIZED"), None)
        assert dec_finalized is not None
        assert dec_finalized["event_payload"]["decision"] == "ALLOW"
        assert dec_finalized["event_payload"]["ruleset_hash"] == alpha_hash
