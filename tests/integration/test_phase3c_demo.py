"""Phase 3C integration tests for the demo runner and scenarios."""

from __future__ import annotations

import json

import httpx

from demos.run_demo import run_named_scenario, run_scenarios



def _transport_from_testclient(client) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8")) if request.content else None
        path = request.url.path
        if request.url.query:
            query = request.url.query.decode("utf-8") if isinstance(request.url.query, (bytes, bytearray)) else str(request.url.query)
            path = f"{path}?{query}"
        response = client.request(request.method, path, json=payload, headers=dict(request.headers))
        content_type = response.headers.get("content-type", "application/json")
        if "application/x-ndjson" in content_type:
            return httpx.Response(response.status_code, text=response.text, headers={"content-type": content_type})
        return httpx.Response(response.status_code, json=response.json(), headers={"content-type": content_type})

    return httpx.MockTransport(handler)



def test_demo_runner_safe_shell_scenario(make_client):
    with make_client() as client:
        transport = _transport_from_testclient(client)
        with httpx.Client(base_url="http://testserver", transport=transport, trust_env=False) as http_client:
            result = run_named_scenario("safe-shell-allow", client=http_client)

        assert result["passed"] is True
        assert result["decision"] == "ALLOW"



def test_demo_runner_all_registered_scenarios(make_client, admin_headers):
    admin_token = admin_headers["X-ZDG-Admin-Token"]
    with make_client() as client:
        # audit-export-verify requires debug_bundle_export; activate dev_monthly.
        client.post(
            "/v1/license/activate",
            json={"email": "test@example.com", "plan_code": "dev_monthly"},
            headers=admin_headers,
        )
        transport = _transport_from_testclient(client)
        with httpx.Client(base_url="http://testserver", transport=transport, trust_env=False) as http_client:
            results = run_scenarios(
                ["safe-shell-allow", "approval-cycle", "audit-export-verify"],
                client=http_client,
                admin_token=admin_token,
            )

        assert len(results) == 3
        assert all(result["passed"] is True for result in results)

