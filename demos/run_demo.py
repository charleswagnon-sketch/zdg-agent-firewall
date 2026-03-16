"""Run bounded pilot demo scenarios against a live or test ZDG instance."""

from __future__ import annotations

import argparse
import json
from typing import Any

import httpx

from demos.scenarios import SCENARIOS



def run_named_scenario(name: str, client: httpx.Client, admin_token: str | None = None) -> dict[str, Any]:
    if name not in SCENARIOS:
        raise KeyError(f"Unknown demo scenario '{name}'.")
    return SCENARIOS[name](client=client, admin_token=admin_token)



def run_scenarios(names: list[str], client: httpx.Client, admin_token: str | None = None) -> list[dict[str, Any]]:
    return [run_named_scenario(name, client=client, admin_token=admin_token) for name in names]



def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run ZDG demo scenarios.")
    parser.add_argument("scenarios", nargs="*", help="Scenario names to run.")
    parser.add_argument("--all", action="store_true", help="Run all registered scenarios.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--admin-token")
    parser.add_argument("--json", action="store_true", help="Emit JSON summary.")
    return parser



def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    scenario_names = list(SCENARIOS.keys()) if args.all else args.scenarios
    if not scenario_names:
        raise SystemExit("Specify one or more scenarios, or use --all.")

    with httpx.Client(base_url=args.base_url, timeout=10.0, trust_env=False) as client:
        results = run_scenarios(scenario_names, client=client, admin_token=args.admin_token)

    summary = {
        "count": len(results),
        "passed": sum(1 for result in results if result.get("passed")),
        "failed": sum(1 for result in results if not result.get("passed")),
        "results": results,
    }

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        for result in results:
            print(f"[{ 'PASS' if result.get('passed') else 'FAIL' }] {result['name']}")
        print(f"Summary: {summary['passed']} passed, {summary['failed']} failed")

    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
