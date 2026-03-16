"""
core/policy.py - Policy bundle loading, validation, and explicit rule evaluation.

Policy bundles are versioned YAML files. The active bundle is loaded at startup
and cached in memory. Every decision records the bundle_id, version, and
ruleset_hash so any past decision can be linked to the exact policy snapshot.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from core.modes import PolicyEffect
from core.schemas import PolicyRuleEvaluation


@dataclass
class PolicyRule:
    """A single explicit policy rule."""

    id: str
    name: str
    tool_family: str
    action_pattern: str
    effect: PolicyEffect
    reason: str
    priority: int = 100


@dataclass
class PolicyBundle:
    """A versioned set of policy rules loaded from a YAML file."""

    bundle_id: str
    version: str
    description: str
    ruleset_hash: str
    rules: list[PolicyRule] = field(default_factory=list)
    governed_families: list[str] = field(default_factory=list)
    approved_domains: list[str] = field(default_factory=list)
    approved_workspace: str = "~/workspace"
    approved_recipient_domains: list[str] = field(default_factory=list)
    bulk_send_threshold: int = 5
    thresholds: dict[str, int] = field(
        default_factory=lambda: {
            "allow_max": 29,
            "approval_min": 30,
            "block_min": 60,
        }
    )


@dataclass
class PolicyResult:
    """Output of explicit rule evaluation (before risk scoring)."""

    has_explicit_deny: bool = False
    has_explicit_allow: bool = False
    is_governed: bool = True
    matched_rule: PolicyRule | None = None
    reason: str = ""


def load_bundle(path: str | Path) -> PolicyBundle:
    """Load and validate a policy bundle from a YAML file."""

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Policy bundle not found: {path}")

    raw_bytes = path.read_bytes()
    ruleset_hash = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
    data: dict[str, Any] = yaml.safe_load(raw_bytes.decode("utf-8")) or {}

    if not data.get("bundle_id"):
        raise ValueError("Policy bundle missing 'bundle_id'")
    if not data.get("version"):
        raise ValueError("Policy bundle missing 'version'")

    rules: list[PolicyRule] = []
    for rule_data in data.get("rules", []):
        rules.append(
            PolicyRule(
                id=rule_data["id"],
                name=rule_data["name"],
                tool_family=rule_data.get("tool_family", "*"),
                action_pattern=rule_data.get("action_pattern", "*"),
                effect=PolicyEffect(rule_data["effect"]),
                reason=rule_data.get("reason", ""),
                priority=rule_data.get("priority", 100),
            )
        )

    rules.sort(key=lambda rule: rule.priority)
    thresholds = {
        "allow_max": data.get("thresholds", {}).get("allow_max", 29),
        "approval_min": data.get("thresholds", {}).get("approval_min", 30),
        "block_min": data.get("thresholds", {}).get("block_min", 60),
    }

    _validate_bundle_data(rules=rules, thresholds=thresholds)

    return PolicyBundle(
        bundle_id=data["bundle_id"],
        version=data["version"],
        description=data.get("description", ""),
        ruleset_hash=ruleset_hash,
        rules=rules,
        governed_families=data.get("governed_families", []),
        approved_domains=data.get("approved_domains", []),
        approved_workspace=data.get("approved_workspace", "~/workspace"),
        approved_recipient_domains=data.get("approved_recipient_domains", []),
        bulk_send_threshold=data.get("bulk_send_threshold", 5),
        thresholds=thresholds,
    )


def evaluate_explicit_rules(
    bundle: PolicyBundle,
    tool_family: str,
    action: str,
    normalized_args: dict[str, Any],
) -> PolicyResult:
    """Backward-compatible explicit rule evaluation API."""

    result, _trace = evaluate_with_trace(
        bundle=bundle,
        tool_family=tool_family,
        action=action,
        normalized_args=normalized_args,
    )
    return result


def evaluate_with_trace(
    bundle: PolicyBundle,
    tool_family: str,
    action: str,
    normalized_args: dict[str, Any],
) -> tuple[PolicyResult, list[PolicyRuleEvaluation]]:
    """Return explicit policy evaluation plus per-rule trace details."""

    if tool_family not in bundle.governed_families:
        return (
            PolicyResult(
                has_explicit_deny=False,
                has_explicit_allow=False,
                is_governed=False,
                reason=f"Tool family '{tool_family}' is not governed by this bundle",
            ),
            [],
        )

    evaluations: list[PolicyRuleEvaluation] = []
    for rule in bundle.rules:
        matched_family = _matches_family(rule, tool_family)
        matched_action = _matches_action(rule, action, normalized_args) if matched_family else False
        matched = matched_family and matched_action

        if not matched_family:
            reason = f"Skipped: rule targets '{rule.tool_family}', request is '{tool_family}'."
        elif not matched_action:
            reason = f"Skipped: action '{action}' did not match pattern '{rule.action_pattern}'."
        else:
            reason = rule.reason or f"Matched explicit {rule.effect.value.lower()} rule '{rule.name}'."

        evaluations.append(
            PolicyRuleEvaluation(
                rule_id=rule.id,
                rule_name=rule.name,
                effect=rule.effect,
                priority=rule.priority,
                matched_family=matched_family,
                matched_action=matched_action,
                matched=matched,
                reason=reason,
            )
        )

        if not matched:
            continue

        if rule.effect == PolicyEffect.DENY:
            return (
                PolicyResult(
                    has_explicit_deny=True,
                    has_explicit_allow=False,
                    is_governed=True,
                    matched_rule=rule,
                    reason=rule.reason or f"Explicit deny: {rule.name}",
                ),
                evaluations,
            )

        if rule.effect == PolicyEffect.ALLOW:
            return (
                PolicyResult(
                    has_explicit_deny=False,
                    has_explicit_allow=True,
                    is_governed=True,
                    matched_rule=rule,
                    reason=rule.reason or f"Explicit allow: {rule.name}",
                ),
                evaluations,
            )

    return (
        PolicyResult(
            has_explicit_deny=False,
            has_explicit_allow=False,
            is_governed=True,
            reason="No explicit rule matched; subject to risk evaluation",
        ),
        evaluations,
    )


def _validate_bundle_data(rules: list[PolicyRule], thresholds: dict[str, int]) -> None:
    rule_ids: set[str] = set()
    for rule in rules:
        if rule.id in rule_ids:
            raise ValueError(f"Policy bundle contains duplicate rule id '{rule.id}'")
        rule_ids.add(rule.id)
        if rule.action_pattern != "*":
            try:
                re.compile(rule.action_pattern, re.IGNORECASE)
            except re.error as exc:
                raise ValueError(
                    f"Policy rule '{rule.id}' has invalid action_pattern: {exc}"
                ) from exc

    allow_max = thresholds["allow_max"]
    approval_min = thresholds["approval_min"]
    block_min = thresholds["block_min"]
    if not (0 <= allow_max < approval_min <= block_min <= 100):
        raise ValueError(
            "Policy bundle thresholds must satisfy 0 <= allow_max < approval_min <= block_min <= 100"
        )


def _matches_family(rule: PolicyRule, tool_family: str) -> bool:
    return rule.tool_family == "*" or rule.tool_family == tool_family


def _matches_action(rule: PolicyRule, action: str, args: dict[str, Any]) -> bool:
    pattern = rule.action_pattern
    if pattern == "*":
        return True

    targets = [action]
    for key in ("command", "url", "path", "body"):
        if key in args and isinstance(args[key], str):
            targets.append(args[key])

    try:
        compiled = re.compile(pattern, re.IGNORECASE)
        return any(compiled.search(target) for target in targets)
    except re.error:
        return False