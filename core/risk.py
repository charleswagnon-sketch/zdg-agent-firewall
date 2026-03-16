"""
core/risk.py - Rule-based risk scoring engine.

Scores every normalized action request on a 0-100 scale.
Returns a RiskResult with the numeric score, list of triggered rule names,
and a human-readable reason string.
"""

from __future__ import annotations

import os
import re
from typing import Any, Callable

from core.schemas import RiskResult, RiskRuleResult


_DESTRUCTIVE_SHELL_RE = re.compile(
    r"(rm\s+-[rf]+|sudo\s+|chmod\s+[0-9]*7[0-9]*[0-9]*|mkfs\.|dd\s+if=|"
    r"shred\s+|:\(\)\{|>\s*/dev/sd)",
    re.IGNORECASE,
)

_REMOTE_SCRIPT_PIPE_RE = re.compile(
    r"(curl|wget|fetch)\s+.+\|\s*(ba)?sh",
    re.IGNORECASE,
)

_PRIVILEGE_ESCALATION_RE = re.compile(
    r"(sudo|su\s+-|pkexec|doas)\s+",
    re.IGNORECASE,
)

_SENSITIVE_PATH_PREFIXES: list[str] = [
    os.path.expanduser("~/.ssh"),
    os.path.expanduser("~/.aws"),
    os.path.expanduser("~/.azure"),
    os.path.expanduser("~/.gnupg"),
    os.path.expanduser("~/.config/gcloud"),
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    os.path.expanduser("~/.bash_profile"),
    os.path.expanduser("~/.bashrc"),
    os.path.expanduser("~/.zshrc"),
    os.path.expanduser("~/.profile"),
]

_RAW_IP_RE = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}(:\d+)?(/|$)")


def _check_destructive_shell(tool_family: str, args: dict[str, Any]) -> tuple[bool, int, str, str]:
    if tool_family != "shell":
        return False, 0, "", ""
    cmd = args.get("command", "")
    if _DESTRUCTIVE_SHELL_RE.search(cmd):
        return True, 40, "DESTRUCTIVE_SHELL_PATTERN", "Command matches destructive shell pattern (rm -rf, sudo, chmod, etc.)"
    return False, 0, "", ""


def _check_remote_script_pipe(tool_family: str, args: dict[str, Any]) -> tuple[bool, int, str, str]:
    if tool_family != "shell":
        return False, 0, "", ""
    cmd = args.get("command", "")
    if _REMOTE_SCRIPT_PIPE_RE.search(cmd):
        return True, 60, "REMOTE_SCRIPT_PIPE", "Command pipes remote content into shell execution (curl|bash, wget|sh)"
    return False, 0, "", ""


def _check_privilege_escalation(tool_family: str, args: dict[str, Any]) -> tuple[bool, int, str, str]:
    if tool_family != "shell":
        return False, 0, "", ""
    cmd = args.get("command", "")
    if _PRIVILEGE_ESCALATION_RE.search(cmd):
        return True, 50, "PRIVILEGE_ESCALATION", "Command attempts privilege escalation (sudo, su, pkexec)"
    return False, 0, "", ""


def _check_unknown_domain(tool_family: str, args: dict[str, Any], approved_domains: list[str]) -> tuple[bool, int, str, str]:
    if tool_family != "http":
        return False, 0, "", ""
    url = args.get("url", "")
    if not url:
        return False, 0, "", ""
    try:
        import urllib.parse

        host = urllib.parse.urlparse(url).hostname or ""
        host = host.lower()
        if any(host == domain.lower() or host.endswith("." + domain.lower()) for domain in approved_domains):
            return False, 0, "", ""
        return True, 30, "UNKNOWN_DOMAIN", f"HTTP destination '{host}' is not in the approved domains list"
    except Exception:  # noqa: BLE001
        return True, 30, "UNKNOWN_DOMAIN", "Could not validate HTTP destination domain"


def _check_raw_ip_destination(tool_family: str, args: dict[str, Any]) -> tuple[bool, int, str, str]:
    if tool_family != "http":
        return False, 0, "", ""
    url = args.get("url", "")
    if _RAW_IP_RE.match(url):
        return True, 50, "RAW_IP_DESTINATION", "HTTP request targets a raw IP address rather than a domain"
    return False, 0, "", ""


def _check_large_outbound_post(tool_family: str, args: dict[str, Any], approved_domains: list[str]) -> tuple[bool, int, str, str]:
    if tool_family != "http":
        return False, 0, "", ""
    method = str(args.get("method", "")).upper()
    if method not in ("POST", "PUT", "PATCH"):
        return False, 0, "", ""
    size = args.get("payload_size_bytes", 0) or 0
    url = args.get("url", "")
    try:
        import urllib.parse

        host = urllib.parse.urlparse(url).hostname or ""
        is_unknown = not any(host == domain or host.endswith("." + domain) for domain in approved_domains)
    except Exception:  # noqa: BLE001
        is_unknown = True
    if is_unknown and size > 100_000:
        return True, 35, "POSSIBLE_EXFILTRATION", f"Large outbound {method} ({size} bytes) to unknown domain"
    return False, 0, "", ""


def _check_sensitive_path(tool_family: str, args: dict[str, Any]) -> tuple[bool, int, str, str]:
    if tool_family != "filesystem":
        return False, 0, "", ""
    path = os.path.normpath(os.path.expanduser(args.get("path", "")))
    for sensitive in _SENSITIVE_PATH_PREFIXES:
        if path == sensitive or path.startswith(sensitive + os.sep):
            return True, 50, "SENSITIVE_PATH_ACCESS", f"Filesystem operation targets sensitive path: {path}"
    return False, 0, "", ""


def _check_outside_workspace(tool_family: str, args: dict[str, Any], workspace: str) -> tuple[bool, int, str, str]:
    if tool_family != "filesystem":
        return False, 0, "", ""
    path = os.path.normpath(os.path.expanduser(args.get("path", "")))
    ws = os.path.normpath(os.path.expanduser(workspace))
    if path and not path.startswith(ws + os.sep) and path != ws:
        return True, 40, "OUTSIDE_WORKSPACE", f"Filesystem operation targets path outside approved workspace: {path}"
    return False, 0, "", ""


def _check_bulk_send(tool_family: str, args: dict[str, Any], bulk_threshold: int) -> tuple[bool, int, str, str]:
    if tool_family != "messaging":
        return False, 0, "", ""
    recipients = args.get("to", []) or []
    cc = args.get("cc", []) or []
    total = len(recipients) + len(cc)
    if total > bulk_threshold:
        return True, 40, "BULK_SEND_DETECTED", f"Outbound message targets {total} recipients (threshold: {bulk_threshold})"
    return False, 0, "", ""


def _check_unapproved_recipient(tool_family: str, args: dict[str, Any], approved_domains: list[str]) -> tuple[bool, int, str, str]:
    if tool_family != "messaging":
        return False, 0, "", ""
    all_recipients = list(args.get("to", []) or []) + list(args.get("cc", []) or [])
    for address in all_recipients:
        domain = address.split("@")[-1].lower() if "@" in str(address) else ""
        if domain and not any(domain == approved.lower() or domain.endswith("." + approved.lower()) for approved in approved_domains):
            return True, 30, "UNAPPROVED_RECIPIENT", f"Message recipient '{address}' is in an unapproved domain"
    return False, 0, "", ""


def _check_attachment_external(tool_family: str, args: dict[str, Any], approved_domains: list[str]) -> tuple[bool, int, str, str]:
    if tool_family != "messaging":
        return False, 0, "", ""
    if not args.get("has_attachment", False):
        return False, 0, "", ""
    all_recipients = list(args.get("to", []) or []) + list(args.get("cc", []) or [])
    for address in all_recipients:
        domain = address.split("@")[-1].lower() if "@" in str(address) else ""
        if domain and not any(domain == approved.lower() or domain.endswith("." + approved.lower()) for approved in approved_domains):
            return True, 35, "ATTACHMENT_TO_EXTERNAL", "Message with attachment targets external unapproved recipient"
    return False, 0, "", ""


def _check_repeated_denials(
    agent_id: str,
    recent_block_count: int,
    repeated_denials_threshold: int,
) -> tuple[bool, int, str, str]:
    if recent_block_count >= repeated_denials_threshold:
        return True, 20, "REPEATED_DENIALS", f"Agent '{agent_id}' has been blocked {recent_block_count} times recently"
    return False, 0, "", ""


def _build_rule_specs(
    tool_family: str,
    args: dict[str, Any],
    agent_id: str,
    approved_domains: list[str],
    workspace: str,
    bulk_threshold: int,
    approved_recipient_domains: list[str],
    recent_block_count: int,
    repeated_denials_threshold: int,
) -> list[tuple[str, str, Callable[[], tuple[bool, int, str, str]]]]:
    return [
        (
            "DESTRUCTIVE_SHELL_PATTERN",
            "Shell command does not match destructive command patterns.",
            lambda: _check_destructive_shell(tool_family, args),
        ),
        (
            "REMOTE_SCRIPT_PIPE",
            "Shell command does not pipe remote content directly into a shell.",
            lambda: _check_remote_script_pipe(tool_family, args),
        ),
        (
            "PRIVILEGE_ESCALATION",
            "Shell command does not attempt privilege escalation.",
            lambda: _check_privilege_escalation(tool_family, args),
        ),
        (
            "UNKNOWN_DOMAIN",
            "HTTP destination is approved or no external destination was evaluated.",
            lambda: _check_unknown_domain(tool_family, args, approved_domains),
        ),
        (
            "RAW_IP_DESTINATION",
            "HTTP destination does not target a raw IP address.",
            lambda: _check_raw_ip_destination(tool_family, args),
        ),
        (
            "POSSIBLE_EXFILTRATION",
            "HTTP request does not look like a large outbound write to an unknown domain.",
            lambda: _check_large_outbound_post(tool_family, args, approved_domains),
        ),
        (
            "SENSITIVE_PATH_ACCESS",
            "Filesystem request does not target a sensitive path.",
            lambda: _check_sensitive_path(tool_family, args),
        ),
        (
            "OUTSIDE_WORKSPACE",
            "Filesystem request stays within the approved workspace.",
            lambda: _check_outside_workspace(tool_family, args, workspace),
        ),
        (
            "BULK_SEND_DETECTED",
            "Message recipient volume is within the configured threshold.",
            lambda: _check_bulk_send(tool_family, args, bulk_threshold),
        ),
        (
            "UNAPPROVED_RECIPIENT",
            "Message recipients are within approved domains.",
            lambda: _check_unapproved_recipient(tool_family, args, approved_recipient_domains),
        ),
        (
            "ATTACHMENT_TO_EXTERNAL",
            "No attachment is being sent to an unapproved external recipient.",
            lambda: _check_attachment_external(tool_family, args, approved_recipient_domains),
        ),
        (
            "REPEATED_DENIALS",
            "Recent block volume for this agent is below the repeated-denial threshold.",
            lambda: _check_repeated_denials(agent_id, recent_block_count, repeated_denials_threshold),
        ),
    ]


def evaluate_breakdown(
    tool_family: str,
    action: str,
    args: dict[str, Any],
    agent_id: str,
    approved_domains: list[str],
    workspace: str,
    bulk_threshold: int,
    approved_recipient_domains: list[str],
    recent_block_count: int = 0,
    repeated_denials_threshold: int = 3,
) -> tuple[list[RiskRuleResult], RiskResult]:
    rule_results: list[RiskRuleResult] = []
    triggered_rules: list[str] = []
    reasons: list[str] = []
    total_score = 0

    for rule_name, default_reason, checker in _build_rule_specs(
        tool_family=tool_family,
        args=args,
        agent_id=agent_id,
        approved_domains=approved_domains,
        workspace=workspace,
        bulk_threshold=bulk_threshold,
        approved_recipient_domains=approved_recipient_domains,
        recent_block_count=recent_block_count,
        repeated_denials_threshold=repeated_denials_threshold,
    ):
        triggered, points, resolved_rule_name, reason = checker()
        effective_rule_name = resolved_rule_name or rule_name
        effective_reason = reason if triggered else default_reason
        effective_points = points if triggered else 0

        rule_results.append(
            RiskRuleResult(
                rule=effective_rule_name,
                triggered=triggered,
                points=effective_points,
                reason=effective_reason,
            )
        )

        if triggered:
            triggered_rules.append(effective_rule_name)
            reasons.append(reason)
            total_score += points

    final_score = min(total_score, 100)
    if reasons:
        human_reason = "; ".join(reasons)
    else:
        human_reason = f"No risk rules triggered for {tool_family}/{action}"

    return rule_results, RiskResult(
        score=final_score,
        triggered_rules=triggered_rules,
        reason=human_reason,
    )


def evaluate(
    tool_family: str,
    action: str,
    args: dict[str, Any],
    agent_id: str,
    approved_domains: list[str],
    workspace: str,
    bulk_threshold: int,
    approved_recipient_domains: list[str],
    recent_block_count: int = 0,
    repeated_denials_threshold: int = 3,
) -> RiskResult:
    """Backward-compatible aggregate risk API."""

    _breakdown, result = evaluate_breakdown(
        tool_family=tool_family,
        action=action,
        args=args,
        agent_id=agent_id,
        approved_domains=approved_domains,
        workspace=workspace,
        bulk_threshold=bulk_threshold,
        approved_recipient_domains=approved_recipient_domains,
        recent_block_count=recent_block_count,
        repeated_denials_threshold=repeated_denials_threshold,
    )
    return result