"""Parallel content guardrails and streaming-policy planning."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from time import perf_counter
from typing import Any, Callable

from core.modes import GuardrailIntervention, StreamingMode
from core.schemas import GuardrailCheckResult, GuardrailTrace, StreamingPlan

_TEXT_KEYS = {
    "body",
    "candidate_text",
    "command",
    "completion",
    "content",
    "guardrail_text",
    "input_text",
    "message",
    "output",
    "output_preview",
    "output_text",
    "payload",
    "prompt",
    "response",
    "response_preview",
    "subject",
    "text",
}

_JAILBREAK_RE = re.compile(
    r"(ignore\s+(all\s+)?previous\s+instructions|reveal\s+(the\s+)?system\s+prompt|"
    r"developer\s+message|bypass\s+safety|jailbreak|do\s+anything\s+now)",
    re.IGNORECASE,
)
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
_TOXICITY_RE = re.compile(
    r"(kill\s+yourself|go\s+die|worthless\s+piece\s+of\s+trash|you\s+are\s+garbage)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _Surface:
    name: str
    text: str


@dataclass(frozen=True)
class _CheckSpec:
    guardrail_id: str
    checker: Callable[[list[_Surface]], GuardrailCheckResult]


def evaluate_guardrails(
    *,
    args: dict[str, Any],
    metadata: dict[str, Any] | None,
    parallel_enabled: bool,
    max_workers: int,
    pii_enabled: bool,
    toxicity_enabled: bool,
    jailbreak_enabled: bool,
    streaming_enabled: bool,
    streaming_release_hold_chars: int,
) -> GuardrailTrace:
    """Run independent content guardrails and build a streaming policy plan."""

    metadata = metadata or {}
    surfaces = _collect_text_surfaces(args, metadata)
    specs = _build_specs(
        pii_enabled=pii_enabled,
        toxicity_enabled=toxicity_enabled,
        jailbreak_enabled=jailbreak_enabled,
    )

    started_at = perf_counter()
    if parallel_enabled and len(specs) > 1:
        checks = _run_parallel(specs, surfaces, max_workers=max_workers)
        mode = "parallel"
    else:
        checks = [_run_spec(spec, surfaces) for spec in specs]
        mode = "serial"

    blocked = any(
        check.triggered and check.intervention == GuardrailIntervention.TERMINATE
        for check in checks
    )
    block_reason = next((check.reason for check in checks if check.triggered and check.intervention == GuardrailIntervention.TERMINATE), None)
    streaming_plan = _build_streaming_plan(
        metadata=metadata,
        blocked=blocked,
        streaming_enabled=streaming_enabled,
        release_hold_chars=streaming_release_hold_chars,
    )

    return GuardrailTrace(
        execution_mode=mode,
        total_duration_ms=round((perf_counter() - started_at) * 1000, 2),
        blocked=blocked,
        block_reason=block_reason,
        checks=checks,
        streaming_plan=streaming_plan,
    )


def _build_specs(*, pii_enabled: bool, toxicity_enabled: bool, jailbreak_enabled: bool) -> list[_CheckSpec]:
    specs: list[_CheckSpec] = []
    if pii_enabled:
        specs.append(_CheckSpec("PII_DETECTED", _check_pii))
    if toxicity_enabled:
        specs.append(_CheckSpec("TOXICITY_DETECTED", _check_toxicity))
    if jailbreak_enabled:
        specs.append(_CheckSpec("JAILBREAK_DETECTED", _check_jailbreak))
    return specs


def _run_parallel(specs: list[_CheckSpec], surfaces: list[_Surface], *, max_workers: int) -> list[GuardrailCheckResult]:
    ordered: list[GuardrailCheckResult | None] = [None] * len(specs)
    workers = max(1, min(max_workers, len(specs)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_run_spec, spec, surfaces): index
            for index, spec in enumerate(specs)
        }
        for future, index in futures.items():
            ordered[index] = future.result()
    return [result for result in ordered if result is not None]


def _run_spec(spec: _CheckSpec, surfaces: list[_Surface]) -> GuardrailCheckResult:
    started_at = perf_counter()
    result = spec.checker(surfaces)
    return result.model_copy(update={"duration_ms": round((perf_counter() - started_at) * 1000, 2)})


def _check_pii(surfaces: list[_Surface]) -> GuardrailCheckResult:
    for surface in surfaces:
        ssn_match = _SSN_RE.search(surface.text)
        if ssn_match:
            return GuardrailCheckResult(
                guardrail_id="PII_DETECTED",
                triggered=True,
                severity="high",
                intervention=GuardrailIntervention.TERMINATE,
                reason="Potential sensitive PII detected in governed content.",
                surface=surface.name,
                evidence_preview=_preview(surface.text, ssn_match.start(), ssn_match.end()),
            )
        card_match = _CARD_RE.search(surface.text)
        if card_match:
            return GuardrailCheckResult(
                guardrail_id="PII_DETECTED",
                triggered=True,
                severity="high",
                intervention=GuardrailIntervention.TERMINATE,
                reason="Potential payment-card style data detected in governed content.",
                surface=surface.name,
                evidence_preview=_preview(surface.text, card_match.start(), card_match.end()),
            )
    return GuardrailCheckResult(
        guardrail_id="PII_DETECTED",
        triggered=False,
        severity="none",
        intervention=GuardrailIntervention.NONE,
        reason="No sensitive PII patterns detected.",
    )


def _check_toxicity(surfaces: list[_Surface]) -> GuardrailCheckResult:
    for surface in surfaces:
        match = _TOXICITY_RE.search(surface.text)
        if match:
            return GuardrailCheckResult(
                guardrail_id="TOXICITY_DETECTED",
                triggered=True,
                severity="high",
                intervention=GuardrailIntervention.TERMINATE,
                reason="Toxic or abusive language detected in governed content.",
                surface=surface.name,
                evidence_preview=_preview(surface.text, match.start(), match.end()),
            )
    return GuardrailCheckResult(
        guardrail_id="TOXICITY_DETECTED",
        triggered=False,
        severity="none",
        intervention=GuardrailIntervention.NONE,
        reason="No toxicity patterns detected.",
    )


def _check_jailbreak(surfaces: list[_Surface]) -> GuardrailCheckResult:
    for surface in surfaces:
        match = _JAILBREAK_RE.search(surface.text)
        if match:
            return GuardrailCheckResult(
                guardrail_id="JAILBREAK_DETECTED",
                triggered=True,
                severity="critical",
                intervention=GuardrailIntervention.TERMINATE,
                reason="Prompt-injection or jailbreak-style instruction detected.",
                surface=surface.name,
                evidence_preview=_preview(surface.text, match.start(), match.end()),
            )
    return GuardrailCheckResult(
        guardrail_id="JAILBREAK_DETECTED",
        triggered=False,
        severity="none",
        intervention=GuardrailIntervention.NONE,
        reason="No jailbreak patterns detected.",
    )


def _collect_text_surfaces(args: dict[str, Any], metadata: dict[str, Any]) -> list[_Surface]:
    surfaces: list[_Surface] = []
    seen: set[tuple[str, str]] = set()

    def visit(prefix: str, value: Any) -> None:
        if value is None:
            return
        if isinstance(value, str):
            key = prefix.rsplit(".", 1)[-1].lower()
            if key in _TEXT_KEYS and value.strip():
                item = (prefix, value)
                if item not in seen:
                    seen.add(item)
                    surfaces.append(_Surface(name=prefix, text=value))
            return
        if isinstance(value, dict):
            for nested_key, nested_value in value.items():
                next_prefix = f"{prefix}.{nested_key}" if prefix else str(nested_key)
                visit(next_prefix, nested_value)
            return
        if isinstance(value, (list, tuple)):
            for index, nested_value in enumerate(value):
                visit(f"{prefix}[{index}]", nested_value)

    visit("args", args)
    visit("metadata", metadata)
    return surfaces


def _build_streaming_plan(
    *,
    metadata: dict[str, Any],
    blocked: bool,
    streaming_enabled: bool,
    release_hold_chars: int,
) -> StreamingPlan:
    streaming_metadata = metadata.get("streaming")
    requested = bool(
        metadata.get("streaming_requested")
        or (isinstance(streaming_metadata, dict) and streaming_metadata.get("enabled"))
    )
    if not requested:
        return StreamingPlan()
    if blocked:
        return StreamingPlan(
            requested=True,
            enabled=False,
            mode=StreamingMode.BUFFERED,
            release_hold_chars=0,
            final_tail_validation=True,
            intervention_actions=[GuardrailIntervention.PAUSE, GuardrailIntervention.TERMINATE],
            reason="Streaming disabled because a blocking guardrail fired.",
        )
    if not streaming_enabled:
        return StreamingPlan(
            requested=True,
            enabled=False,
            mode=StreamingMode.BUFFERED,
            release_hold_chars=0,
            final_tail_validation=True,
            intervention_actions=[GuardrailIntervention.PAUSE, GuardrailIntervention.TERMINATE],
            reason="Streaming guardrails are disabled in this environment.",
        )
    return StreamingPlan(
        requested=True,
        enabled=True,
        mode=StreamingMode.VALIDATED_RELEASE,
        release_hold_chars=max(0, int(release_hold_chars)),
        final_tail_validation=True,
        intervention_actions=[GuardrailIntervention.PAUSE, GuardrailIntervention.TERMINATE],
        reason="Independent guardrails passed; adapters may stream with holdback and final-tail validation.",
    )


def _preview(text: str, start: int, end: int, radius: int = 24) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    preview = " ".join(text[left:right].split())
    return preview[:96]
