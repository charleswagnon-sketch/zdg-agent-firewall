"""
core/decision.py - Decision engine: combines policy + risk into a final verdict.

This module is the single authority that maps (PolicyResult, RiskResult, PolicyBundle)
to DecisionResult. No other module computes a final decision.

Decision logic:
  1. Normalization FAILED for dangerous family -> BLOCK (NORMALIZATION_FAILED)
  2. Explicit DENY rule matched               -> BLOCK (EXPLICIT_POLICY_DENY)
  3. Explicit ALLOW rule matched              -> ALLOW (ALLOW)
  4. Ungoverned tool family                   -> ALLOW (UNGOVERNED_TOOL_FAMILY)
  5. risk.score >= block_min                  -> BLOCK (RISK_THRESHOLD_BLOCK)
  6. risk.score >= approval_min               -> APPROVAL_REQUIRED
  7. All other governed + low risk            -> ALLOW (ALLOW)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from core.modes import Decision, Disposition, EnforcementModuleOrigin, GalStage, NormalizationStatus, ReasonCode
from core.policy import PolicyBundle, PolicyResult
from core.schemas import (
    CanonicalRuntimeCorrelation,
    DecisionResult,
    EnforcementDecision,
    PolicyBundleMeta,
    RiskResult,
    RunAuthorityContext,
)


def decide(
    policy_result: PolicyResult,
    risk_result: RiskResult,
    bundle: PolicyBundle,
    payload_hash: str,
    normalization_status: NormalizationStatus,
) -> DecisionResult:
    """
    Produce a final DecisionResult.

    Parameters:
        policy_result:         output of policy.evaluate_explicit_rules()
        risk_result:           output of risk.evaluate()
        bundle:                the active PolicyBundle (for thresholds + metadata)
        payload_hash:          sha256 hash of the canonical normalized payload
        normalization_status:  COMPLETE | PARTIAL | FAILED

    Returns a DecisionResult with all fields populated.
    """
    bundle_meta = PolicyBundleMeta(
        bundle_id=bundle.bundle_id,
        version=bundle.version,
        ruleset_hash=bundle.ruleset_hash,
    )

    block_min = bundle.thresholds["block_min"]
    approval_min = bundle.thresholds["approval_min"]

    if normalization_status == NormalizationStatus.FAILED:
        return DecisionResult(
            decision=Decision.BLOCK,
            reason_code=ReasonCode.NORMALIZATION_FAILED,
            reason="Payload normalization failed; execution blocked for safety.",
            risk_score=risk_result.score,
            triggered_rules=risk_result.triggered_rules,
            policy_bundle=bundle_meta,
            payload_hash=payload_hash,
        )

    if policy_result.has_explicit_deny:
        return DecisionResult(
            decision=Decision.BLOCK,
            reason_code=ReasonCode.EXPLICIT_POLICY_DENY,
            reason=policy_result.reason,
            risk_score=risk_result.score,
            triggered_rules=risk_result.triggered_rules,
            policy_bundle=bundle_meta,
            payload_hash=payload_hash,
        )

    if policy_result.has_explicit_allow:
        return DecisionResult(
            decision=Decision.ALLOW,
            reason_code=ReasonCode.ALLOW,
            reason=policy_result.reason,
            risk_score=risk_result.score,
            triggered_rules=risk_result.triggered_rules,
            policy_bundle=bundle_meta,
            payload_hash=payload_hash,
        )

    if not policy_result.is_governed:
        return DecisionResult(
            decision=Decision.ALLOW,
            reason_code=ReasonCode.UNGOVERNED_TOOL_FAMILY,
            reason=policy_result.reason,
            risk_score=0,
            triggered_rules=[],
            policy_bundle=bundle_meta,
            payload_hash=payload_hash,
        )

    if risk_result.score >= block_min:
        return DecisionResult(
            decision=Decision.BLOCK,
            reason_code=ReasonCode.RISK_THRESHOLD_BLOCK,
            reason=(
                f"Risk score {risk_result.score} exceeds block threshold ({block_min}). "
                + risk_result.reason
            ),
            risk_score=risk_result.score,
            triggered_rules=risk_result.triggered_rules,
            policy_bundle=bundle_meta,
            payload_hash=payload_hash,
        )

    if risk_result.score >= approval_min:
        return DecisionResult(
            decision=Decision.APPROVAL_REQUIRED,
            reason_code=ReasonCode.APPROVAL_REQUIRED_THRESHOLD,
            reason=(
                f"Risk score {risk_result.score} requires operator approval "
                f"(threshold: {approval_min}). "
                + risk_result.reason
            ),
            risk_score=risk_result.score,
            triggered_rules=risk_result.triggered_rules,
            policy_bundle=bundle_meta,
            payload_hash=payload_hash,
        )

    return DecisionResult(
        decision=Decision.ALLOW,
        reason_code=ReasonCode.ALLOW,
        reason=f"Action permitted. Risk score: {risk_result.score}.",
        risk_score=risk_result.score,
        triggered_rules=risk_result.triggered_rules,
        policy_bundle=bundle_meta,
        payload_hash=payload_hash,
    )


def module_origin_for_reason(reason_code: ReasonCode) -> EnforcementModuleOrigin:
    """Map reason codes onto the primary enforcement module origin."""

    mapping = {
        ReasonCode.IDENTITY_FAILED: EnforcementModuleOrigin.IDENTITY,
        ReasonCode.SESSION_CLOSED: EnforcementModuleOrigin.AUTHORITY_CONTEXT,
        ReasonCode.SESSION_SUSPENDED: EnforcementModuleOrigin.AUTHORITY_CONTEXT,
        ReasonCode.AGENT_SUSPENDED: EnforcementModuleOrigin.AUTHORITY_CONTEXT,
        ReasonCode.AUTHORITY_BINDING_REQUIRED: EnforcementModuleOrigin.CREDENTIALING,
        ReasonCode.AUTHORITY_SCOPE_VIOLATION: EnforcementModuleOrigin.CREDENTIALING,
        ReasonCode.CREDENTIAL_EXPIRED: EnforcementModuleOrigin.CREDENTIALING,
        ReasonCode.CREDENTIAL_REVOKED: EnforcementModuleOrigin.CREDENTIALING,
        ReasonCode.HANDOFF_SCHEMA_NOT_FOUND: EnforcementModuleOrigin.HANDOFF_FIREWALL,
        ReasonCode.HANDOFF_VALIDATION_FAILED: EnforcementModuleOrigin.HANDOFF_FIREWALL,
        ReasonCode.NORMALIZATION_FAILED: EnforcementModuleOrigin.NORMALIZATION,
        ReasonCode.KILLSWITCH_ACTIVE: EnforcementModuleOrigin.POLICY_CONTEXT,
        ReasonCode.EXPLICIT_POLICY_DENY: EnforcementModuleOrigin.POLICY_CONTEXT,
        ReasonCode.UNGOVERNED_TOOL_FAMILY: EnforcementModuleOrigin.POLICY_CONTEXT,
        ReasonCode.RISK_THRESHOLD_BLOCK: EnforcementModuleOrigin.RISK_EVALUATION,
        ReasonCode.APPROVAL_REQUIRED_THRESHOLD: EnforcementModuleOrigin.RISK_EVALUATION,
        ReasonCode.GUARDRAIL_BLOCKED: EnforcementModuleOrigin.GUARDRAILS,
        ReasonCode.UNREGISTERED_TOOL_FAMILY: EnforcementModuleOrigin.EXECUTION,
        ReasonCode.WRAPPER_BLOCKED: EnforcementModuleOrigin.EXECUTION,
    }
    return mapping.get(reason_code, EnforcementModuleOrigin.DECISION)


def build_enforcement_decision(
    *,
    decision: Decision,
    reason_code: ReasonCode,
    reason: str,
    risk_score: int,
    triggered_rules: list[str],
    payload_hash: str,
    policy_bundle_id: str,
    policy_bundle_version: str,
    ruleset_hash: str,
    authority_context: RunAuthorityContext | None = None,
    killswitch_scope=None,
    gal_stage: GalStage = GalStage.DECISION,
    module_origin: EnforcementModuleOrigin | None = None,
    effective_at: datetime | None = None,
) -> EnforcementDecision:
    """Build one canonical enforcement decision object for runtime and evidence paths."""

    return EnforcementDecision(
        decision=decision,
        reason_code=reason_code,
        reason=reason,
        risk_score=risk_score,
        triggered_rules=triggered_rules,
        payload_hash=payload_hash,
        policy_bundle_id=policy_bundle_id,
        policy_bundle_version=policy_bundle_version,
        ruleset_hash=ruleset_hash,
        killswitch_scope=killswitch_scope,
        gal_stage=gal_stage,
        module_origin=module_origin or module_origin_for_reason(reason_code),
        authority_context=authority_context,
        effective_at=effective_at,
    )


def disposition_for_decision(decision: Decision) -> Disposition:
    """Normalize route/runtime decisions into the locked disposition vocabulary."""

    return {
        Decision.ALLOW: Disposition.ALLOW,
        Decision.WARN: Disposition.ALLOW,
        Decision.PAUSE: Disposition.HOLD,
        Decision.RETRY: Disposition.HOLD,
        Decision.APPROVAL_REQUIRED: Disposition.HOLD,
        Decision.BLOCK: Disposition.BLOCK,
        Decision.TERMINATE: Disposition.TERMINATE,
        Decision.QUARANTINE: Disposition.QUARANTINE,
        Decision.ESCALATE: Disposition.ESCALATE,
    }[decision]


def source_component_for_decision(decision: EnforcementDecision) -> str:
    """Return the canonical source component for a persisted/runtime decision."""

    return f"agent_firewall.{decision.module_origin.value}"


def build_runtime_correlation(
    *,
    timestamp: datetime,
    source_component: str,
    authority_context: RunAuthorityContext | None = None,
    enforcement_decision: EnforcementDecision | None = None,
    run_id: str | None = None,
    session_id: str | None = None,
    trace_id: str | None = None,
    actor_id: str | None = None,
    agent_id: str | None = None,
    delegation_id: str | None = None,
    authority_scope: dict[str, Any] | None = None,
    contract_id: str | None = None,
    handoff_id: str | None = None,
    decision_state: Decision | None = None,
    disposition: Disposition | None = None,
) -> CanonicalRuntimeCorrelation:
    """Build the canonical identifier/correlation payload for replay and evidence."""

    derived_decision = decision_state or (
        enforcement_decision.decision if enforcement_decision is not None else None
    )
    derived_disposition = disposition or (
        disposition_for_decision(derived_decision) if derived_decision is not None else None
    )
    derived_scope = authority_scope
    if derived_scope is None and authority_context is not None:
        derived_scope = dict(authority_context.delegation_chain.authority_scope or {})
    if derived_scope is None and enforcement_decision is not None and enforcement_decision.authority_context is not None:
        derived_scope = dict(enforcement_decision.authority_context.delegation_chain.authority_scope or {})

    return CanonicalRuntimeCorrelation(
        run_id=run_id or (authority_context.run_id if authority_context is not None else None),
        session_id=session_id or (authority_context.session_id if authority_context is not None else None),
        trace_id=trace_id or (authority_context.trace_id if authority_context is not None else None),
        actor_id=actor_id or (
            authority_context.actor_identity.actor_id if authority_context is not None else None
        ),
        agent_id=agent_id or (
            authority_context.agent_identity.agent_id if authority_context is not None else None
        ),
        delegation_id=delegation_id or (
            authority_context.delegation_chain.delegation_chain_id if authority_context is not None else None
        ),
        authority_scope=derived_scope or {},
        contract_id=contract_id,
        handoff_id=handoff_id,
        decision_state=derived_decision,
        disposition=derived_disposition,
        timestamp=timestamp,
        source_component=source_component,
    )
