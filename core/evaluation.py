"""
core/evaluation.py - Shared read-only evaluation trace builder.

This module contains the pure, side-effect-free decision pipeline used by both
/v1/action and /v1/investigate. Persistence, audit, approval creation, and
wrapper execution stay in the route layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlmodel import func, select

from core import agents as agent_manager
from core import approval as approval_manager
from core import decision as decision_engine
from core import guardrails as guardrail_engine
from core import killswitch as ks_manager
from core import normalize as normalizer
from core import policy as policy_engine
from core import risk as risk_engine
from core.modes import Decision, ReasonCode
from core.policy import PolicyBundle
from core.schemas import (
    ActorIdentity,
    AgentIdentity,
    ActionRequest,
    ApprovalUsageTrace,
    DelegationChain,
    EnforcementDecision,
    EvaluationTrace,
    IdempotencyTrace,
    KillSwitchTrace,
    RunAuthorityContext,
)
from db.models import IdempotencyCache, PolicyDecision, ToolAttempt


@dataclass
class EvaluationArtifacts:
    trace: EvaluationTrace
    cached_response_json: str | None = None


def utc_now() -> datetime:
    """Naive UTC timestamp compatible with SQLite round-trip semantics."""

    return datetime.now(timezone.utc).replace(tzinfo=None)


def evaluate_request(
    session,
    bundle: PolicyBundle,
    workspace: str,
    body: ActionRequest,
    run_id: str | None = None,
    trace_id: str | None = None,
    timestamp: datetime | None = None,
    risk_block_count_window_seconds: int = 300,
    risk_repeated_denials_threshold: int = 3,
    guardrail_parallel_enabled: bool = True,
    guardrail_parallel_workers: int = 4,
    guardrail_pii_enabled: bool = True,
    guardrail_toxicity_enabled: bool = True,
    guardrail_jailbreak_enabled: bool = True,
    streaming_guardrails_enabled: bool = True,
    streaming_release_hold_chars: int = 160,
) -> EvaluationArtifacts:
    """Evaluate a request without any DB writes or wrapper execution."""

    evaluation_time = timestamp or utc_now()
    normalization = normalizer.normalize_with_trace(
        tool_family=body.tool_family,
        action=body.action,
        args=body.args,
    )
    normalized_args = (
        normalization.normalized_payload.get("args", {})
        if isinstance(normalization.normalized_payload, dict)
        else {}
    )
    authority_context = _build_authority_context(
        session=session,
        body=body,
        bundle=bundle,
        payload_hash=normalization.payload_hash,
        evaluation_time=evaluation_time,
        run_id=run_id,
        trace_id=trace_id,
    )
    guardrails = guardrail_engine.evaluate_guardrails(
        args=normalized_args,
        metadata=body.metadata,
        parallel_enabled=guardrail_parallel_enabled,
        max_workers=guardrail_parallel_workers,
        pii_enabled=guardrail_pii_enabled,
        toxicity_enabled=guardrail_toxicity_enabled,
        jailbreak_enabled=guardrail_jailbreak_enabled,
        streaming_enabled=streaming_guardrails_enabled,
        streaming_release_hold_chars=streaming_release_hold_chars,
    )

    idempotency = IdempotencyTrace(checked=bool(body.idempotency_key), key=body.idempotency_key)
    cached_response_json: str | None = None
    if body.idempotency_key:
        cached_entries = _load_active_idempotency_entries(
            session=session,
            idempotency_key=body.idempotency_key,
            agent_id=body.agent_id,
            evaluation_time=evaluation_time,
        )
        if cached_entries:
            if any(entry.payload_hash != normalization.payload_hash for entry in cached_entries):
                idempotency.payload_mismatch = True
            else:
                scoped_entry = next(
                    (
                        entry
                        for entry in cached_entries
                        if entry.approval_id == body.approval_id
                    ),
                    None,
                )
                if scoped_entry:
                    idempotency.cached_attempt_id = scoped_entry.attempt_id
                    idempotency.replay_hit = True
                    cached_response_json = scoped_entry.response_json

    ks_active, ks_scope, ks_scope_value, ks_reason = ks_manager.check_killswitch(
        session=session,
        agent_id=body.agent_id,
        tool_family=body.tool_family,
        session_id=body.session_id,
    )
    killswitch = KillSwitchTrace(
        active=ks_active,
        scope=ks_scope,
        scope_value=ks_scope_value,
        reason=ks_reason,
    )

    recent_block_count = _recent_block_count(
        session=session,
        agent_id=body.agent_id,
        decided_after=evaluation_time - timedelta(seconds=risk_block_count_window_seconds),
    )

    risk_breakdown, risk_result = risk_engine.evaluate_breakdown(
        tool_family=body.tool_family,
        action=body.action,
        args=normalized_args,
        agent_id=body.agent_id,
        approved_domains=bundle.approved_domains,
        workspace=workspace,
        bulk_threshold=bundle.bulk_send_threshold,
        approved_recipient_domains=bundle.approved_recipient_domains,
        recent_block_count=recent_block_count,
        repeated_denials_threshold=risk_repeated_denials_threshold,
    )

    policy_result, policy_trace = policy_engine.evaluate_with_trace(
        bundle=bundle,
        tool_family=body.tool_family,
        action=body.action,
        normalized_args=normalized_args,
    )

    decision_result = decision_engine.decide(
        policy_result=policy_result,
        risk_result=risk_result,
        bundle=bundle,
        payload_hash=normalization.payload_hash,
        normalization_status=normalization.status,
    )

    approval = ApprovalUsageTrace(
        provided=body.approval_id is not None,
        checked=False,
        approval_id=body.approval_id,
    )

    final_decision = _decision_to_envelope(decision_result)
    final_decision.authority_context = authority_context
    final_decision.effective_at = evaluation_time
    if guardrails.blocked:
        final_decision = decision_engine.build_enforcement_decision(
            decision=Decision.BLOCK,
            reason_code=ReasonCode.GUARDRAIL_BLOCKED,
            reason=guardrails.block_reason or "A guardrail blocked the action before execution.",
            risk_score=max(risk_result.score, 100),
            triggered_rules=decision_result.triggered_rules + [
                check.guardrail_id for check in guardrails.checks if check.triggered
            ],
            payload_hash=decision_result.payload_hash,
            policy_bundle_id=bundle.bundle_id,
            policy_bundle_version=bundle.version,
            ruleset_hash=bundle.ruleset_hash,
            authority_context=authority_context,
            effective_at=evaluation_time,
        )

    if body.approval_id and guardrails.blocked:
        approval = ApprovalUsageTrace(
            provided=True,
            checked=False,
            approval_id=body.approval_id,
            matched=False,
            consumable=False,
            reason_code=ReasonCode.GUARDRAIL_BLOCKED,
            reason="Approval cannot override a blocking guardrail decision.",
        )
    elif body.approval_id and not ks_active and decision_result.decision == Decision.APPROVAL_REQUIRED:
        matched, reason_code, reason, _record = approval_manager.check_approved_action(
            session=session,
            approval_id=body.approval_id,
            payload_hash=normalization.payload_hash,
            policy_bundle_version=bundle.version,
            agent_id=body.agent_id,
            tool_family=body.tool_family,
            action=body.action,
        )
        approval = ApprovalUsageTrace(
            provided=True,
            checked=True,
            approval_id=body.approval_id,
            matched=matched,
            consumable=matched,
            reason_code=reason_code,
            reason=reason,
        )
        if matched:
            final_decision = decision_engine.build_enforcement_decision(
                decision=Decision.ALLOW,
                reason_code=ReasonCode.APPROVED_MATCHED,
                reason=reason,
                risk_score=decision_result.risk_score,
                triggered_rules=decision_result.triggered_rules,
                payload_hash=decision_result.payload_hash,
                policy_bundle_id=bundle.bundle_id,
                policy_bundle_version=bundle.version,
                ruleset_hash=bundle.ruleset_hash,
                authority_context=authority_context,
                effective_at=evaluation_time,
            )
    elif body.approval_id and ks_active:
        approval = ApprovalUsageTrace(
            provided=True,
            checked=False,
            approval_id=body.approval_id,
            matched=False,
            consumable=False,
            reason_code=ReasonCode.KILLSWITCH_ACTIVE,
            reason="Approval cannot override an active kill switch.",
        )
    elif body.approval_id:
        approval = ApprovalUsageTrace(
            provided=True,
            checked=False,
            approval_id=body.approval_id,
            matched=False,
            consumable=False,
            reason="Approval was provided, but the current evaluation did not require approval.",
        )

    if ks_active:
        scope_label = ks_scope.value if ks_scope else "global"
        final_decision = decision_engine.build_enforcement_decision(
            decision=Decision.BLOCK,
            reason_code=ReasonCode.KILLSWITCH_ACTIVE,
            reason=f"Kill switch active ({scope_label}): {ks_reason}",
            risk_score=0,
            triggered_rules=[],
            payload_hash=normalization.payload_hash,
            policy_bundle_id=bundle.bundle_id,
            policy_bundle_version=bundle.version,
            ruleset_hash=bundle.ruleset_hash,
            killswitch_scope=ks_scope,
            authority_context=authority_context,
            effective_at=evaluation_time,
        )

    return EvaluationArtifacts(
        trace=EvaluationTrace(
            normalized_payload=normalization.normalized_payload,
            normalization_status=normalization.status,
            normalization_failure_reason=normalization.failure_reason,
            normalization_steps=normalization.steps,
            canonical_json=normalization.canonical_json,
            payload_hash=normalization.payload_hash,
            idempotency=idempotency,
            killswitch=killswitch,
            risk_breakdown=risk_breakdown,
            total_risk_score=risk_result.score,
            policy_rules_evaluated=policy_trace,
            matched_policy_rule=policy_result.matched_rule.id if policy_result.matched_rule else None,
            authority_context=authority_context,
            final_decision=final_decision,
            approval=approval,
            guardrails=guardrails,
        ),
        cached_response_json=cached_response_json,
    )


def _load_active_idempotency_entries(session, idempotency_key: str, agent_id: str, evaluation_time: datetime) -> list[IdempotencyCache]:
    return list(
        session.exec(
            select(IdempotencyCache)
            .where(IdempotencyCache.idempotency_key == idempotency_key)
            .where(IdempotencyCache.agent_id == agent_id)
            .where(IdempotencyCache.expires_at > evaluation_time)
            .order_by(IdempotencyCache.created_at.desc(), IdempotencyCache.id.desc())
        ).all()
    )


def _recent_block_count(session, agent_id: str, decided_after: datetime) -> int:
    count = session.exec(
        select(func.count())
        .select_from(PolicyDecision)
        .join(ToolAttempt, ToolAttempt.attempt_id == PolicyDecision.attempt_id)
        .where(PolicyDecision.decision == Decision.BLOCK.value)
        .where(ToolAttempt.agent_id == agent_id)
        .where(PolicyDecision.decided_at >= decided_after)
    ).one()
    return int(count or 0)


def _decision_to_envelope(decision_result) -> EnforcementDecision:
    return decision_engine.build_enforcement_decision(
        decision=decision_result.decision,
        reason_code=decision_result.reason_code,
        reason=decision_result.reason,
        risk_score=decision_result.risk_score,
        triggered_rules=decision_result.triggered_rules,
        payload_hash=decision_result.payload_hash,
        policy_bundle_id=decision_result.policy_bundle.bundle_id,
        policy_bundle_version=decision_result.policy_bundle.version,
        ruleset_hash=decision_result.policy_bundle.ruleset_hash,
        killswitch_scope=decision_result.killswitch_scope,
    )


def _build_authority_context(
    *,
    session,
    body: ActionRequest,
    bundle: PolicyBundle,
    payload_hash: str,
    evaluation_time: datetime,
    run_id: str | None,
    trace_id: str | None,
) -> RunAuthorityContext:
    actor_identity = _resolve_actor_identity(body)
    agent_identity = _resolve_agent_identity(session, body)
    delegation_chain = _resolve_delegation_chain(
        body=body,
        actor_identity=actor_identity,
        agent_identity=agent_identity,
        evaluation_time=evaluation_time,
        payload_hash=payload_hash,
    )
    return RunAuthorityContext(
        run_id=run_id or f"run_{payload_hash.split(':')[-1][:12]}",
        session_id=body.session_id,
        trace_id=trace_id,
        actor_identity=actor_identity,
        agent_identity=agent_identity,
        delegation_chain=delegation_chain,
        requested_tool_family=body.tool_family,
        requested_operation=body.action,
        policy_bundle_id=bundle.bundle_id,
        policy_bundle_version=bundle.version,
    )


def _resolve_actor_identity(body: ActionRequest) -> ActorIdentity:
    if body.actor_identity is not None:
        return body.actor_identity

    metadata = body.metadata or {}
    actor_id = str(metadata.get("actor_id") or metadata.get("operator") or "actor:unspecified")
    actor_type = str(metadata.get("actor_type") or "unspecified")
    tenant_id = metadata.get("tenant_id")
    role_bindings = list(metadata.get("role_bindings") or [])
    auth_context = {
        key: value
        for key, value in {
            "source": metadata.get("auth_source"),
            "operator": metadata.get("operator"),
        }.items()
        if value is not None
    }
    return ActorIdentity(
        actor_id=actor_id,
        actor_type=actor_type,
        tenant_id=str(tenant_id) if tenant_id is not None else None,
        role_bindings=[str(role) for role in role_bindings],
        auth_context=auth_context,
    )


def _resolve_agent_identity(session, body: ActionRequest) -> AgentIdentity:
    registered = agent_manager.get_agent(session=session, agent_id=body.agent_id)
    if registered is None:
        return AgentIdentity(
            agent_id=body.agent_id,
            allowed_tool_families=[body.tool_family],
            lifecycle_state="unregistered",
        )
    metadata = registered.get("metadata") or {}
    allowed_tool_families = metadata.get("allowed_tool_families") or [body.tool_family]
    capabilities = metadata.get("registered_capabilities") or []
    owner_domain = metadata.get("owner_domain")
    return AgentIdentity(
        agent_id=registered["agent_id"],
        agent_type=str(registered.get("agent_type") or "unspecified"),
        owner_domain=str(owner_domain) if owner_domain is not None else None,
        registered_capabilities=[str(item) for item in capabilities],
        allowed_tool_families=[str(item) for item in allowed_tool_families],
        lifecycle_state=str(registered.get("status") or "active"),
    )


def _resolve_delegation_chain(
    *,
    body: ActionRequest,
    actor_identity: ActorIdentity,
    agent_identity: AgentIdentity,
    evaluation_time: datetime,
    payload_hash: str,
) -> DelegationChain:
    if body.delegation_chain is not None:
        return body.delegation_chain
    return DelegationChain(
        delegation_chain_id=f"dlg_{payload_hash.split(':')[-1][:16]}",
        root_actor_id=actor_identity.actor_id,
        delegated_agent_ids=[agent_identity.agent_id],
        authority_scope={
            "tool_family": body.tool_family,
            "action": body.action,
        },
        issued_at=evaluation_time,
        delegation_reason="direct_request",
    )
