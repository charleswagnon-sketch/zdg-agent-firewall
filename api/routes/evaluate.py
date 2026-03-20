"""
api/routes/evaluate.py - POST /v1/action.

The primary evaluation endpoint. This is where every agent tool call enters
the ZDG enforcement boundary.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta
from time import perf_counter

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlmodel import Session

from api.config import Settings
from api.state import AppState
from core.licensing import LicenseError as LicenseError, enforce_monthly_runs_cap
from core import agents as agent_manager
from core import approval as approval_manager
from core import contracts as contracts_manager
from core import credentialing
from core import decision as decision_engine
from core import handoffs
from core import killswitch as ks_manager
from core import normalize as normalizer
from core import sessions as session_manager
from core.audit import (
    CONTRACT_BREACHED,
    CREDENTIAL_USED,
    DECISION_FINALIZED,
    append_audit_event_with_session_chain,
)
from core.evaluation import evaluate_request, utc_now
from core.logging import log_decision, log_execution
from core.modes import Decision, NormalizationStatus, ReasonCode
from core.policy import PolicyBundle
from core.schemas import (
    ActionRequest,
    ActionResponse,
    AgentContract,
    CredentialGrant,
    EnforcementDecision,
    ExecutionOutcome,
    HandoffEnvelope,
    HandoffSchema,
    HandoffValidationResult,
)
from db.models import ExecutionResult, IdempotencyCache, PolicyDecision, ToolAttempt
from db.sqlite import get_session
from wrappers import ExecutionContext, UnregisteredToolFamily, get_wrapper
from wrappers.base import WrapperResult

router = APIRouter()


def _get_state(request: Request) -> AppState:
    return request.app.state.zdg


@router.post("/action", response_model=ActionResponse)
def evaluate_action(
    body: ActionRequest,
    request: Request,
    session: Session = Depends(get_session),
) -> ActionResponse:
    """Evaluate an agent tool request against ZDG policy before execution."""

    state: AppState = _get_state(request)
    settings: Settings = state.settings
    bundle = state.bundle

    started_at = perf_counter()
    trace_id = f"zdg_{uuid.uuid4().hex[:8]}"
    attempt_id = f"atm_{uuid.uuid4().hex[:16]}"
    decision_id = f"dec_{uuid.uuid4().hex[:16]}"
    timestamp = utc_now()
    request_id = getattr(request.state, "request_id", None)

    # LIC-LIMITS enforcement: monthly run cap check.
    # Checked BEFORE evaluate_request() so cap-exceeded requests do not create a
    # ToolAttempt record (keeping the counter clean) and return 402 immediately.
    try:
        enforce_monthly_runs_cap(session)
    except LicenseError as exc:
        raise HTTPException(
            status_code=402,
            detail={"reason": str(exc), "feature": exc.feature_code},
        ) from exc

    # ── Tier 1: Lifecycle Block Check (Fast-Fail) ─────────────────────────────
    # Check session/agent state before any heavy evaluation work.
    lifecycle_block = _check_lifecycle_block(session=session, body=body)

    # We still need basic normalization for the audit trail even if we block.
    # This is lightweight (regex/string parsing).
    normalization = normalizer.normalize_with_trace(
        tool_family=body.tool_family,
        action=body.action,
        args=body.args,
    )

    if lifecycle_block is not None:
        reason_code, reason = lifecycle_block
        
        # Resolve a minimal authority context for the lifecycle block audit.
        _authority_ctx = _build_authority_context(
            settings=settings,
            bundle=bundle,
            body=body,
            payload_hash=normalization.payload_hash,
            evaluation_time=timestamp,
            run_id=attempt_id,
            trace_id=trace_id,
        )

        _persist_attempt(
            session=session,
            attempt_id=attempt_id,
            body=body,
            normalized_payload=normalization.normalized_payload,
            payload_hash=normalization.payload_hash,
            normalization_status=normalization.status,
            authority_context=_authority_ctx,
        )
        session.flush()

        return _build_lifecycle_block_response(
            session=session,
            state=state,
            bundle=bundle,
            body=body,
            authority_context=_authority_ctx,
            attempt_id=attempt_id,
            decision_id=decision_id,
            trace_id=trace_id,
            timestamp=timestamp,
            request_id=request_id,
            started_at=started_at,
            reason_code=reason_code,
            reason=reason,
        )

    # ── Tier 2: Full Evaluation ───────────────────────────────────────────────

    artifacts = evaluate_request(
        session=session,
        bundle=bundle,
        workspace=settings.workspace_resolved,
        body=body,
        run_id=attempt_id,
        trace_id=trace_id,
        timestamp=timestamp,
        risk_block_count_window_seconds=settings.zdg_risk_block_count_window_seconds,
        risk_repeated_denials_threshold=settings.zdg_risk_repeated_denials_threshold,
        guardrail_parallel_enabled=settings.zdg_guardrail_parallel_enabled,
        guardrail_parallel_workers=settings.zdg_guardrail_parallel_workers,
        guardrail_pii_enabled=settings.zdg_guardrail_pii_enabled,
        guardrail_toxicity_enabled=settings.zdg_guardrail_toxicity_enabled,
        guardrail_jailbreak_enabled=settings.zdg_guardrail_jailbreak_enabled,
        streaming_guardrails_enabled=settings.zdg_streaming_guardrails_enabled,
        streaming_release_hold_chars=settings.zdg_streaming_release_hold_chars,
    )
    trace = artifacts.trace

    if trace.idempotency.replay_hit and artifacts.cached_response_json:
        cached_response = json.loads(artifacts.cached_response_json)
        cached_response["idempotent_replay"] = True
        response = ActionResponse(**cached_response)
        log_decision(
            state.logger,
            request_id=request_id,
            trace_id=response.trace_id,
            chain_id=settings.zdg_chain_id,
            attempt_id=response.attempt_id,
            decision_id=response.decision_id,
            agent_id=response.agent_id,
            tool_family=response.tool_family,
            decision=response.decision.value,
            reason_code=response.reason_code.value,
            risk_score=response.risk_score,
            duration_ms=round((perf_counter() - started_at) * 1000, 2),
            idempotent_replay=True,
            guardrail_blocked=bool(response.guardrails and response.guardrails.blocked),
            guardrail_checks_triggered=len(
                [check for check in (response.guardrails.checks if response.guardrails else []) if check.triggered]
            ),
            streaming_mode=(
                response.guardrails.streaming_plan.mode.value
                if response.guardrails is not None
                else "buffered"
            ),
        )
        return response

    if body.approval_id and trace.approval.checked and not trace.approval.matched:
        status_code = 404 if trace.approval.reason_code == ReasonCode.APPROVAL_NOT_FOUND else (
            403 if trace.approval.reason_code == ReasonCode.APPROVAL_EXPIRED else 409
        )
        raise HTTPException(
            status_code=status_code,
            detail={
                "reason_code": trace.approval.reason_code,
                "reason": trace.approval.reason,
                "approval_id": body.approval_id,
            },
        )

    execution_context = _build_execution_context(
        settings=settings,
        bundle=bundle,
        request_id=request_id,
        trace_id=trace_id,
        attempt_id=attempt_id,
        session_id=body.session_id,
        agent_id=body.agent_id,
        tool_family=body.tool_family,
        authority_context=trace.authority_context,
        credential_grant=None,
    )

    if (
        trace.final_decision.decision == Decision.ALLOW
        and _requires_real_exec_idempotency(body=body, context=execution_context)
        and not body.idempotency_key
    ):
        raise HTTPException(
            status_code=400,
            detail={
                "reason_code": ReasonCode.IDEMPOTENCY_KEY_REQUIRED,
                "reason": (
                    "Mutating real execution requires an idempotency_key so retries "
                    "cannot duplicate side effects."
                ),
                "tool_family": body.tool_family,
                "action": body.action,
            },
        )

    if trace.final_decision.decision == Decision.ALLOW:
        authority_failure = credentialing.validate_authority_context(
            body=body,
            authority_context=trace.authority_context,
            context=execution_context,
            evaluation_time=timestamp,
        )
        if authority_failure is not None:
            reason_code, reason = authority_failure
            return _build_lifecycle_block_response(
                session=session,
                state=state,
                bundle=bundle,
                body=body,
                trace=trace,
                attempt_id=attempt_id,
                decision_id=decision_id,
                trace_id=trace_id,
                timestamp=timestamp,
                request_id=request_id,
                started_at=started_at,
                reason_code=reason_code,
                reason=reason,
            )

    final_decision = trace.final_decision.decision
    final_reason_code = trace.final_decision.reason_code
    final_reason = trace.final_decision.reason
    final_risk_score = trace.final_decision.risk_score
    final_triggered_rules = trace.final_decision.triggered_rules
    approval_id: str | None = None
    approval_expires_at: datetime | None = None
    approval_consumed = False
    credential_grant: CredentialGrant | None = None
    bound_contract: AgentContract | None = None
    handoff_envelope: HandoffEnvelope | None = None
    handoff_schema: HandoffSchema | None = None
    handoff_result: HandoffValidationResult | None = None
    wrapper_result: WrapperResult | None = None
    execution_status: str | None = None
    execution_outcome: ExecutionOutcome | None = None

    _persist_attempt(
        session=session,
        attempt_id=attempt_id,
        body=body,
        normalized_payload=trace.normalized_payload,
        payload_hash=trace.payload_hash,
        normalization_status=trace.normalization_status,
        authority_context=trace.authority_context,
    )
    session.flush()


    if final_decision == Decision.ALLOW:
        try:
            wrapper = get_wrapper(body.tool_family)
        except UnregisteredToolFamily as exc:
            final_decision = Decision.BLOCK
            final_reason_code = ReasonCode.UNREGISTERED_TOOL_FAMILY
            final_reason = str(exc)
            final_risk_score = 0
            final_triggered_rules = []
        else:
            if credentialing.requires_scoped_credential(body, execution_context):
                credential_grant = credentialing.issue_credential_grant(
                    session=session,
                    authority_context=trace.authority_context,
                    body=body,
                    ttl_seconds=settings.zdg_credential_ttl_seconds,
                    issued_at=timestamp,
                )
                _append_credential_audit_event(
                    session=session,
                    state=state,
                    event_type="CREDENTIAL_ISSUED",
                    grant=credential_grant,
                    authority_context=trace.authority_context,
                    related_attempt_id=attempt_id,
                )
                credential_grant = credentialing.activate_credential_grant(
                    session=session,
                    grant_id=credential_grant.grant_id,
                    activated_at=timestamp,
                )
                _append_credential_audit_event(
                    session=session,
                    state=state,
                    event_type="CREDENTIAL_ACTIVATED",
                    grant=credential_grant,
                    authority_context=trace.authority_context,
                    related_attempt_id=attempt_id,
                )
                # ── High-Integrity Credential Usage (Mission 1) ──────────────
                append_audit_event_with_session_chain(
                    session=session,
                    global_chain_id=settings.zdg_chain_id,
                    session_id=body.session_id,
                    event_type=CREDENTIAL_USED,
                    event_payload={
                        "timestamp": timestamp.isoformat(),
                        "attempt_id": attempt_id,
                        "grant_id": credential_grant.grant_id,
                        "lease_state": credential_grant.lease_state.value,
                        "agent_id": body.agent_id,
                        "tool_family": body.tool_family,
                        "action": body.action,
                    },
                    related_attempt_id=attempt_id,
                )
                execution_context = _build_execution_context(
                    settings=settings,
                    bundle=bundle,
                    request_id=request_id,
                    trace_id=trace_id,
                    attempt_id=attempt_id,
                    session_id=body.session_id,
                    agent_id=body.agent_id,
                    tool_family=body.tool_family,
                    authority_context=trace.authority_context,
                    credential_grant=credential_grant,
                )

            _contract_bound_at = utc_now()
            _contract_expires_at = _contract_bound_at + timedelta(
                seconds=settings.zdg_contract_ttl_seconds
            )
            bound_contract = contracts_manager.bind_contract(
                session=session,
                authority_context=trace.authority_context,
                bound_at=_contract_bound_at,
                expires_at=_contract_expires_at,
            )
            append_audit_event_with_session_chain(
                session=session,
                global_chain_id=settings.zdg_chain_id,
                session_id=body.session_id,
                event_type="CONTRACT_BOUND",
                event_payload={
                    "contract_id": bound_contract.contract_id,
                    "run_id": bound_contract.run_id,
                    "session_id": bound_contract.session_id,
                    "trace_id": bound_contract.trace_id,
                    "actor_id": bound_contract.actor_id,
                    "agent_id": bound_contract.agent_id,
                    "delegation_chain_id": bound_contract.delegation_chain_id,
                    "allowed_tool_families": bound_contract.allowed_tool_families,
                    "contract_state": bound_contract.contract_state.value,
                    "bound_at": bound_contract.bound_at.isoformat(),
                    "expires_at": (
                        bound_contract.expires_at.isoformat()
                        if bound_contract.expires_at is not None
                        else None
                    ),
                    "attempt_id": attempt_id,
                    "decision_id": decision_id,
                    "tool_family": body.tool_family,
                    "action": body.action,
                },
                related_attempt_id=attempt_id,
            )

            handoff_envelope = handoffs.build_handoff_envelope(
                authority_context=trace.authority_context,
                tool_family=body.tool_family,
                action=body.action,
                args=body.args,
                timestamp=utc_now(),
            )
            handoff_envelope.contract_id = bound_contract.contract_id
            _append_handoff_audit_event(
                session=session,
                state=state,
                event_type="HANDOFF_ATTEMPTED",
                body=body,
                authority_context=trace.authority_context,
                handoff_envelope=handoff_envelope,
                handoff_schema=None,
                handoff_result=None,
                related_attempt_id=attempt_id,
                contract_id=bound_contract.contract_id,
            )

            handoff_schema = handoffs.resolve_handoff_schema(body.tool_family, body.action)
            if handoff_schema is not None:
                handoff_envelope.schema_version = handoff_schema.schema_version
            _append_handoff_audit_event(
                session=session,
                state=state,
                event_type="HANDOFF_SCHEMA_RESOLVED",
                body=body,
                authority_context=trace.authority_context,
                handoff_envelope=handoff_envelope,
                handoff_schema=handoff_schema,
                handoff_result=None,
                related_attempt_id=attempt_id,
                contract_id=bound_contract.contract_id,
            )

            handoff_result = handoffs.validate_handoff(handoff_envelope, handoff_schema)
            handoff_envelope.validation_state = handoff_result.validation_state
            handoff_envelope.disposition = handoff_result.disposition
            _persist_handoff(
                session=session,
                attempt_id=attempt_id,
                handoff_envelope=handoff_envelope,
                handoff_result=handoff_result,
            )
            _append_handoff_audit_event(
                session=session,
                state=state,
                event_type=(
                    "HANDOFF_VALIDATION_PASSED"
                    if handoff_result.valid
                    else "HANDOFF_VALIDATION_FAILED"
                ),
                body=body,
                authority_context=trace.authority_context,
                handoff_envelope=handoff_envelope,
                handoff_schema=handoff_schema,
                handoff_result=handoff_result,
                related_attempt_id=attempt_id,
                contract_id=bound_contract.contract_id,
            )

            if not handoff_result.valid:
                final_decision = Decision.BLOCK
                final_reason_code = (
                    ReasonCode.HANDOFF_SCHEMA_NOT_FOUND
                    if handoff_schema is None
                    else ReasonCode.HANDOFF_VALIDATION_FAILED
                )
                final_reason = "; ".join(handoff_result.errors)
                final_risk_score = 0
                final_triggered_rules = []

                _append_handoff_audit_event(
                    session=session,
                    state=state,
                    event_type="HANDOFF_PROPAGATION_PREVENTED",
                    body=body,
                    authority_context=trace.authority_context,
                    handoff_envelope=handoff_envelope,
                    handoff_schema=handoff_schema,
                    handoff_result=handoff_result,
                    related_attempt_id=attempt_id,
                    contract_id=bound_contract.contract_id,
                )
                _append_handoff_audit_event(
                    session=session,
                    state=state,
                    event_type="HANDOFF_DISPOSITION_APPLIED",
                    body=body,
                    authority_context=trace.authority_context,
                    handoff_envelope=handoff_envelope,
                    handoff_schema=handoff_schema,
                    handoff_result=handoff_result,
                    related_attempt_id=attempt_id,
                    contract_id=bound_contract.contract_id,
                )
                if credential_grant is not None:
                    credential_grant = credentialing.revoke_credential_grant(
                        session=session,
                        grant_id=credential_grant.grant_id,
                        revoked_reason="handoff_blocked",
                        revoked_by=trace.authority_context.actor_identity.actor_id,
                        revoked_at=utc_now(),
                    )
                    if credential_grant is not None:
                        _append_credential_audit_event(
                            session=session,
                            state=state,
                            event_type="CREDENTIAL_REVOKED",
                            grant=credential_grant,
                            authority_context=trace.authority_context,
                            related_attempt_id=attempt_id,
                        )
            else:
                _append_handoff_audit_event(
                    session=session,
                    state=state,
                    event_type="HANDOFF_PROPAGATION_ALLOWED",
                    body=body,
                    authority_context=trace.authority_context,
                    handoff_envelope=handoff_envelope,
                    handoff_schema=handoff_schema,
                    handoff_result=handoff_result,
                    related_attempt_id=attempt_id,
                    contract_id=bound_contract.contract_id,
                )

                if body.session_id is not None:
                    _session_usage = contracts_manager.query_session_usage(
                        session=session, session_id=body.session_id
                    )
                    _candidate_fields = []
                    if _session_usage.invocation_count >= settings.zdg_breach_warn_session_invocations:
                        _candidate_fields.append("session_invocation_count")
                    if _session_usage.elapsed_ms_total >= settings.zdg_breach_warn_session_elapsed_ms:
                        _candidate_fields.append("session_elapsed_ms_total")
                    # Deduplicate: only emit for threshold types not already warned this session.
                    _already_warned = contracts_manager.get_warned_breach_fields(
                        session=session, session_id=body.session_id
                    )
                    _breach_fields = [f for f in _candidate_fields if f not in _already_warned]
                    if _breach_fields:
                        append_audit_event_with_session_chain(
                            session=session,
                            global_chain_id=settings.zdg_chain_id,
                            session_id=body.session_id,
                            event_type="BREACH_WARN",
                            event_payload={
                                "contract_id": bound_contract.contract_id,
                                "run_id": attempt_id,
                                "session_id": body.session_id,
                                "breach_fields": _breach_fields,
                                "session_invocation_count": _session_usage.invocation_count,
                                "session_elapsed_ms_total": _session_usage.elapsed_ms_total,
                                "threshold_invocations": settings.zdg_breach_warn_session_invocations,
                                "threshold_elapsed_ms": settings.zdg_breach_warn_session_elapsed_ms,
                                "disposition": "warn",
                                "reference_time": timestamp.isoformat(),
                            },
                            related_attempt_id=attempt_id,
                        )
                        # ── High-Integrity Contract Breach (Mission 1) ──────────────
                        append_audit_event_with_session_chain(
                            session=session,
                            global_chain_id=settings.zdg_chain_id,
                            session_id=body.session_id,
                            event_type=CONTRACT_BREACHED,
                            event_payload={
                                "timestamp": timestamp.isoformat(),
                                "attempt_id": attempt_id,
                                "contract_id": bound_contract.contract_id,
                                "breach_type": "soft_warn",
                                "breached_fields": _breach_fields,
                                "disposition": "warn",
                            },
                            related_attempt_id=attempt_id,
                        )

                # Escalation check: emit BREACH_ESCALATED once when accumulated
                # BREACH_WARN count reaches the configured threshold.
                if (
                    body.session_id is not None
                    and settings.zdg_breach_escalation_warn_count > 0
                ):
                    from db.models import AuditEvent as _AuditEvent
                    from sqlmodel import func as _func, select as _select

                    _breach_warn_count: int = session.exec(
                        _select(_func.count()).where(
                            _AuditEvent.chain_id == f"session:{body.session_id}",
                            _AuditEvent.event_type == "BREACH_WARN",
                        )
                    ).one()
                    if (
                        _breach_warn_count >= settings.zdg_breach_escalation_warn_count
                        and not contracts_manager.has_breach_escalation(
                            session=session, session_id=body.session_id
                        )
                    ):
                        append_audit_event_with_session_chain(
                            session=session,
                            global_chain_id=settings.zdg_chain_id,
                            session_id=body.session_id,
                            event_type="BREACH_ESCALATED",
                            event_payload={
                                "session_id": body.session_id,
                                "contract_id": bound_contract.contract_id,
                                "breach_warn_count": _breach_warn_count,
                                "escalation_threshold": settings.zdg_breach_escalation_warn_count,
                                "reference_time": timestamp.isoformat(),
                                "disposition": "escalate",
                            },
                            related_attempt_id=attempt_id,
                        )
                        # ── High-Integrity Contract Breach (Mission 1) ──────────────
                        append_audit_event_with_session_chain(
                            session=session,
                            global_chain_id=settings.zdg_chain_id,
                            session_id=body.session_id,
                            event_type=CONTRACT_BREACHED,
                            event_payload={
                                "timestamp": timestamp.isoformat(),
                                "attempt_id": attempt_id,
                                "contract_id": bound_contract.contract_id,
                                "breach_type": "escalation",
                                "breach_warn_count": _breach_warn_count,
                                "disposition": "block",
                            },
                            related_attempt_id=attempt_id,
                        )


                wrapper.context = execution_context
                revoke_reason = "execution_completed"
                try:
                    wrapper_result = wrapper.run(body.args)
                    execution_status = (
                        "mock_success"
                        if wrapper_result.mock
                        else ("blocked" if wrapper_result.blocked_reason else "success")
                    )
                    execution_outcome = _build_execution_outcome(wrapper_result, execution_status)
                    session.add(
                        ExecutionResult(
                            result_id=f"res_{uuid.uuid4().hex[:16]}",
                            attempt_id=attempt_id,
                            executed=wrapper_result.executed,
                            mock=wrapper_result.mock,
                            execution_status=execution_status,
                            output_summary=wrapper_result.output_summary,
                            blocked_reason=wrapper_result.blocked_reason,
                            raw_output_json=(
                                json.dumps(wrapper_result.raw_output, default=str)
                                if wrapper_result.raw_output is not None
                                else None
                            ),
                        )
                    )
                    log_execution(
                        state.logger,
                        request_id=request_id,
                        trace_id=trace_id,
                        attempt_id=attempt_id,
                        agent_id=body.agent_id,
                        tool_family=body.tool_family,
                        executed=wrapper_result.executed,
                        mock=wrapper_result.mock,
                        execution_status=execution_status,
                        blocked=bool(wrapper_result.blocked_reason),
                    )
                    if bound_contract is not None:
                        _elapsed_ms = (perf_counter() - started_at) * 1000
                        usage_record = contracts_manager.record_usage(
                            session=session,
                            contract=bound_contract,
                            elapsed_ms=_elapsed_ms,
                            tool_invocations=1,
                        )
                        append_audit_event_with_session_chain(
                            session=session,
                            global_chain_id=settings.zdg_chain_id,
                            session_id=body.session_id,
                            event_type="CONTRACT_USAGE_UPDATED",
                            event_payload={
                                "usage_id": usage_record.usage_id,
                                "contract_id": usage_record.contract_id,
                                "run_id": usage_record.run_id,
                                "elapsed_ms": usage_record.elapsed_ms,
                                "tool_invocations": usage_record.tool_invocations,
                                "tokens_used": usage_record.tokens_used,
                                "spend_used": usage_record.spend_used,
                                "current_state": usage_record.current_state.value,
                                "last_updated_at": usage_record.last_updated_at.isoformat(),
                            },
                            related_attempt_id=attempt_id,
                        )
                    if wrapper_result.blocked_reason and execution_context.is_real_exec_enabled(body.tool_family):
                        final_decision = Decision.BLOCK
                        final_reason_code = ReasonCode.WRAPPER_BLOCKED
                        final_reason = wrapper_result.blocked_reason
                        revoke_reason = "wrapper_blocked"
                except Exception:
                    revoke_reason = "execution_failed"
                    raise
                finally:
                    wrapper.context = ExecutionContext()
                    if credential_grant is not None:
                        credential_grant = credentialing.revoke_credential_grant(
                            session=session,
                            grant_id=credential_grant.grant_id,
                            revoked_reason=revoke_reason,
                            revoked_by=trace.authority_context.actor_identity.actor_id,
                            revoked_at=utc_now(),
                        )
                        if credential_grant is not None:
                            _append_credential_audit_event(
                                session=session,
                                state=state,
                                event_type="CREDENTIAL_REVOKED",
                                grant=credential_grant,
                                authority_context=trace.authority_context,
                                related_attempt_id=attempt_id,
                            )

    decision_envelope = decision_engine.build_enforcement_decision(
        decision=final_decision,
        reason_code=final_reason_code,
        reason=final_reason,
        risk_score=final_risk_score,
        triggered_rules=final_triggered_rules,
        payload_hash=trace.payload_hash,
        policy_bundle_id=bundle.bundle_id,
        policy_bundle_version=bundle.version,
        ruleset_hash=bundle.ruleset_hash,
        killswitch_scope=(
            trace.final_decision.killswitch_scope
            if final_reason_code == ReasonCode.KILLSWITCH_ACTIVE
            else None
        ),
        authority_context=trace.authority_context,
        effective_at=timestamp,
    )

    audit_event_type = _decision_audit_event_type(decision_envelope)

    _persist_decision(
        session=session,
        decision_id=decision_id,
        attempt_id=attempt_id,
        decision=decision_envelope,
    )
    session.flush()

    # ── High-Integrity Terminal Event (Mission 1) ────────────────────────────
    # Immutable fact recording the final decision and its context.
    _append_decision_finalized_event(
        session=session,
        state=state,
        body=body,
        trace=trace,
        decision=decision_envelope,
        attempt_id=attempt_id,
        decision_id=decision_id,
        timestamp=timestamp,
    )

    if trace.guardrails.checks:
        append_audit_event_with_session_chain(
            session=session,
            global_chain_id=settings.zdg_chain_id,
            session_id=body.session_id,
            event_type="GUARDRAIL_EVALUATED",
            event_payload=_build_runtime_event_payload(
                timestamp=timestamp,
                source_component="agent_firewall.guardrails",
                body=body,
                authority_context=trace.authority_context,
                decision=decision_envelope,
                handoff_id=(
                    handoff_envelope.handoff_id
                    if handoff_envelope is not None
                    else None
                ),
                extra={
                    "attempt_id": attempt_id,
                    "decision_id": decision_id,
                    "tool_family": body.tool_family,
                    "action": body.action,
                    "execution_mode": trace.guardrails.execution_mode,
                    "total_duration_ms": trace.guardrails.total_duration_ms,
                    "blocked": trace.guardrails.blocked,
                    "block_reason": trace.guardrails.block_reason,
                    "checks": [check.model_dump(mode="json") for check in trace.guardrails.checks],
                    "streaming_plan": trace.guardrails.streaming_plan.model_dump(mode="json"),
                    "authority_context": (
                        trace.authority_context.model_dump(mode="json")
                        if trace.authority_context is not None
                        else None
                    ),
                    "enforcement_decision": decision_envelope.model_dump(mode="json"),
                },
            ),
            related_attempt_id=attempt_id,
        )

    append_audit_event_with_session_chain(
        session=session,
        global_chain_id=settings.zdg_chain_id,
        session_id=body.session_id,
        event_type=audit_event_type,
        event_payload=_build_runtime_event_payload(
            timestamp=timestamp,
            source_component=decision_engine.source_component_for_decision(decision_envelope),
            body=body,
            authority_context=trace.authority_context,
            decision=decision_envelope,
            handoff_id=(
                handoff_envelope.handoff_id
                if handoff_envelope is not None
                else None
            ),
            extra={
                "attempt_id": attempt_id,
                "decision_id": decision_id,
                "tool_family": body.tool_family,
                "action": body.action,
                "reason_code": decision_envelope.reason_code.value,
                "risk_score": decision_envelope.risk_score,
                "policy_bundle_version": decision_envelope.policy_bundle_version,
                "ruleset_hash": decision_envelope.ruleset_hash,
                "guardrail_blocked": trace.guardrails.blocked,
                "guardrail_total_duration_ms": trace.guardrails.total_duration_ms,
                "streaming_mode": trace.guardrails.streaming_plan.mode.value,
                "module_origin": decision_envelope.module_origin.value,
                "gal_stage": decision_envelope.gal_stage.value,
                "handoff_validation_state": (
                    handoff_result.validation_state.value
                    if handoff_result is not None
                    else None
                ),
                "handoff_schema_version": (
                    handoff_result.schema_version
                    if handoff_result is not None
                    else None
                ),
                "authority_context": (
                    trace.authority_context.model_dump(mode="json")
                    if trace.authority_context is not None
                    else None
                ),
            },
        ),
        related_attempt_id=attempt_id,
    )

    if wrapper_result is not None and execution_status is not None:
        append_audit_event_with_session_chain(
            session=session,
            global_chain_id=settings.zdg_chain_id,
            session_id=body.session_id,
            event_type=_execution_audit_event_type(wrapper_result),
            event_payload=_build_runtime_event_payload(
                timestamp=utc_now(),
                source_component="agent_firewall.execution",
                body=body,
                authority_context=trace.authority_context,
                decision=decision_envelope,
                handoff_id=(
                    handoff_envelope.handoff_id
                    if handoff_envelope is not None
                    else None
                ),
                extra={
                    "attempt_id": attempt_id,
                    "decision_id": decision_id,
                    "tool_family": body.tool_family,
                    "action": body.action,
                    "executed": wrapper_result.executed,
                    "mock": wrapper_result.mock,
                    "execution_status": execution_status,
                    "blocked_reason": wrapper_result.blocked_reason,
                    "output_summary": wrapper_result.output_summary,
                },
            ),
            related_attempt_id=attempt_id,
        )

    if final_decision == Decision.APPROVAL_REQUIRED:
        approval_id, approval_expires_at = approval_manager.create_approval(
            session=session,
            decision_id=decision_id,
            policy_bundle_version=bundle.version,
            agent_id=body.agent_id,
            tool_family=body.tool_family,
            action=body.action,
            payload_hash=trace.payload_hash,
            risk_score=decision_envelope.risk_score,
            triggered_rules=decision_envelope.triggered_rules,
            reason=decision_envelope.reason,
            expiry_seconds=settings.zdg_approval_expiry_seconds,
        )

    if final_decision == Decision.ALLOW and trace.approval.matched and body.approval_id:
        consumed, consume_reason_code, consume_reason = approval_manager.consume_approval(
            session=session,
            approval_id=body.approval_id,
            attempt_id=attempt_id,
        )
        if not consumed:
            status_code = 404 if consume_reason_code == ReasonCode.APPROVAL_NOT_FOUND else (
                403 if consume_reason_code == ReasonCode.APPROVAL_EXPIRED else 409
            )
            raise HTTPException(
                status_code=status_code,
                detail={
                    "reason_code": consume_reason_code,
                    "reason": consume_reason,
                    "approval_id": body.approval_id,
                },
            )
        approval_consumed = True
        approval_id = body.approval_id
        append_audit_event_with_session_chain(
            session=session,
            global_chain_id=settings.zdg_chain_id,
            session_id=body.session_id,
            event_type="APPROVAL_CONSUMED",
            event_payload=_build_runtime_event_payload(
                timestamp=utc_now(),
                source_component="agent_firewall.approval",
                body=body,
                authority_context=trace.authority_context,
                decision=decision_envelope,
                extra={
                "attempt_id": attempt_id,
                "decision_id": decision_id,
                "approval_id": body.approval_id,
                "tool_family": body.tool_family,
                "action": body.action,
                "reason_code": consume_reason_code.value,
                },
            ),
            related_attempt_id=attempt_id,
        )

    should_auto_trigger_killswitch = decision_envelope.decision == Decision.BLOCK and decision_envelope.reason_code not in {
        ReasonCode.KILLSWITCH_ACTIVE,
        ReasonCode.UNREGISTERED_TOOL_FAMILY,
        ReasonCode.WRAPPER_BLOCKED,
    }
    if should_auto_trigger_killswitch:
        ks_manager.check_auto_trigger(
            session=session,
            tool_family=body.tool_family,
            agent_id=body.agent_id,
            shell_block_count=settings.zdg_ks_shell_block_count,
            shell_block_window=settings.zdg_ks_shell_block_window,
            http_block_count=settings.zdg_ks_http_block_count,
            http_block_window=settings.zdg_ks_http_block_window,
            escalate_count=settings.zdg_ks_escalate_count,
        )

    session.commit()

    response = ActionResponse(
        trace_id=trace_id,
        attempt_id=attempt_id,
        decision_id=decision_id,
        session_id=body.session_id,
        agent_id=body.agent_id,
        tool_family=body.tool_family,
        action=body.action,
        decision=decision_envelope.decision,
        reason_code=decision_envelope.reason_code,
        reason=decision_envelope.reason,
        risk_score=decision_envelope.risk_score,
        triggered_rules=decision_envelope.triggered_rules,
        payload_hash=decision_envelope.payload_hash,
        policy_bundle_id=decision_envelope.policy_bundle_id,
        policy_bundle_version=decision_envelope.policy_bundle_version,
        ruleset_hash=decision_envelope.ruleset_hash,
        approval_id=approval_id,
        approval_expires_at=approval_expires_at,
        approval_consumed=approval_consumed,
        killswitch_scope=decision_envelope.killswitch_scope,
        authority_context=trace.authority_context,
        credential_grant=credential_grant,
        contract_id=bound_contract.contract_id if bound_contract is not None else None,
        enforcement_decision=decision_envelope,
        execution=execution_outcome,
        guardrails=trace.guardrails,
        timestamp=timestamp,
    )

    if body.idempotency_key:
        session.add(
            IdempotencyCache(
                idempotency_key=body.idempotency_key,
                agent_id=body.agent_id,
                approval_id=body.approval_id,
                payload_hash=trace.payload_hash,
                attempt_id=attempt_id,
                response_json=response.model_dump_json(),
                expires_at=timestamp + timedelta(seconds=settings.zdg_idempotency_window_seconds),
            )
        )
        session.commit()

    log_decision(
        state.logger,
        request_id=request_id,
        trace_id=trace_id,
        chain_id=settings.zdg_chain_id,
        attempt_id=attempt_id,
        decision_id=decision_id,
        agent_id=body.agent_id,
        tool_family=body.tool_family,
        decision=decision_envelope.decision.value,
        reason_code=decision_envelope.reason_code.value,
        risk_score=decision_envelope.risk_score,
        duration_ms=round((perf_counter() - started_at) * 1000, 2),
        approval_consumed=approval_consumed,
        idempotent_replay=False,
        guardrail_blocked=trace.guardrails.blocked,
        guardrail_checks_triggered=len([check for check in trace.guardrails.checks if check.triggered]),
        streaming_mode=trace.guardrails.streaming_plan.mode.value,
    )

    return response


def _check_lifecycle_block(session: Session, body: ActionRequest) -> tuple[ReasonCode, str] | None:
    # Lifecycle block precedence order (first match wins):
    #   1. IDENTITY_FAILED   — agent_id mismatch for this session
    #   2. SESSION_CLOSED    — terminal session state; no recovery path
    #   3. SESSION_SUSPENDED — operator-reversible session pause
    #   4. CONTRACT_EXPIRED  — TTL elapsed; operator can renew
    #   5. AGENT_SUSPENDED   — agent globally suspended (checked before CONTRACT_REVOKED)
    #   6. CONTRACT_REVOKED  — explicit contract revocation (kill switch, manual revoke)
    #   7. BREACH_ESCALATED  — accumulated breach warnings; operator review required
    #
    # AGENT_SUSPENDED (5) is intentionally ordered before CONTRACT_REVOKED (6).
    # The agent-suspend handler (api/routes/agents.py) automatically revokes all active
    # contracts as a side-effect of suspension. If CONTRACT_REVOKED were checked first,
    # the root cause (agent is suspended) would be masked by the derived state (contract
    # was revoked because the agent was suspended). Surfacing AGENT_SUSPENDED gives the
    # operator the correct remediation path: unsuspend the agent first, then reinstate
    # the contract. CONTRACT_REVOKED still fires correctly in cases where contracts are
    # revoked independently of agent state (kill switch reset, manual revocation).

    if body.session_id:
        session_info = session_manager.get_session_info(session=session, session_id=body.session_id)
        if session_info is not None:
            bound_agent_id = session_info.get("agent_id")
            if bound_agent_id and bound_agent_id != body.agent_id:
                return ReasonCode.IDENTITY_FAILED, (
                    f"Session '{body.session_id}' is bound to agent '{bound_agent_id}', not '{body.agent_id}'."
                )
            if session_info["status"] == "closed":
                return ReasonCode.SESSION_CLOSED, f"Session '{body.session_id}' is closed."
            if session_info["status"] == "suspended":
                return ReasonCode.SESSION_SUSPENDED, f"Session '{body.session_id}' is suspended."

        # Expiry gate: block if any contract in this session has expired.
        # expire_active_contracts() is called before this function so ACTIVE→EXPIRED
        # transitions are already persisted; this gate reads the resulting state.
        if contracts_manager.has_expired_contract(session=session, session_id=body.session_id):
            return (
                ReasonCode.CONTRACT_EXPIRED,
                f"Session '{body.session_id}' has an expired contract. "
                "The contract TTL has elapsed. Start a new session to continue.",
            )

    # Agent gate: checked here (between CONTRACT_EXPIRED and CONTRACT_REVOKED) so that
    # when agent suspension triggers automatic contract revocation, AGENT_SUSPENDED
    # surfaces as the reason code rather than the derived CONTRACT_REVOKED state.
    # This gate fires for both session and non-session requests.
    agent_info = agent_manager.get_agent(session=session, agent_id=body.agent_id)
    if agent_info is not None and agent_info["status"] == "suspended":
        return ReasonCode.AGENT_SUSPENDED, f"Agent '{body.agent_id}' is suspended."

    if body.session_id:
        # Revocation gate: block if any contract in this session was revoked.
        # Covers kill-switch-driven and manual revocations that are independent of
        # agent state. Agent-level historical revocations from prior sessions are
        # intentionally excluded to avoid false positives.
        if contracts_manager.has_revoked_contract(session=session, session_id=body.session_id):
            return (
                ReasonCode.CONTRACT_REVOKED,
                f"Session '{body.session_id}' has a revoked contract. "
                "Execution is blocked until the session is re-established.",
            )

        # Escalation gate: block if BREACH_ESCALATED event exists in the session chain.
        # Emitted by the evaluate path when accumulated BREACH_WARN count hits threshold.
        # Requires operator review; no automatic clearance path.
        if contracts_manager.has_breach_escalation(session=session, session_id=body.session_id):
            return (
                ReasonCode.BREACH_ESCALATED,
                f"Session '{body.session_id}' has been escalated due to repeated breach "
                "warnings. Operator review required before execution can resume.",
            )

    return None


def _build_lifecycle_block_response(
    session: Session,
    state: AppState,
    bundle: PolicyBundle,
    body: ActionRequest,
    authority_context,
    attempt_id: str,
    decision_id: str,
    trace_id: str,
    timestamp: datetime,
    request_id: str | None,
    started_at: float,
    reason_code: ReasonCode,
    reason: str,
) -> ActionResponse:
    decision_envelope = decision_engine.build_enforcement_decision(
        decision=Decision.BLOCK,
        reason_code=reason_code,
        reason=reason,
        risk_score=0,
        triggered_rules=[],
        payload_hash="lifecycle:blocked",
        policy_bundle_id=bundle.bundle_id,
        policy_bundle_version=bundle.version,
        ruleset_hash=bundle.ruleset_hash,
        authority_context=authority_context,
        effective_at=timestamp,
    )

    _persist_decision(
        session=session,
        decision_id=decision_id,
        attempt_id=attempt_id,
        decision=decision_envelope,
    )
    session.flush()

    append_audit_event_with_session_chain(
        session=session,
        global_chain_id=state.settings.zdg_chain_id,
        session_id=body.session_id,
        event_type="ACTION_BLOCKED",
        event_payload={
            "timestamp": timestamp.isoformat(),
            "source_component": decision_engine.source_component_for_decision(decision_envelope),
            "attempt_id": attempt_id,
            "decision_id": decision_id,
            "agent_id": body.agent_id,
            "tool_family": body.tool_family,
            "action": body.action,
            "session_id": body.session_id,
            "reason_code": reason_code.value,
            "risk_score": 0,
            "policy_bundle_version": bundle.version,
            "ruleset_hash": bundle.ruleset_hash,
            "module_origin": decision_envelope.module_origin.value,
            "gal_stage": decision_envelope.gal_stage.value,
            "authority_context": (
                authority_context.model_dump(mode="json")
                if authority_context is not None
                else None
            ),
        },
        related_attempt_id=attempt_id,
    )
    session.commit()

    response = ActionResponse(
        trace_id=trace_id,
        attempt_id=attempt_id,
        decision_id=decision_id,
        session_id=body.session_id,
        agent_id=body.agent_id,
        tool_family=body.tool_family,
        action=body.action,
        decision=Decision.BLOCK,
        reason_code=reason_code,
        reason=reason,
        risk_score=0,
        triggered_rules=[],
        payload_hash="lifecycle:blocked",
        policy_bundle_id=bundle.bundle_id,
        policy_bundle_version=bundle.version,
        ruleset_hash=bundle.ruleset_hash,
        approval_id=None,
        approval_expires_at=None,
        approval_consumed=False,
        killswitch_scope=None,
        authority_context=authority_context,
        enforcement_decision=decision_envelope,
        execution=None,
        timestamp=timestamp,
    )
    log_decision(
        state.logger,
        request_id=request_id,
        trace_id=trace_id,
        chain_id=state.settings.zdg_chain_id,
        attempt_id=attempt_id,
        decision_id=decision_id,
        agent_id=body.agent_id,
        tool_family=body.tool_family,
        decision=Decision.BLOCK.value,
        reason_code=reason_code.value,
        risk_score=0,
        duration_ms=round((perf_counter() - started_at) * 1000, 2),
        approval_consumed=False,
        idempotent_replay=False,
    )
    return response


def _build_authority_context(
    settings: Settings,
    bundle: PolicyBundle,
    body: ActionRequest,
    payload_hash: str,
    evaluation_time: datetime,
    run_id: str,
    trace_id: str,
) -> RunAuthorityContext:
    # Minimal resolution for lifecycle blocks
    from core.evaluation import _resolve_actor_identity, _resolve_delegation_chain
    actor_identity = _resolve_actor_identity(body)
    # Note: agent identity resolution is skipped here as we already have agent_id
    # and we want to keep lifecycle blocks as fast as possible.
    return RunAuthorityContext(
        run_id=run_id,
        session_id=body.session_id,
        trace_id=trace_id,
        actor_identity=actor_identity,
        agent_identity=AgentIdentity(
            agent_id=body.agent_id,
            allowed_tool_families=[body.tool_family],
            lifecycle_state="active",
        ),
        delegation_chain=_resolve_delegation_chain(
            body=body,
            actor_identity=actor_identity,
            agent_identity=AgentIdentity(agent_id=body.agent_id, allowed_tool_families=[body.tool_family], lifecycle_state="active"),
            evaluation_time=evaluation_time,
            payload_hash=payload_hash,
        ),
        requested_tool_family=body.tool_family,
        requested_operation=body.action,
        policy_bundle_id=bundle.bundle_id,
        policy_bundle_version=bundle.version,
    )



def _build_execution_outcome(
    wrapper_result: WrapperResult,
    execution_status: str | None,
) -> ExecutionOutcome:
    return ExecutionOutcome(
        executed=wrapper_result.executed,
        mock=wrapper_result.mock,
        execution_status=execution_status,
        output_summary=wrapper_result.output_summary,
        blocked_reason=wrapper_result.blocked_reason,
        raw_output=wrapper_result.raw_output,
    )



def _persist_attempt(
    session: Session,
    attempt_id: str,
    body: ActionRequest,
    normalized_payload: dict,
    payload_hash: str,
    normalization_status: NormalizationStatus,
    authority_context=None,
) -> None:
    session.add(
        ToolAttempt(
            attempt_id=attempt_id,
            run_id=(
                authority_context.run_id
                if authority_context is not None
                else attempt_id
            ),
            trace_id=(
                authority_context.trace_id
                if authority_context is not None
                else None
            ),
            session_id=body.session_id,
            agent_id=body.agent_id,
            actor_id=(
                authority_context.actor_identity.actor_id
                if authority_context is not None
                else None
            ),
            delegation_chain_id=(
                authority_context.delegation_chain.delegation_chain_id
                if authority_context is not None
                else None
            ),
            runtime=body.runtime,
            tool_family=body.tool_family,
            action=body.action,
            raw_payload=json.dumps(body.args),
            normalized_payload=json.dumps(normalized_payload),
            payload_hash=payload_hash,
            normalization_status=normalization_status.value,
            idempotency_key=body.idempotency_key,
            authority_scope_json=(
                json.dumps(authority_context.delegation_chain.authority_scope or {})
                if authority_context is not None
                else None
            ),
            authority_context_json=(
                authority_context.model_dump_json()
                if authority_context is not None
                else None
            ),
        )
    )



def _persist_decision(
    session: Session,
    decision_id: str,
    attempt_id: str,
    decision: EnforcementDecision,
) -> None:
    session.add(
        PolicyDecision(
            decision_id=decision_id,
            attempt_id=attempt_id,
            policy_bundle_id=decision.policy_bundle_id,
            policy_bundle_version=decision.policy_bundle_version,
            ruleset_hash=decision.ruleset_hash,
            risk_score=decision.risk_score,
            decision=decision.decision.value,
            decision_state_canonical=decision.decision.value,
            disposition=decision_engine.disposition_for_decision(decision.decision).value,
            module_origin=decision.module_origin.value,
            source_component=decision_engine.source_component_for_decision(decision),
            reason_code=decision.reason_code.value,
            triggered_rules=json.dumps(decision.triggered_rules),
            reason=decision.reason,
        )
    )



def _build_execution_context(
    settings: Settings,
    bundle: PolicyBundle,
    request_id: str | None,
    trace_id: str,
    attempt_id: str,
    session_id: str | None,
    agent_id: str,
    tool_family: str,
    authority_context=None,
    credential_grant: CredentialGrant | None = None,
) -> ExecutionContext:
    return ExecutionContext(
        real_exec=settings.zdg_real_exec,
        real_exec_shell=settings.zdg_real_exec_shell,
        real_exec_http=settings.zdg_real_exec_http,
        real_exec_filesystem=settings.zdg_real_exec_filesystem,
        real_exec_messaging=settings.zdg_real_exec_messaging,
        workspace_root=settings.workspace_resolved,
        filesystem_allowed_roots=tuple(settings.filesystem_allowed_roots_resolved),
        fs_read_approval_bytes=settings.zdg_fs_read_approval_bytes,
        maildir_path=settings.maildir_path_resolved,
        bulk_send_threshold=bundle.bulk_send_threshold,
        approved_domains=tuple(bundle.approved_domains),
        approved_recipient_domains=tuple(bundle.approved_recipient_domains),
        shell_timeout_seconds=settings.zdg_shell_timeout_seconds,
        shell_max_output_bytes=settings.zdg_shell_max_output_bytes,
        shell_allowed_env=tuple(settings.zdg_shell_allowed_env),
        http_timeout_seconds=settings.zdg_http_timeout_seconds,
        http_max_response_bytes=settings.zdg_http_max_response_bytes,
        http_max_redirects=settings.zdg_http_max_redirects,
        request_id=request_id,
        trace_id=trace_id,
        attempt_id=attempt_id,
        session_id=session_id,
        agent_id=agent_id,
        actor_id=(
            authority_context.actor_identity.actor_id
            if authority_context is not None
            else None
        ),
        delegation_chain_id=(
            authority_context.delegation_chain.delegation_chain_id
            if authority_context is not None
            else None
        ),
        tool_family=tool_family,
        credential_grant_id=credential_grant.grant_id if credential_grant is not None else None,
        credential_lease_state=(
            credential_grant.lease_state.value
            if credential_grant is not None
            else None
        ),
        privilege_scope=(
            dict(credential_grant.privilege_scope)
            if credential_grant is not None
            else {}
        ),
    )



def _requires_real_exec_idempotency(body: ActionRequest, context: ExecutionContext) -> bool:
    if body.tool_family == "messaging" and context.is_real_exec_enabled("messaging"):
        return True
    if body.tool_family == "shell" and context.is_real_exec_enabled("shell"):
        return True
    if body.tool_family == "http" and context.is_real_exec_enabled("http"):
        method = str(body.args.get("method", "GET")).upper().strip()
        return method in {"POST", "PUT", "PATCH", "DELETE"}
    if body.tool_family != "filesystem" or not context.is_real_exec_enabled("filesystem"):
        return False
    operation = str(body.args.get("operation", "read")).lower().strip()
    return operation in {"write", "delete", "move"}



def _execution_audit_event_type(wrapper_result: WrapperResult) -> str:
    if wrapper_result.blocked_reason:
        return "EXECUTION_FAILED"
    return "EXECUTION_COMPLETED"


def _decision_audit_event_type(decision: EnforcementDecision) -> str:
    if decision.reason_code == ReasonCode.UNREGISTERED_TOOL_FAMILY:
        return "UNREGISTERED_TOOL_FAMILY"
    return {
        Decision.ALLOW: "ACTION_ALLOWED",
        Decision.WARN: "ACTION_ALLOWED",
        Decision.PAUSE: "ACTION_BLOCKED",
        Decision.BLOCK: "ACTION_BLOCKED",
        Decision.ESCALATE: "ACTION_BLOCKED",
        Decision.RETRY: "ACTION_BLOCKED",
        Decision.QUARANTINE: "ACTION_BLOCKED",
        Decision.TERMINATE: "ACTION_BLOCKED",
        Decision.APPROVAL_REQUIRED: "APPROVAL_REQUIRED",
    }[decision.decision]


def _append_credential_audit_event(
    *,
    session: Session,
    state: AppState,
    event_type: str,
    grant: CredentialGrant,
    authority_context,
    related_attempt_id: str | None,
) -> None:
    append_audit_event_with_session_chain(
        session=session,
        global_chain_id=state.settings.zdg_chain_id,
        session_id=grant.session_id,
        event_type=event_type,
        event_payload=credentialing.build_credential_event_payload(
            grant,
            event_type=event_type,
            authority_context=authority_context,
        ),
        related_attempt_id=related_attempt_id,
    )


def _append_handoff_audit_event(
    *,
    session: Session,
    state: AppState,
    event_type: str,
    body: ActionRequest,
    authority_context,
    handoff_envelope: HandoffEnvelope,
    handoff_schema: HandoffSchema | None,
    handoff_result: HandoffValidationResult | None,
    related_attempt_id: str | None,
    contract_id: str | None = None,
) -> None:
    append_audit_event_with_session_chain(
        session=session,
        global_chain_id=state.settings.zdg_chain_id,
        session_id=body.session_id,
        event_type=event_type,
        event_payload=_build_runtime_event_payload(
            timestamp=handoff_envelope.timestamp,
            source_component=handoff_envelope.source_component,
            body=body,
            authority_context=authority_context,
            decision=None,
            handoff_id=handoff_envelope.handoff_id,
            contract_id=contract_id,
            disposition=(handoff_result.disposition if handoff_result is not None else None),
            extra={
                "attempt_id": related_attempt_id,
                "tool_family": body.tool_family,
                "action": body.action,
                "handoff_id": handoff_envelope.handoff_id,
                "contract_id": contract_id,
                "schema_id": handoff_schema.schema_id if handoff_schema is not None else None,
                "schema_version": (
                    handoff_result.schema_version
                    if handoff_result is not None
                    else handoff_envelope.schema_version
                ),
                "validation_state": (
                    handoff_result.validation_state.value
                    if handoff_result is not None
                    else handoff_envelope.validation_state.value
                ),
                "payload_reference": dict(handoff_envelope.payload_reference),
                "errors": handoff_result.errors if handoff_result is not None else [],
            },
        ),
        related_attempt_id=related_attempt_id,
    )


def _build_runtime_event_payload(
    *,
    timestamp: datetime,
    source_component: str,
    body: ActionRequest,
    authority_context,
    decision: EnforcementDecision | None,
    handoff_id: str | None = None,
    contract_id: str | None = None,
    decision_state: Decision | None = None,
    disposition=None,
    extra: dict,
) -> dict:
    return {
        **decision_engine.build_runtime_correlation(
            timestamp=timestamp,
            source_component=source_component,
            authority_context=authority_context,
            enforcement_decision=decision,
            run_id=(authority_context.run_id if authority_context is not None else None),
            session_id=body.session_id,
            trace_id=(authority_context.trace_id if authority_context is not None else None),
            actor_id=(
                authority_context.actor_identity.actor_id
                if authority_context is not None
                else None
            ),
            agent_id=body.agent_id,
            delegation_id=(
                authority_context.delegation_chain.delegation_chain_id
                if authority_context is not None
                else None
            ),
            contract_id=contract_id,
            handoff_id=handoff_id,
            decision_state=decision_state,
            disposition=disposition,
        ).model_dump(mode="json"),
        **extra,
    }


def _persist_handoff(
    *,
    session: Session,
    attempt_id: str,
    handoff_envelope: HandoffEnvelope,
    handoff_result: HandoffValidationResult,
) -> None:
    attempt = session.get(ToolAttempt, attempt_id)
    if attempt is None:
        return
    attempt.handoff_id = handoff_envelope.handoff_id
    attempt.handoff_schema_version = handoff_result.schema_version
    attempt.handoff_validation_state = handoff_result.validation_state.value
    attempt.handoff_disposition = handoff_result.disposition.value


def _append_decision_finalized_event(
    *,
    session: Session,
    state: AppState,
    body: ActionRequest,
    trace,
    decision: EnforcementDecision,
    attempt_id: str,
    decision_id: str,
    timestamp: datetime,
) -> None:
    """Emit the terminal immutable fact for this evaluation."""
    append_audit_event_with_session_chain(
        session=session,
        global_chain_id=state.settings.zdg_chain_id,
        session_id=body.session_id,
        event_type=DECISION_FINALIZED,
        event_payload={
            "timestamp": timestamp.isoformat(),
            "attempt_id": attempt_id,
            "decision_id": decision_id,
            "agent_id": body.agent_id,
            "tool_family": body.tool_family,
            "action": body.action,
            "decision": decision.decision.value,
            "reason_code": decision.reason_code.value,
            "reason": decision.reason,
            "risk_score": decision.risk_score,
            "policy_bundle_version": decision.policy_bundle_version,
            "ruleset_hash": decision.ruleset_hash,
            "triggered_rules": decision.triggered_rules,
            "authority_context": (
                trace.authority_context.model_dump(mode="json")
                if trace.authority_context is not None
                else None
            ),
        },
        related_attempt_id=attempt_id,
    )


