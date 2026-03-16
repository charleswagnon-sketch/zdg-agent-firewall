"""
core/schemas.py - Pydantic request/response schemas and internal domain objects.

These are the API contract types. DB models live in db/models.py.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from core.modes import (
    ContractState,
    CredentialLeaseState,
    Decision,
    Disposition,
    EnforcementModuleOrigin,
    GalStage,
    GuardrailIntervention,
    HandoffValidationState,
    KillSwitchScope,
    NormalizationStatus,
    PolicyEffect,
    ReasonCode,
    StreamingMode,
)


class ActorIdentity(BaseModel):
    """Canonical initiating actor identity for governed execution."""

    actor_id: str
    actor_type: str = "unspecified"
    tenant_id: str | None = None
    role_bindings: list[str] = Field(default_factory=list)
    auth_context: dict[str, Any] = Field(default_factory=dict)


class AgentIdentity(BaseModel):
    """Canonical non-human agent identity."""

    agent_id: str
    agent_type: str = "unspecified"
    owner_domain: str | None = None
    registered_capabilities: list[str] = Field(default_factory=list)
    allowed_tool_families: list[str] = Field(default_factory=list)
    lifecycle_state: str = "unregistered"


class DelegationChain(BaseModel):
    """Explicit authority path from actor to executing agent."""

    delegation_chain_id: str
    root_actor_id: str
    delegated_agent_ids: list[str] = Field(default_factory=list)
    authority_scope: dict[str, Any] = Field(default_factory=dict)
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    delegation_reason: str = "direct_request"


class RunAuthorityContext(BaseModel):
    """Canonical run, session, and authority correlation context."""

    run_id: str
    session_id: str | None = None
    trace_id: str | None = None
    actor_identity: ActorIdentity
    agent_identity: AgentIdentity
    delegation_chain: DelegationChain
    requested_tool_family: str
    requested_operation: str
    policy_bundle_id: str
    policy_bundle_version: str


class CredentialGrant(BaseModel):
    """First-pass scoped credential grant with lease-state transitions."""

    grant_id: str
    run_id: str
    session_id: str | None = None
    trace_id: str | None = None
    actor_id: str
    agent_id: str
    delegation_chain_id: str
    tool_family: str
    action: str
    privilege_scope: dict[str, Any] = Field(default_factory=dict)
    lease_state: CredentialLeaseState = CredentialLeaseState.ISSUED
    issued_at: datetime
    activated_at: datetime | None = None
    expires_at: datetime
    revoked_at: datetime | None = None
    revoked_reason: str | None = None
    revoked_by: str | None = None


class ContractUsageState(BaseModel):
    """Replay-visible usage state for a bound contract after execution."""

    usage_id: str
    contract_id: str
    run_id: str
    # tokens_used and spend_used are zero until a token/spend data source is wired.
    tokens_used: int = 0
    spend_used: float = 0.0
    # elapsed_ms is total governed-run elapsed time (evaluation + execution).
    elapsed_ms: float = 0.0
    tool_invocations: int = 0
    last_updated_at: datetime
    current_state: ContractState


class AgentContract(BaseModel):
    """Canonical contract binding for a governed run."""

    contract_id: str
    run_id: str
    session_id: str | None = None
    trace_id: str | None = None
    actor_id: str
    agent_id: str
    delegation_chain_id: str
    allowed_tool_families: list[str] = Field(default_factory=list)
    contract_state: ContractState = ContractState.ACTIVE
    bound_at: datetime
    expires_at: datetime | None = None
    renewed_at: datetime | None = None
    revoked_at: datetime | None = None
    revoked_reason: str | None = None
    revoked_by: str | None = None


class HandoffEnvelope(BaseModel):
    """Canonical typed handoff envelope for governed downstream propagation."""

    run_id: str
    session_id: str | None = None
    trace_id: str | None = None
    actor_id: str | None = None
    agent_id: str
    delegation_id: str | None = None
    authority_scope: dict[str, Any] = Field(default_factory=dict)
    contract_id: str | None = None
    handoff_id: str
    schema_version: str | None = None
    source_component: str
    timestamp: datetime
    payload: dict[str, Any] = Field(default_factory=dict)
    payload_reference: dict[str, Any] = Field(default_factory=dict)
    validation_state: HandoffValidationState = HandoffValidationState.PENDING
    disposition: Disposition | None = None


class HandoffSchema(BaseModel):
    """Static schema registry entry for the governed handoff boundary."""

    schema_id: str
    schema_version: str
    tool_family: str
    action: str
    required_fields: list[str] = Field(default_factory=list)
    optional_fields: list[str] = Field(default_factory=list)
    field_types: dict[str, str] = Field(default_factory=dict)
    strict: bool = True
    failure_disposition: Disposition = Disposition.BLOCK


class HandoffValidationResult(BaseModel):
    """Result of typed handoff validation before downstream propagation."""

    handoff_id: str
    schema_id: str | None = None
    schema_version: str | None = None
    validation_state: HandoffValidationState
    valid: bool = False
    errors: list[str] = Field(default_factory=list)
    disposition: Disposition
    payload_reference: dict[str, Any] = Field(default_factory=dict)


class ActionRequest(BaseModel):
    """Body for POST /v1/action and POST /v1/investigate."""

    session_id: str | None = None
    agent_id: str
    runtime: str = "direct"
    tool_family: str
    action: str
    args: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] | None = None
    idempotency_key: str | None = None
    approval_id: str | None = None
    actor_identity: ActorIdentity | None = None
    delegation_chain: DelegationChain | None = None


class NormalizeResult(BaseModel):
    """Output of the canonical normalization step."""

    normalized_payload: dict[str, Any]
    payload_hash: str
    status: NormalizationStatus
    failure_reason: str | None = None


class NormalizationStep(BaseModel):
    """One normalization rule/check recorded in the evaluation trace."""

    step: str
    applied: bool
    detail: str


class NormalizationTrace(BaseModel):
    """Detailed normalization output for explainability endpoints."""

    normalized_payload: dict[str, Any]
    payload_hash: str
    status: NormalizationStatus
    failure_reason: str | None = None
    canonical_json: str
    steps: list[NormalizationStep] = Field(default_factory=list)


class RiskRuleResult(BaseModel):
    """One risk rule evaluation result."""

    rule: str
    triggered: bool
    points: int = 0
    reason: str
    category: str = "risk"
    duration_ms: float = 0.0


class RiskResult(BaseModel):
    """Output of the risk scoring engine."""

    score: int = Field(ge=0, le=100)
    triggered_rules: list[str] = Field(default_factory=list)
    reason: str


class PolicyRuleEvaluation(BaseModel):
    """Trace of a single policy rule evaluation."""

    rule_id: str
    rule_name: str
    effect: PolicyEffect
    priority: int
    matched_family: bool
    matched_action: bool
    matched: bool
    reason: str


class PolicyBundleMeta(BaseModel):
    """Metadata about the active policy bundle recorded in every decision."""

    bundle_id: str
    version: str
    ruleset_hash: str


class EnforcementDecision(BaseModel):
    """Canonical enforcement decision aligned to GAL and evidence emission."""

    decision: Decision
    reason_code: ReasonCode
    reason: str
    risk_score: int
    triggered_rules: list[str] = Field(default_factory=list)
    payload_hash: str
    policy_bundle_id: str
    policy_bundle_version: str
    ruleset_hash: str
    killswitch_scope: KillSwitchScope | None = None
    gal_stage: GalStage = GalStage.DECISION
    module_origin: EnforcementModuleOrigin = EnforcementModuleOrigin.DECISION
    authority_context: RunAuthorityContext | None = None
    effective_at: datetime | None = None


class CanonicalRuntimeCorrelation(BaseModel):
    """Normalized correlation fields for runtime evidence and replay payloads."""

    run_id: str | None = None
    session_id: str | None = None
    trace_id: str | None = None
    actor_id: str | None = None
    agent_id: str | None = None
    delegation_id: str | None = None
    authority_scope: dict[str, Any] = Field(default_factory=dict)
    contract_id: str | None = None
    handoff_id: str | None = None
    decision_state: Decision | None = None
    disposition: Disposition | None = None
    timestamp: datetime
    source_component: str


class DecisionEnvelope(EnforcementDecision):
    """Backward-compatible canonical decision metadata shared across routes."""


class DecisionResult(BaseModel):
    """Complete output of a single policy evaluation cycle."""

    decision: Decision
    reason_code: ReasonCode
    reason: str
    risk_score: int
    triggered_rules: list[str] = Field(default_factory=list)
    policy_bundle: PolicyBundleMeta
    payload_hash: str
    approval_id: str | None = None
    approval_expires_at: datetime | None = None
    killswitch_scope: KillSwitchScope | None = None


class IdempotencyTrace(BaseModel):
    """Read-only summary of idempotency analysis."""

    checked: bool = False
    key: str | None = None
    replay_hit: bool = False
    payload_mismatch: bool = False
    cached_attempt_id: str | None = None


class KillSwitchTrace(BaseModel):
    """Read-only summary of effective kill-switch evaluation."""

    active: bool = False
    scope: KillSwitchScope | None = None
    scope_value: str | None = None
    reason: str | None = None


class ApprovalUsageTrace(BaseModel):
    """Read-only summary of approval matching and consumption eligibility."""

    provided: bool = False
    checked: bool = False
    approval_id: str | None = None
    matched: bool = False
    consumable: bool = False
    consumed: bool = False
    reason_code: ReasonCode | None = None
    reason: str | None = None


class EvaluationTrace(BaseModel):
    """Pure evaluation trace shared by /v1/action and /v1/investigate."""

    normalized_payload: dict[str, Any]
    normalization_status: NormalizationStatus
    normalization_failure_reason: str | None = None
    normalization_steps: list[NormalizationStep] = Field(default_factory=list)
    canonical_json: str
    payload_hash: str
    idempotency: IdempotencyTrace = Field(default_factory=IdempotencyTrace)
    killswitch: KillSwitchTrace = Field(default_factory=KillSwitchTrace)
    risk_breakdown: list[RiskRuleResult] = Field(default_factory=list)
    total_risk_score: int = 0
    policy_rules_evaluated: list[PolicyRuleEvaluation] = Field(default_factory=list)
    matched_policy_rule: str | None = None
    authority_context: RunAuthorityContext | None = None
    final_decision: EnforcementDecision
    approval: ApprovalUsageTrace = Field(default_factory=ApprovalUsageTrace)
    guardrails: "GuardrailTrace" = Field(default_factory=lambda: GuardrailTrace())


class ExecutionOutcome(BaseModel):
    """Structured wrapper execution outcome returned to action callers."""

    executed: bool = False
    mock: bool = True
    execution_status: str | None = None
    output_summary: str = ""
    blocked_reason: str | None = None
    raw_output: dict[str, Any] | None = None


class GuardrailCheckResult(BaseModel):
    """Outcome of a single independent guardrail check."""

    guardrail_id: str
    triggered: bool = False
    severity: str = "none"
    intervention: GuardrailIntervention = GuardrailIntervention.NONE
    reason: str
    surface: str | None = None
    evidence_preview: str | None = None
    duration_ms: float = 0.0


class StreamingPlan(BaseModel):
    """Streaming policy surfaced to runtime adapters and callers."""

    requested: bool = False
    enabled: bool = False
    mode: StreamingMode = StreamingMode.BUFFERED
    release_hold_chars: int = 0
    final_tail_validation: bool = True
    intervention_actions: list[GuardrailIntervention] = Field(default_factory=list)
    reason: str = "Streaming not requested."


class GuardrailTrace(BaseModel):
    """Parallel guardrail execution trace."""

    execution_mode: str = "serial"
    total_duration_ms: float = 0.0
    blocked: bool = False
    block_reason: str | None = None
    checks: list[GuardrailCheckResult] = Field(default_factory=list)
    streaming_plan: StreamingPlan = Field(default_factory=StreamingPlan)


class GuardrailEvaluationResult(BaseModel):
    """Emission-ready guardrail output paired with the effective decision."""

    authority_context: RunAuthorityContext | None = None
    trace: GuardrailTrace
    effective_decision: EnforcementDecision | None = None


class ActionResponse(BaseModel):
    """Response body for POST /v1/action."""

    trace_id: str
    attempt_id: str
    decision_id: str
    session_id: str | None
    agent_id: str
    tool_family: str
    action: str
    decision: Decision
    reason_code: ReasonCode
    reason: str
    risk_score: int
    triggered_rules: list[str]
    payload_hash: str
    policy_bundle_id: str
    policy_bundle_version: str
    ruleset_hash: str
    approval_id: str | None = None
    approval_expires_at: datetime | None = None
    approval_consumed: bool = False
    killswitch_scope: KillSwitchScope | None = None
    authority_context: RunAuthorityContext | None = None
    credential_grant: CredentialGrant | None = None
    contract_id: str | None = None
    enforcement_decision: EnforcementDecision | None = None
    execution: ExecutionOutcome | None = None
    guardrails: GuardrailTrace | None = None
    idempotent_replay: bool = False
    timestamp: datetime


class ContractStateView(BaseModel):
    """Read-only current-state snapshot of a contract for investigation and replay.

    This is a point-in-time view of the most recently bound contract for a session.
    It reflects the contract's current lifecycle state and latest usage record.
    It is NOT a historical event timeline — it does not replay the sequence of
    state transitions. For the ordered event history, export the session audit chain
    (chain_id=``session:<session_id>``) via GET /v1/audit/export.

    breach_warn_count counts BREACH_WARN events in the session-scoped audit chain
    only (chain_id=``session:<session_id>``). Global-chain duplicates are excluded.
    """

    contract_id: str
    contract_state: ContractState
    bound_at: datetime
    expires_at: datetime | None = None
    renewed_at: datetime | None = None
    revoked_at: datetime | None = None
    revoked_reason: str | None = None
    revoked_by: str | None = None
    # Latest usage record for this contract. None if no execution has completed.
    latest_usage: "ContractUsageState | None" = None
    # Authoritative fields within latest_usage (backed by real data).
    usage_authoritative_fields: list[str] = Field(default_factory=list)
    # Stub fields within latest_usage (placeholder zeros until a data source is wired).
    usage_stub_fields: list[str] = Field(default_factory=list)
    # BREACH_WARN presence from the session-scoped audit chain only.
    breach_warn_emitted: bool = False
    breach_warn_count: int = 0
    # Reinstatement state — DB-backed, authoritative. All four are None if the
    # contract has never been reinstated. Set by POST /v1/sessions/{id}/reinstate-contract.
    was_reinstated: bool = False
    reinstated_at: datetime | None = None
    reinstated_by: str | None = None
    reinstated_reason: str | None = None
    # Renewal lineage — is_renewal is True when this contract was created by
    # POST /v1/sessions/{id}/renew-contract (run_id carries "ren_" prefix by convention).
    # prior_renewed_contract_ids lists EXPIRED contract IDs for this session that
    # have been stamped with renewed_at — direct lineage evidence without audit-chain export.
    is_renewal: bool = False
    prior_renewed_contract_ids: list[str] = Field(default_factory=list)
    # Escalation state — True when a BREACH_ESCALATED event exists in the session-scoped
    # audit chain. Sourced from has_breach_escalation() at read time. Operator review
    # required to clear; actions are gated by BREACH_ESCALATED in _check_lifecycle_block.
    breach_escalated: bool = False


class InvestigationResponse(EvaluationTrace):
    """Response body for POST /v1/investigate."""

    contract_state_view: "ContractStateView | None" = None


class ContractReinstatementResponse(BaseModel):
    """Response body for POST /v1/sessions/{session_id}/reinstate-contract."""

    session_id: str
    reinstated_count: int
    reinstated_contract_ids: list[str]
    operator: str


class ContractRenewalResponse(BaseModel):
    """Response body for POST /v1/sessions/{session_id}/renew-contract."""

    session_id: str
    renewed_count: int
    renewed_contract_ids: list[str]
    new_contract_id: str
    operator: str


class ApprovalRequest(BaseModel):
    """Body for POST /v1/approval/{id}."""

    approve: bool
    operator: str
    payload_hash: str
    comment: str | None = None


class ApprovalResponse(BaseModel):
    approval_id: str
    status: str
    decision: str | None = None
    reason_code: ReasonCode | None = None
    reason: str | None = None
    resolved_at: datetime | None = None


class KillSwitchStatus(BaseModel):
    global_halt: bool
    scoped_halts: list[dict[str, Any]] = Field(default_factory=list)


class KillSwitchResetRequest(BaseModel):
    operator: str
    comment: str | None = None
    scope: KillSwitchScope = KillSwitchScope.GLOBAL
    scope_value: str | None = None


class EventsResponse(BaseModel):
    count: int
    events: list[dict[str, Any]]


class MetricsResponse(BaseModel):
    total_attempts: int
    total_allowed: int
    total_blocked: int
    total_approval_required: int
    top_triggered_rules: list[dict[str, Any]]
    top_reason_codes: list[dict[str, Any]]
    active_policy_bundle: str
    kill_switch_global_active: bool
    kill_switch_scoped_active_count: int


class SessionCreateRequest(BaseModel):
    """Body for POST /v1/sessions."""

    agent_id: str | None = None
    metadata: dict[str, Any] | None = None
    operator: str
    creation_source: str = "api"


class SessionStatusRequest(BaseModel):
    """Body for session lifecycle transitions."""

    operator: str
    reason: str

    @field_validator("operator")
    @classmethod
    def operator_nonempty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("operator must be a non-empty string")
        return v


class AgentRegisterRequest(BaseModel):
    """Body for POST /v1/agents."""

    agent_id: str
    agent_type: str
    metadata: dict[str, Any] | None = None
    operator: str


class AgentStatusRequest(BaseModel):
    """Body for agent lifecycle transitions."""

    operator: str
    reason: str


EvaluationTrace.model_rebuild()
InvestigationResponse.model_rebuild()
