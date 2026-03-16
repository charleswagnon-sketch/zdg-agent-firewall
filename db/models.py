"""
db/models.py - SQLModel table definitions.

All tables are defined here. Business logic lives in core/.

SQLite drops timezone information on round-trip, so model defaults must stay naive UTC.
Use utc_now_naive() for new timestamp fields instead of timezone-aware datetime.now(...).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Column, Field, Integer, SQLModel, Text


def utc_now_naive() -> datetime:
    """Return a naive UTC datetime for SQLite-friendly defaults."""

    return datetime.now(timezone.utc).replace(tzinfo=None)


class ToolAttempt(SQLModel, table=True):
    """One record per /v1/action request before evaluation."""

    __tablename__ = "tool_attempts"
    __table_args__ = {"extend_existing": True}

    attempt_id: str = Field(primary_key=True)
    run_id: Optional[str] = Field(default=None, index=True)
    trace_id: Optional[str] = Field(default=None, index=True)
    session_id: Optional[str] = Field(default=None, index=True)
    agent_id: str = Field(index=True)
    actor_id: Optional[str] = Field(default=None, index=True)
    delegation_chain_id: Optional[str] = Field(default=None, index=True)
    runtime: str = Field(default="direct")
    tool_family: str = Field(index=True)
    action: str
    raw_payload: Optional[str] = Field(default=None, sa_column=Column(Text))
    normalized_payload: Optional[str] = Field(default=None, sa_column=Column(Text))
    authority_context_json: Optional[str] = Field(default=None, sa_column=Column(Text))
    authority_scope_json: Optional[str] = Field(default=None, sa_column=Column(Text))
    handoff_id: Optional[str] = Field(default=None, index=True)
    handoff_schema_version: Optional[str] = None
    handoff_validation_state: Optional[str] = Field(default=None, index=True)
    handoff_disposition: Optional[str] = Field(default=None, index=True)
    payload_hash: str = Field(index=True)
    normalization_status: str = Field(default="COMPLETE")
    idempotency_key: Optional[str] = Field(default=None, index=True)
    requested_at: datetime = Field(default_factory=utc_now_naive)


class PolicyDecision(SQLModel, table=True):
    """One record per evaluation cycle."""

    __tablename__ = "policy_decisions"
    __table_args__ = {"extend_existing": True}

    decision_id: str = Field(primary_key=True)
    attempt_id: str = Field(foreign_key="tool_attempts.attempt_id", index=True)
    policy_bundle_id: str
    policy_bundle_version: str
    ruleset_hash: str
    risk_score: int = Field(default=0)
    decision: str
    decision_state_canonical: Optional[str] = Field(default=None, index=True)
    disposition: Optional[str] = Field(default=None, index=True)
    module_origin: Optional[str] = Field(default=None, index=True)
    source_component: Optional[str] = Field(default=None, index=True)
    reason_code: str
    triggered_rules: Optional[str] = Field(default=None, sa_column=Column(Text))
    reason: Optional[str] = Field(default=None, sa_column=Column(Text))
    decided_at: datetime = Field(default_factory=utc_now_naive)


class CredentialGrantRecord(SQLModel, table=True):
    """First-pass scoped credential grant with lease-state transitions."""

    __tablename__ = "credential_grants"
    __table_args__ = {"extend_existing": True}

    grant_id: str = Field(primary_key=True)
    run_id: str = Field(index=True)
    session_id: Optional[str] = Field(default=None, index=True)
    trace_id: Optional[str] = Field(default=None, index=True)
    actor_id: str = Field(index=True)
    agent_id: str = Field(index=True)
    delegation_chain_id: str = Field(index=True)
    tool_family: str = Field(index=True)
    action: str
    privilege_scope_json: Optional[str] = Field(default=None, sa_column=Column(Text))
    lease_state: str = Field(default="issued", index=True)
    issued_at: datetime = Field(default_factory=utc_now_naive)
    activated_at: Optional[datetime] = None
    expires_at: datetime = Field(index=True)
    revoked_at: Optional[datetime] = Field(default=None, index=True)
    revoked_reason: Optional[str] = Field(default=None, sa_column=Column(Text))
    revoked_by: Optional[str] = None


class ExecutionResult(SQLModel, table=True):
    """Outcome of a wrapper execution."""

    __tablename__ = "execution_results"
    __table_args__ = {"extend_existing": True}

    result_id: str = Field(primary_key=True)
    attempt_id: str = Field(foreign_key="tool_attempts.attempt_id", index=True)
    executed: bool = Field(default=False)
    mock: bool = Field(default=False)
    execution_status: Optional[str] = None
    output_summary: Optional[str] = Field(default=None, sa_column=Column(Text))
    blocked_reason: Optional[str] = Field(default=None, sa_column=Column(Text))
    raw_output_json: Optional[str] = Field(default=None, sa_column=Column(Text))
    completed_at: datetime = Field(default_factory=utc_now_naive)


class Approval(SQLModel, table=True):
    """Pending or resolved approval record."""

    __tablename__ = "approvals"
    __table_args__ = {"extend_existing": True}

    approval_id: str = Field(primary_key=True)
    decision_id: str = Field(foreign_key="policy_decisions.decision_id", index=True)
    payload_hash: str
    policy_bundle_version: str
    agent_id: str = Field(index=True)
    tool_family: str
    action: str
    risk_score: int = Field(default=0)
    triggered_rules: Optional[str] = Field(default=None, sa_column=Column(Text))
    reason: Optional[str] = Field(default=None, sa_column=Column(Text))
    approved: Optional[bool] = Field(default=None)
    operator: Optional[str] = None
    comment: Optional[str] = None
    expires_at: datetime
    created_at: datetime = Field(default_factory=utc_now_naive)
    resolved_at: Optional[datetime] = None
    consumed_at: Optional[datetime] = Field(default=None, index=True)
    consumed_attempt_id: Optional[str] = Field(default=None, index=True)


class KillSwitchEvent(SQLModel, table=True):
    """Represents one active or historical kill switch state."""

    __tablename__ = "killswitch_events"
    __table_args__ = {"extend_existing": True}

    id: str = Field(primary_key=True)
    scope: str = Field(index=True)
    scope_value: Optional[str] = Field(default=None, index=True)
    triggered_at: datetime = Field(default_factory=utc_now_naive)
    trigger_reason: str
    session_id: Optional[str] = None
    agent_id: Optional[str] = None
    reset_at: Optional[datetime] = Field(default=None, index=True)
    reset_by: Optional[str] = None


class AuditEvent(SQLModel, table=True):
    """Append-only tamper-evident audit log."""

    __tablename__ = "audit_events"
    __table_args__ = {"extend_existing": True}

    event_id: str = Field(primary_key=True)
    event_type: str = Field(index=True)
    related_attempt_id: Optional[str] = Field(default=None, index=True)
    chain_id: str = Field(index=True)
    prev_event_hash: str
    event_hash: str
    event_payload: str = Field(sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now_naive)
    seq: int = Field(index=True)


class IdempotencyCache(SQLModel, table=True):
    """Short-lived cache for idempotency key lookups."""

    __tablename__ = "idempotency_cache"
    __table_args__ = {"extend_existing": True}

    id: Optional[int] = Field(
        default=None,
        sa_column=Column(Integer, primary_key=True, autoincrement=True),
    )
    idempotency_key: str = Field(index=True)
    agent_id: str = Field(index=True)
    approval_id: Optional[str] = Field(default=None, index=True)
    payload_hash: str
    attempt_id: str
    response_json: str = Field(sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now_naive)
    expires_at: datetime


class AgentRecord(SQLModel, table=True):
    """Registered agent lifecycle record."""

    __tablename__ = "agent_records"
    __table_args__ = {"extend_existing": True}

    agent_id: str = Field(primary_key=True)
    agent_type: str = Field(index=True)
    status: str = Field(default="active", index=True)
    metadata_json: Optional[str] = Field(default=None, sa_column=Column(Text))
    registered_at: datetime = Field(default_factory=utc_now_naive)
    registered_by: Optional[str] = None
    status_changed_at: datetime = Field(default_factory=utc_now_naive)
    status_changed_by: Optional[str] = None
    status_reason: Optional[str] = Field(default=None, sa_column=Column(Text))


class AgentContractRecord(SQLModel, table=True):
    """Contract binding record for a governed run."""

    __tablename__ = "agent_contracts"
    __table_args__ = {"extend_existing": True}

    contract_id: str = Field(primary_key=True)
    run_id: str = Field(index=True)
    session_id: Optional[str] = Field(default=None, index=True)
    trace_id: Optional[str] = Field(default=None, index=True)
    actor_id: str = Field(index=True)
    agent_id: str = Field(index=True)
    delegation_chain_id: str
    allowed_tool_families_json: str = Field(sa_column=Column(Text))
    contract_state: str = Field(default="active", index=True)
    bound_at: datetime = Field(default_factory=utc_now_naive)
    revoked_at: Optional[datetime] = Field(default=None, index=True)
    revoked_reason: Optional[str] = Field(default=None, sa_column=Column(Text))
    revoked_by: Optional[str] = None
    expires_at: Optional[datetime] = Field(default=None, index=True)
    # Set by renew_expired_contracts(). None if never renewed. EXPIRED stays EXPIRED.
    renewed_at: Optional[datetime] = None
    renewed_by: Optional[str] = None
    renewed_reason: Optional[str] = Field(default=None, sa_column=Column(Text))
    # Set by reinstate_revoked_contracts(). None if never reinstated.
    reinstated_at: Optional[datetime] = Field(default=None, index=True)
    reinstated_by: Optional[str] = None
    reinstated_reason: Optional[str] = Field(default=None, sa_column=Column(Text))


class ContractUsageRecord(SQLModel, table=True):
    """Replay-visible usage record for a governed run bound by a contract."""

    __tablename__ = "contract_usage"
    __table_args__ = {"extend_existing": True}

    usage_id: str = Field(primary_key=True)
    contract_id: str = Field(index=True)
    run_id: str = Field(index=True)
    tokens_used: int = Field(default=0)
    spend_used: float = Field(default=0.0)
    elapsed_ms: float = Field(default=0.0)
    tool_invocations: int = Field(default=0)
    last_updated_at: datetime = Field(default_factory=utc_now_naive, index=True)
    current_state: str = Field(default="active", index=True)


class SessionRecord(SQLModel, table=True):
    """Session lifecycle record."""

    __tablename__ = "session_records"
    __table_args__ = {"extend_existing": True}

    session_id: str = Field(primary_key=True)
    agent_id: Optional[str] = Field(default=None, index=True)
    status: str = Field(default="active", index=True)
    metadata_json: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now_naive)
    created_by: Optional[str] = None
    creation_source: str = Field(default="api")
    closed_at: Optional[datetime] = None
    closed_by: Optional[str] = None
    close_reason: Optional[str] = Field(default=None, sa_column=Column(Text))
    suspended_at: Optional[datetime] = None
    suspended_by: Optional[str] = None
    suspend_reason: Optional[str] = Field(default=None, sa_column=Column(Text))


# ── Licensing tables (ZDG-FR-LIC-01) ─────────────────────────────────────────

class LicenseAccount(SQLModel, table=True):
    """Developer account that holds one or more licenses."""

    __tablename__ = "license_accounts"
    __table_args__ = {"extend_existing": True}

    account_id: str = Field(primary_key=True)
    email: str = Field(index=True)
    display_name: str
    created_at: datetime = Field(default_factory=utc_now_naive)
    # active | suspended
    status: str = Field(default="active", index=True)
    # PAY-01: Stripe customer ID for billing reconciliation
    stripe_customer_id: Optional[str] = Field(default=None, index=True)


class License(SQLModel, table=True):
    """License record for a developer account."""

    __tablename__ = "licenses"
    __table_args__ = {"extend_existing": True}

    license_id: str = Field(primary_key=True)
    account_id: str = Field(foreign_key="license_accounts.account_id", index=True)
    # free | dev_monthly | dev_annual
    plan_code: str = Field(index=True)
    # active | trialing | expired | revoked
    status: str = Field(default="active", index=True)
    issued_at: datetime = Field(default_factory=utc_now_naive)
    starts_at: datetime = Field(default_factory=utc_now_naive)
    expires_at: Optional[datetime] = Field(default=None, index=True)
    trial_ends_at: Optional[datetime] = Field(default=None)
    max_installations: int = Field(default=1)
    notes: Optional[str] = Field(default=None, sa_column=Column(Text))
    # PAY-01: Stripe subscription and price IDs for billing reconciliation
    stripe_subscription_id: Optional[str] = Field(default=None, index=True)
    stripe_price_id: Optional[str] = Field(default=None)


class Entitlement(SQLModel, table=True):
    """Feature entitlement for a license.

    Entitlements are opt-in: if no record exists for a feature, the feature is
    accessible (permissive default). A record with enabled=False explicitly
    blocks the feature.  limit_value carries numeric limits (e.g. replay_history_days=7).
    """

    __tablename__ = "license_entitlements"
    __table_args__ = {"extend_existing": True}

    entitlement_id: str = Field(primary_key=True)
    license_id: str = Field(foreign_key="licenses.license_id", index=True)
    feature_code: str = Field(index=True)
    enabled: bool = Field(default=True)
    # For numeric limits (e.g. replay_history_days=7, max_monthly_runs=1000).
    # None means unlimited.
    limit_value: Optional[int] = Field(default=None)
    created_at: datetime = Field(default_factory=utc_now_naive)


class Installation(SQLModel, table=True):
    """Installation record for a licensed device or deployment."""

    __tablename__ = "license_installations"
    __table_args__ = {"extend_existing": True}

    installation_id: str = Field(primary_key=True)
    account_id: str = Field(foreign_key="license_accounts.account_id", index=True)
    license_id: str = Field(foreign_key="licenses.license_id", index=True)
    device_label: str
    device_fingerprint: Optional[str] = Field(default=None, index=True)
    platform: Optional[str] = Field(default=None)
    app_version: Optional[str] = Field(default=None)
    first_seen_at: datetime = Field(default_factory=utc_now_naive)
    last_seen_at: datetime = Field(default_factory=utc_now_naive)
    revoked_at: Optional[datetime] = Field(default=None, index=True)


class LicenseEvent(SQLModel, table=True):
    """Append-only audit log for license lifecycle state changes."""

    __tablename__ = "license_events"
    __table_args__ = {"extend_existing": True}

    event_id: str = Field(primary_key=True)
    license_id: str = Field(foreign_key="licenses.license_id", index=True)
    # LICENSE_ACTIVATED | LICENSE_EXPIRED | LICENSE_REVOKED | ENTITLEMENT_ADDED |
    # INSTALLATION_REGISTERED | INSTALLATION_REVOKED
    event_type: str = Field(index=True)
    event_payload: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now_naive)


class LicenseUsage(SQLModel, table=True):
    """Per-operation usage record for cap-gated license features.

    One row is inserted each time a capped feature is consumed (e.g. an export).
    Monthly cap enforcement queries this table filtered by feature_code and
    used_at >= current-month-start. Governed run counts use ToolAttempt.requested_at
    directly, so this table is only needed for features without an existing audit row.
    """

    __tablename__ = "license_usage"
    __table_args__ = {"extend_existing": True}

    usage_id: str = Field(primary_key=True)
    license_id: str = Field(foreign_key="licenses.license_id", index=True)
    # e.g. "max_monthly_exports"
    feature_code: str = Field(index=True)
    used_at: datetime = Field(default_factory=utc_now_naive, index=True)


class TrialFeedback(SQLModel, table=True):
    """Structured trial feedback submitted via POST /v1/support/feedback.

    Stored locally for triage. Included in support bundles (count + recent IDs).
    Context field is user-provided JSON; must not contain secrets.
    """

    __tablename__ = "trial_feedback"
    __table_args__ = {"extend_existing": True}

    feedback_id: str = Field(primary_key=True)
    # bug_report | feature_request | general
    feedback_type: str = Field(index=True)
    description: str = Field(sa_column=Column(Text))
    # Optional JSON blob — user-provided non-secret context (steps to reproduce, etc.)
    context: Optional[str] = Field(default=None, sa_column=Column(Text))
    app_version: str
    created_at: datetime = Field(default_factory=utc_now_naive, index=True)
