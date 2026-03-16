"""core/contracts.py - Agent contract binding and lifecycle."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, NamedTuple

from sqlmodel import select

from core.modes import ContractState
from core.schemas import AgentContract, ContractRenewalResponse, ContractStateView, ContractUsageState, RunAuthorityContext

if TYPE_CHECKING:
    from sqlmodel import Session


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class SessionUsageSummary(NamedTuple):
    """Aggregate prior usage for a session, computed from ContractUsageRecords."""

    invocation_count: int
    elapsed_ms_total: float


def query_session_usage(*, session: "Session", session_id: str) -> SessionUsageSummary:
    """Return aggregate prior completed-execution usage for a session.

    Reads ContractUsageRecords linked to AgentContractRecords for the session.
    Does not include the current in-flight run (record_usage has not been called yet).
    Returns (0, 0.0) when no prior usage exists.
    """
    from db.models import AgentContractRecord, ContractUsageRecord

    contract_ids = session.exec(
        select(AgentContractRecord.contract_id).where(
            AgentContractRecord.session_id == session_id
        )
    ).all()

    if not contract_ids:
        return SessionUsageSummary(invocation_count=0, elapsed_ms_total=0.0)

    usage_records = session.exec(
        select(ContractUsageRecord).where(
            ContractUsageRecord.contract_id.in_(contract_ids)  # type: ignore[attr-defined]
        )
    ).all()

    return SessionUsageSummary(
        invocation_count=len(usage_records),
        elapsed_ms_total=sum(r.elapsed_ms for r in usage_records),
    )


_USAGE_AUTHORITATIVE_FIELDS = ["elapsed_ms"]
_USAGE_STUB_FIELDS = ["tokens_used", "spend_used", "tool_invocations"]


def get_warned_breach_fields(*, session: "Session", session_id: str) -> set[str]:
    """Return the set of breach_fields already recorded in BREACH_WARN events for this session.

    Queries the session-scoped audit chain (chain_id="session:{session_id}") for all
    BREACH_WARN events and unions their breach_fields lists. Used by the evaluate path
    to suppress duplicate warnings: only emit BREACH_WARN for threshold types not yet
    warned in this session.

    Returns an empty set if no BREACH_WARN events exist for the session.
    All queries are SELECT-only; this function never mutates state.
    """
    import json as _json
    from db.models import AuditEvent

    records = session.exec(
        select(AuditEvent)
        .where(AuditEvent.chain_id == f"session:{session_id}")
        .where(AuditEvent.event_type == "BREACH_WARN")
    ).all()
    warned: set[str] = set()
    for rec in records:
        payload = _json.loads(rec.event_payload or "{}")
        warned.update(payload.get("breach_fields", []))
    return warned


def has_breach_escalation(*, session: "Session", session_id: str) -> bool:
    """Return True if a BREACH_ESCALATED event exists in the session-scoped audit chain.

    Used as a request-entry gate in _check_lifecycle_block. Once a session has been
    escalated, further action requests are blocked until an operator clears the state.
    Queries only the session-scoped chain (chain_id="session:{session_id}") to avoid
    false positives from global-chain duplicate events.
    """
    from db.models import AuditEvent

    record = session.exec(
        select(AuditEvent)
        .where(AuditEvent.chain_id == f"session:{session_id}")
        .where(AuditEvent.event_type == "BREACH_ESCALATED")
        .limit(1)
    ).first()
    return record is not None


def get_contract_state_view(
    *, session: "Session", session_id: str
) -> ContractStateView | None:
    """Return the current-state contract snapshot for a session (read-only).

    Selects the most recently bound contract for the session using
    ORDER BY bound_at DESC LIMIT 1. Returns None if no contract record exists.

    This is a current-state view, not a historical timeline. It reflects the
    present lifecycle state and latest usage record of the most recent contract.
    It does not reconstruct the ordered sequence of state transitions.

    BREACH_WARN count is sourced from the session-scoped audit chain only
    (chain_id=``session:<session_id>``). The global-chain duplicate of each
    BREACH_WARN event is intentionally excluded from this count.

    All queries are SELECT-only; this function never mutates state.
    """
    from db.models import AgentContractRecord, AuditEvent, ContractUsageRecord
    from sqlmodel import func, select

    record = session.exec(
        select(AgentContractRecord)
        .where(AgentContractRecord.session_id == session_id)
        .order_by(AgentContractRecord.bound_at.desc())
        .limit(1)
    ).first()

    if record is None:
        return None

    usage_record = session.exec(
        select(ContractUsageRecord)
        .where(ContractUsageRecord.contract_id == record.contract_id)
        .order_by(ContractUsageRecord.last_updated_at.desc())
        .limit(1)
    ).first()

    breach_count: int = session.exec(
        select(func.count()).where(
            AuditEvent.chain_id == f"session:{session_id}",
            AuditEvent.event_type == "BREACH_WARN",
        )
    ).one()

    # Renewal lineage: EXPIRED records for this session that carry renewed_at.
    prior_renewed_ids: list[str] = list(
        session.exec(
            select(AgentContractRecord.contract_id)
            .where(AgentContractRecord.session_id == session_id)
            .where(AgentContractRecord.contract_state == ContractState.EXPIRED.value)
            .where(AgentContractRecord.renewed_at.isnot(None))  # type: ignore[union-attr]
        ).all()
    )
    # is_renewal: True when this contract was created by renew_expired_contracts,
    # which stamps the run_id with the "ren_" prefix.
    is_renewal = record.run_id.startswith("ren_")

    escalated = has_breach_escalation(session=session, session_id=session_id)

    latest_usage = _usage_to_schema(usage_record) if usage_record is not None else None

    return ContractStateView(
        contract_id=record.contract_id,
        contract_state=ContractState(record.contract_state),
        bound_at=record.bound_at,
        expires_at=record.expires_at,
        renewed_at=record.renewed_at,
        revoked_at=record.revoked_at,
        revoked_reason=record.revoked_reason,
        revoked_by=record.revoked_by,
        latest_usage=latest_usage,
        usage_authoritative_fields=_USAGE_AUTHORITATIVE_FIELDS if latest_usage else [],
        usage_stub_fields=_USAGE_STUB_FIELDS if latest_usage else [],
        breach_warn_emitted=breach_count > 0,
        breach_warn_count=breach_count,
        was_reinstated=record.reinstated_at is not None,
        reinstated_at=record.reinstated_at,
        reinstated_by=record.reinstated_by,
        reinstated_reason=record.reinstated_reason,
        is_renewal=is_renewal,
        prior_renewed_contract_ids=prior_renewed_ids,
        breach_escalated=escalated,
    )


def reinstate_revoked_contracts(
    *,
    session: "Session",
    session_id: str,
    reinstated_by: str,
    reinstated_reason: str,
    reinstated_at: datetime | None = None,
) -> list[AgentContract]:
    """Transition all REVOKED contracts for a session back to ACTIVE.

    Operator-initiated only. Targets every AgentContractRecord for the session
    where contract_state == REVOKED — mirrors the revoke-all pattern used by
    revoke_active_contracts so that has_revoked_contract() returns False after
    a single operator call, regardless of how many contracts were swept by a
    prior kill switch or session-close.

    Clears revoked_at, revoked_reason, and revoked_by on each reinstated record.
    Prior revocation evidence is preserved in the CONTRACT_REVOKED audit event
    emitted at revocation time, and the caller must emit a CONTRACT_REINSTATED
    audit event per reinstated contract (with prior_revoked_reason captured
    before this mutation).

    Returns the list of reinstated AgentContract schemas. Returns [] if no
    REVOKED contracts exist for the session (caller should return 409).

    Does not modify session lifecycle state. A CLOSED session will still be
    gated by SESSION_CLOSED before CONTRACT_REVOKED is checked.
    """
    from db.models import AgentContractRecord

    now = reinstated_at or utc_now()
    records = session.exec(
        select(AgentContractRecord)
        .where(AgentContractRecord.session_id == session_id)
        .where(AgentContractRecord.contract_state == ContractState.REVOKED.value)
    ).all()

    result: list[AgentContract] = []
    for record in records:
        # Capture prior revocation facts before clearing — caller uses these
        # to populate the CONTRACT_REINSTATED audit payload.
        prior = _to_schema(record)
        record.contract_state = ContractState.ACTIVE.value
        record.revoked_at = None
        record.revoked_reason = None
        record.revoked_by = None
        record.reinstated_at = now
        record.reinstated_by = reinstated_by
        record.reinstated_reason = reinstated_reason
        session.add(record)
        result.append(prior)

    return result


def has_revoked_contract(*, session: "Session", session_id: str) -> bool:
    """Return True if any contract for this session is in REVOKED state.

    Used as a request-entry gate. Does not check agent-level revocations —
    historical agent contracts could be from prior sessions and would produce
    false positives if used as a per-agent block.
    """
    from db.models import AgentContractRecord

    record = session.exec(
        select(AgentContractRecord)
        .where(AgentContractRecord.session_id == session_id)
        .where(AgentContractRecord.contract_state == ContractState.REVOKED.value)
        .limit(1)
    ).first()
    return record is not None


def expire_active_contracts(
    *,
    session: "Session",
    reference_time: datetime,
    session_id: str | None = None,
) -> list[AgentContract]:
    """Transition ACTIVE contracts that have passed their expires_at to EXPIRED.

    If session_id is given, only contracts for that session are swept.
    Returns the list of newly-expired contracts (pre-mutation snapshots for
    audit payload use). Returns [] if no eligible contracts exist.
    """
    from db.models import AgentContractRecord

    stmt = (
        select(AgentContractRecord)
        .where(AgentContractRecord.contract_state == ContractState.ACTIVE.value)
        .where(AgentContractRecord.expires_at.isnot(None))  # type: ignore[union-attr]
        .where(AgentContractRecord.expires_at <= reference_time)  # type: ignore[union-attr]
    )
    if session_id is not None:
        stmt = stmt.where(AgentContractRecord.session_id == session_id)

    records = session.exec(stmt).all()
    expired: list[AgentContract] = []
    for record in records:
        snapshot = _to_schema(record)
        record.contract_state = ContractState.EXPIRED.value
        session.add(record)
        expired.append(snapshot)
    return expired


def has_expired_contract(*, session: "Session", session_id: str) -> bool:
    """Return True if any un-renewed contract for this session is in EXPIRED state.

    Only unrenewed expired contracts gate further execution. Once a contract is
    renewed (renewed_at is set), the EXPIRED record is retained as immutable
    history and no longer blocks requests.
    """
    from db.models import AgentContractRecord

    record = session.exec(
        select(AgentContractRecord)
        .where(AgentContractRecord.session_id == session_id)
        .where(AgentContractRecord.contract_state == ContractState.EXPIRED.value)
        .where(AgentContractRecord.renewed_at.is_(None))  # type: ignore[union-attr]
        .limit(1)
    ).first()
    return record is not None


def renew_expired_contracts(
    *,
    session: "Session",
    session_id: str,
    renewed_by: str,
    renewed_reason: str,
    bound_at: datetime,
    expires_at: datetime | None = None,
    renewed_at: datetime | None = None,
) -> tuple[list[AgentContract], AgentContract] | None:
    """Governed renewal: mark all un-renewed EXPIRED contracts, create a new ACTIVE one.

    EXPIRED contracts are never mutated back to ACTIVE. Instead:
    - Each unrenewed EXPIRED record gets renewed_at/by/reason set (terminal metadata).
    - A fresh ACTIVE contract is created, copying authority identity from the most
      recently expired contract (same actor_id, agent_id, delegation_chain_id,
      allowed_tool_families_json, session_id).

    Returns None if no un-renewed EXPIRED contracts exist for the session (caller
    should return 409). Returns (expired_snapshots, new_contract) on success, where
    expired_snapshots are pre-mutation (renewed_at still None) for audit payload use.
    """
    from db.models import AgentContractRecord

    records = session.exec(
        select(AgentContractRecord)
        .where(AgentContractRecord.session_id == session_id)
        .where(AgentContractRecord.contract_state == ContractState.EXPIRED.value)
        .where(AgentContractRecord.renewed_at.is_(None))  # type: ignore[union-attr]
    ).all()

    if not records:
        return None

    now = renewed_at or utc_now()

    # Use the most recently expired contract as the authority source for the new contract.
    source = max(records, key=lambda r: r.bound_at)

    # Capture pre-mutation snapshots for audit payload use, then mark as renewed.
    expired_snapshots: list[AgentContract] = []
    for record in records:
        expired_snapshots.append(_to_schema(record))
        record.renewed_at = now
        record.renewed_by = renewed_by
        record.renewed_reason = renewed_reason
        session.add(record)

    # Create a fresh ACTIVE contract inheriting authority from the source record.
    allowed = json.loads(source.allowed_tool_families_json or "[]")
    new_record = AgentContractRecord(
        contract_id=f"ctr_{uuid.uuid4().hex[:16]}",
        run_id=f"ren_{uuid.uuid4().hex[:12]}",
        session_id=session_id,
        trace_id=None,
        actor_id=source.actor_id,
        agent_id=source.agent_id,
        delegation_chain_id=source.delegation_chain_id,
        allowed_tool_families_json=json.dumps(allowed),
        contract_state=ContractState.ACTIVE.value,
        bound_at=bound_at,
        expires_at=expires_at,
    )
    session.add(new_record)
    return expired_snapshots, _to_schema(new_record)


def sweep_expired_contracts(*, global_chain_id: str) -> int:
    """Global expiry sweep: transition all ACTIVE contracts past their TTL to EXPIRED.

    Designed to be called by the background sweep task on a configurable interval.
    Idempotent: expire_active_contracts() selects only ACTIVE contracts where
    expires_at <= reference_time, so already-EXPIRED or REVOKED contracts are
    excluded — running the sweep multiple times produces no duplicate mutations
    or duplicate audit events.

    Emits CONTRACT_EXPIRED to both the global and session-scoped audit chains,
    using the same payload structure as the inline expiry path in evaluate.py.

    Returns the count of contracts swept to EXPIRED in this pass.

    Single-process assumption: the app runs as one uvicorn worker by default.
    Under multi-worker deployment each worker runs its own sweep loop; concurrent
    sweeps are safe because SQLite WAL mode serialises writers and the ACTIVE-only
    query ensures the second sweeper finds no rows to mutate.
    """
    from core.audit import append_audit_event_with_session_chain
    from db.sqlite import get_engine
    from sqlmodel import Session as _Session

    now = utc_now()
    with _Session(get_engine()) as session:
        expired = expire_active_contracts(session=session, reference_time=now, session_id=None)
        for contract in expired:
            append_audit_event_with_session_chain(
                session=session,
                global_chain_id=global_chain_id,
                session_id=contract.session_id,
                event_type="CONTRACT_EXPIRED",
                event_payload={
                    "contract_id": contract.contract_id,
                    "run_id": contract.run_id,
                    "session_id": contract.session_id,
                    "agent_id": contract.agent_id,
                    "actor_id": contract.actor_id,
                    "delegation_chain_id": contract.delegation_chain_id,
                    "expires_at": (
                        contract.expires_at.isoformat()
                        if contract.expires_at is not None
                        else None
                    ),
                    "reference_time": now.isoformat(),
                },
            )
        session.commit()
    return len(expired)


def bind_contract(
    *,
    session: "Session",
    authority_context: RunAuthorityContext,
    bound_at: datetime,
    expires_at: datetime | None = None,
) -> AgentContract:
    """Create and persist a contract binding for a governed run."""
    from db.models import AgentContractRecord

    allowed = list(authority_context.agent_identity.allowed_tool_families)
    record = AgentContractRecord(
        contract_id=f"ctr_{uuid.uuid4().hex[:16]}",
        run_id=authority_context.run_id,
        session_id=authority_context.session_id,
        trace_id=authority_context.trace_id,
        actor_id=authority_context.actor_identity.actor_id,
        agent_id=authority_context.agent_identity.agent_id,
        delegation_chain_id=authority_context.delegation_chain.delegation_chain_id,
        allowed_tool_families_json=json.dumps(allowed),
        contract_state=ContractState.ACTIVE.value,
        bound_at=bound_at,
        expires_at=expires_at,
    )
    session.add(record)
    return _to_schema(record)


def get_active_contract(*, session: "Session", run_id: str) -> AgentContract | None:
    """Return the active contract for a run, or None."""
    from db.models import AgentContractRecord

    record = session.exec(
        select(AgentContractRecord)
        .where(AgentContractRecord.run_id == run_id)
        .where(AgentContractRecord.contract_state == ContractState.ACTIVE.value)
        .limit(1)
    ).first()
    return _to_schema(record) if record is not None else None


def revoke_active_contracts(
    *,
    session: "Session",
    revoked_reason: str,
    revoked_by: str,
    revoked_at: datetime | None = None,
    session_id: str | None = None,
    agent_id: str | None = None,
    allow_global: bool = False,
) -> list[AgentContract]:
    """Transition ACTIVE contracts to REVOKED.

    Requires at least one of session_id or agent_id, OR explicit allow_global=True.
    Raises ValueError if called with no scope and allow_global=False to prevent
    accidental global revocation.
    """
    from db.models import AgentContractRecord

    if session_id is None and agent_id is None and not allow_global:
        raise ValueError(
            "Global contract revocation requires allow_global=True. "
            "Pass allow_global=True to confirm intent to revoke all active contracts."
        )

    stmt = select(AgentContractRecord).where(
        AgentContractRecord.contract_state == ContractState.ACTIVE.value
    )
    if session_id is not None:
        stmt = stmt.where(AgentContractRecord.session_id == session_id)
    if agent_id is not None:
        stmt = stmt.where(AgentContractRecord.agent_id == agent_id)

    now = revoked_at or utc_now()
    records = session.exec(stmt).all()
    for record in records:
        record.contract_state = ContractState.REVOKED.value
        record.revoked_at = now
        record.revoked_reason = revoked_reason
        record.revoked_by = revoked_by
        session.add(record)

    return [_to_schema(record) for record in records]


def record_usage(
    *,
    session: "Session",
    contract: AgentContract,
    elapsed_ms: float,
    tool_invocations: int = 1,
) -> ContractUsageState:
    """Persist a usage record for a completed governed run."""
    from db.models import ContractUsageRecord

    now = utc_now()
    record = ContractUsageRecord(
        usage_id=f"usg_{uuid.uuid4().hex[:16]}",
        contract_id=contract.contract_id,
        run_id=contract.run_id,
        tokens_used=0,
        spend_used=0.0,
        elapsed_ms=elapsed_ms,
        tool_invocations=tool_invocations,
        last_updated_at=now,
        current_state=contract.contract_state.value,
    )
    session.add(record)
    return _usage_to_schema(record)


def _usage_to_schema(record: "ContractUsageRecord") -> ContractUsageState:
    return ContractUsageState(
        usage_id=record.usage_id,
        contract_id=record.contract_id,
        run_id=record.run_id,
        tokens_used=record.tokens_used,
        spend_used=record.spend_used,
        elapsed_ms=record.elapsed_ms,
        tool_invocations=record.tool_invocations,
        last_updated_at=record.last_updated_at,
        current_state=ContractState(record.current_state),
    )


def _to_schema(record: "AgentContractRecord") -> AgentContract:
    return AgentContract(
        contract_id=record.contract_id,
        run_id=record.run_id,
        session_id=record.session_id,
        trace_id=record.trace_id,
        actor_id=record.actor_id,
        agent_id=record.agent_id,
        delegation_chain_id=record.delegation_chain_id,
        allowed_tool_families=json.loads(record.allowed_tool_families_json or "[]"),
        contract_state=ContractState(record.contract_state),
        bound_at=record.bound_at,
        expires_at=record.expires_at,
        renewed_at=record.renewed_at,
        revoked_at=record.revoked_at,
        revoked_reason=record.revoked_reason,
        revoked_by=record.revoked_by,
    )
