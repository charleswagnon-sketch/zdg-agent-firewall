"""Scoped credential grant lifecycle and authority validation helpers."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlmodel import Session, select

from core import decision as decision_engine
from core.modes import CredentialLeaseState, DANGEROUS_FAMILIES, ReasonCode
from core.schemas import ActionRequest, CredentialGrant, RunAuthorityContext
from db.models import CredentialGrantRecord
from wrappers.base import ExecutionContext


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def requires_scoped_credential(body: ActionRequest, context: ExecutionContext) -> bool:
    """Real privileged execution requires an explicit scoped credential."""

    return context.is_real_exec_enabled(body.tool_family) and body.tool_family in DANGEROUS_FAMILIES


def validate_authority_context(
    *,
    body: ActionRequest,
    authority_context: RunAuthorityContext,
    context: ExecutionContext,
    evaluation_time: datetime,
) -> tuple[ReasonCode, str] | None:
    """Validate explicit authority before privileged real execution."""

    if not requires_scoped_credential(body, context):
        return None

    if body.actor_identity is None or body.delegation_chain is None:
        return (
            ReasonCode.AUTHORITY_BINDING_REQUIRED,
            "Privileged real execution requires explicit actor identity and delegation chain binding.",
        )

    chain = authority_context.delegation_chain
    if chain.root_actor_id != authority_context.actor_identity.actor_id:
        return (
            ReasonCode.AUTHORITY_SCOPE_VIOLATION,
            "Delegation root actor does not match the initiating actor identity.",
        )

    if chain.expires_at is not None and _to_naive_utc(chain.expires_at) <= evaluation_time:
        return (
            ReasonCode.AUTHORITY_SCOPE_VIOLATION,
            "Delegation chain has expired for the requested execution.",
        )

    if chain.delegated_agent_ids and authority_context.agent_identity.agent_id not in chain.delegated_agent_ids:
        return (
            ReasonCode.AUTHORITY_SCOPE_VIOLATION,
            "Delegation chain does not authorize the requested agent.",
        )

    authority_scope = chain.authority_scope or {}
    requested_family = authority_context.requested_tool_family
    requested_action = authority_context.requested_operation
    scoped_family = authority_scope.get("tool_family")
    scoped_action = authority_scope.get("action")

    if scoped_family and str(scoped_family) != requested_family:
        return (
            ReasonCode.AUTHORITY_SCOPE_VIOLATION,
            f"Delegation scope permits tool family '{scoped_family}', not '{requested_family}'.",
        )

    if scoped_action and str(scoped_action) != requested_action:
        return (
            ReasonCode.AUTHORITY_SCOPE_VIOLATION,
            f"Delegation scope permits action '{scoped_action}', not '{requested_action}'.",
        )

    allowed_tool_families = authority_context.agent_identity.allowed_tool_families
    if allowed_tool_families and requested_family not in allowed_tool_families:
        return (
            ReasonCode.AUTHORITY_SCOPE_VIOLATION,
            f"Agent '{authority_context.agent_identity.agent_id}' is not permitted to use tool family '{requested_family}'.",
        )

    return None


def issue_credential_grant(
    *,
    session: Session,
    authority_context: RunAuthorityContext,
    body: ActionRequest,
    ttl_seconds: int,
    issued_at: datetime,
) -> CredentialGrant:
    """Create a new scoped credential grant in issued state."""

    expires_at = issued_at + timedelta(seconds=max(ttl_seconds, 1))
    grant = CredentialGrantRecord(
        grant_id=f"grt_{uuid.uuid4().hex[:16]}",
        run_id=authority_context.run_id,
        session_id=authority_context.session_id,
        trace_id=authority_context.trace_id,
        actor_id=authority_context.actor_identity.actor_id,
        agent_id=authority_context.agent_identity.agent_id,
        delegation_chain_id=authority_context.delegation_chain.delegation_chain_id,
        tool_family=body.tool_family,
        action=body.action,
        privilege_scope_json=json.dumps(_build_privilege_scope(authority_context)),
        lease_state=CredentialLeaseState.ISSUED.value,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    session.add(grant)
    return _to_schema(grant)


def activate_credential_grant(
    *,
    session: Session,
    grant_id: str,
    activated_at: datetime,
) -> CredentialGrant:
    """Activate an issued grant immediately before real execution."""

    record = _get_grant_record(session, grant_id)
    record.lease_state = CredentialLeaseState.ACTIVE.value
    record.activated_at = activated_at
    session.add(record)
    return _to_schema(record)


def expire_active_grants(session: Session, reference_time: datetime) -> list[CredentialGrant]:
    """Expire any issued or active grants whose TTL has elapsed."""

    stmt = (
        select(CredentialGrantRecord)
        .where(CredentialGrantRecord.lease_state.in_([CredentialLeaseState.ISSUED.value, CredentialLeaseState.ACTIVE.value]))
        .where(CredentialGrantRecord.expires_at <= reference_time)
    )
    records = session.exec(stmt).all()
    expired: list[CredentialGrant] = []
    for record in records:
        record.lease_state = CredentialLeaseState.EXPIRED.value
        session.add(record)
        expired.append(_to_schema(record))
    return expired


def revoke_credential_grant(
    *,
    session: Session,
    grant_id: str,
    revoked_reason: str,
    revoked_by: str | None = None,
    revoked_at: datetime | None = None,
) -> CredentialGrant | None:
    """Revoke one active or issued grant."""

    record = session.exec(
        select(CredentialGrantRecord).where(CredentialGrantRecord.grant_id == grant_id)
    ).first()
    if record is None:
        return None
    if record.lease_state in {CredentialLeaseState.REVOKED.value, CredentialLeaseState.EXPIRED.value}:
        return _to_schema(record)

    record.lease_state = CredentialLeaseState.REVOKED.value
    record.revoked_at = revoked_at or utc_now()
    record.revoked_reason = revoked_reason
    record.revoked_by = revoked_by
    session.add(record)
    return _to_schema(record)


def revoke_active_grants(
    *,
    session: Session,
    revoked_reason: str,
    revoked_by: str | None = None,
    revoked_at: datetime | None = None,
    session_id: str | None = None,
    agent_id: str | None = None,
    tool_family: str | None = None,
) -> list[CredentialGrant]:
    """Revoke matching active or issued grants for lifecycle and kill-switch hooks."""

    stmt = select(CredentialGrantRecord).where(
        CredentialGrantRecord.lease_state.in_([CredentialLeaseState.ISSUED.value, CredentialLeaseState.ACTIVE.value])
    )
    if session_id is not None:
        stmt = stmt.where(CredentialGrantRecord.session_id == session_id)
    if agent_id is not None:
        stmt = stmt.where(CredentialGrantRecord.agent_id == agent_id)
    if tool_family is not None:
        stmt = stmt.where(CredentialGrantRecord.tool_family == tool_family)

    records = session.exec(stmt).all()
    revoked: list[CredentialGrant] = []
    effective_revoked_at = revoked_at or utc_now()
    for record in records:
        record.lease_state = CredentialLeaseState.REVOKED.value
        record.revoked_at = effective_revoked_at
        record.revoked_reason = revoked_reason
        record.revoked_by = revoked_by
        session.add(record)
        revoked.append(_to_schema(record))
    return revoked


def build_credential_event_payload(
    grant: CredentialGrant,
    *,
    event_type: str,
    authority_context: RunAuthorityContext | None = None,
    operator: str | None = None,
    source_component: str = "agent_firewall.credentialing",
) -> dict[str, Any]:
    payload = {
        **decision_engine.build_runtime_correlation(
            timestamp=_credential_event_timestamp(grant, event_type),
            source_component=source_component,
            authority_context=authority_context,
            run_id=grant.run_id,
            session_id=grant.session_id,
            trace_id=grant.trace_id,
            actor_id=grant.actor_id,
            agent_id=grant.agent_id,
            delegation_id=grant.delegation_chain_id,
            authority_scope=dict(grant.privilege_scope),
        ).model_dump(mode="json"),
        **grant.model_dump(mode="json"),
    }
    if authority_context is not None:
        payload["authority_context"] = authority_context.model_dump(mode="json")
    if operator is not None:
        payload["operator"] = operator
    return payload


def _build_privilege_scope(authority_context: RunAuthorityContext) -> dict[str, Any]:
    scope = dict(authority_context.delegation_chain.authority_scope or {})
    scope.setdefault("tool_family", authority_context.requested_tool_family)
    scope.setdefault("action", authority_context.requested_operation)
    if authority_context.session_id is not None:
        scope.setdefault("session_id", authority_context.session_id)
    scope.setdefault("run_id", authority_context.run_id)
    if authority_context.trace_id is not None:
        scope.setdefault("trace_id", authority_context.trace_id)
    return scope


def _to_schema(record: CredentialGrantRecord) -> CredentialGrant:
    return CredentialGrant(
        grant_id=record.grant_id,
        run_id=record.run_id,
        session_id=record.session_id,
        trace_id=record.trace_id,
        actor_id=record.actor_id,
        agent_id=record.agent_id,
        delegation_chain_id=record.delegation_chain_id,
        tool_family=record.tool_family,
        action=record.action,
        privilege_scope=json.loads(record.privilege_scope_json or "{}"),
        lease_state=CredentialLeaseState(record.lease_state),
        issued_at=record.issued_at,
        activated_at=record.activated_at,
        expires_at=record.expires_at,
        revoked_at=record.revoked_at,
        revoked_reason=record.revoked_reason,
        revoked_by=record.revoked_by,
    )


def _get_grant_record(session: Session, grant_id: str) -> CredentialGrantRecord:
    record = session.exec(
        select(CredentialGrantRecord).where(CredentialGrantRecord.grant_id == grant_id)
    ).first()
    if record is None:
        raise KeyError(f"Credential grant '{grant_id}' was not found.")
    return record


def _to_naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _credential_event_timestamp(grant: CredentialGrant, event_type: str) -> datetime:
    if event_type == "CREDENTIAL_REVOKED" and grant.revoked_at is not None:
        return grant.revoked_at
    if event_type == "CREDENTIAL_ACTIVATED" and grant.activated_at is not None:
        return grant.activated_at
    return grant.issued_at
