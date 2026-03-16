"""
core/modes.py - Enumerations and constants for ZDG Agent Firewall.

All decision states, reason codes, tool families, and kill switch scopes
are defined here. No business logic lives in this module.
"""

from enum import Enum


class Decision(str, Enum):
    """Possible outcomes of a policy evaluation."""

    ALLOW = "ALLOW"
    WARN = "WARN"
    PAUSE = "PAUSE"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"
    RETRY = "RETRY"
    QUARANTINE = "QUARANTINE"
    TERMINATE = "TERMINATE"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"


class Disposition(str, Enum):
    """Canonical replay/evidence disposition vocabulary."""

    ALLOW = "allow"
    HOLD = "hold"
    BLOCK = "block"
    TERMINATE = "terminate"
    QUARANTINE = "quarantine"
    ESCALATE = "escalate"


class ReasonCode(str, Enum):
    """Machine-readable reason codes returned on every decision."""

    ALLOW = "ALLOW"
    APPROVED_MATCHED = "APPROVED_MATCHED"
    APPROVAL_ALREADY_USED = "APPROVAL_ALREADY_USED"
    APPROVAL_ALREADY_RESOLVED = "APPROVAL_ALREADY_RESOLVED"
    RISK_THRESHOLD_BLOCK = "RISK_THRESHOLD_BLOCK"
    APPROVAL_REQUIRED_THRESHOLD = "APPROVAL_REQUIRED_THRESHOLD"
    EXPLICIT_POLICY_DENY = "EXPLICIT_POLICY_DENY"
    DEFAULT_DENY = "DEFAULT_DENY"
    KILLSWITCH_ACTIVE = "KILLSWITCH_ACTIVE"
    APPROVAL_NOT_FOUND = "APPROVAL_NOT_FOUND"
    PAYLOAD_MISMATCH = "PAYLOAD_MISMATCH"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    UNREGISTERED_TOOL_FAMILY = "UNREGISTERED_TOOL_FAMILY"
    NORMALIZATION_FAILED = "NORMALIZATION_FAILED"
    IDEMPOTENCY_KEY_PAYLOAD_MISMATCH = "IDEMPOTENCY_KEY_PAYLOAD_MISMATCH"
    IDEMPOTENCY_KEY_REQUIRED = "IDEMPOTENCY_KEY_REQUIRED"
    WRAPPER_BLOCKED = "WRAPPER_BLOCKED"
    IDENTITY_FAILED = "IDENTITY_FAILED"
    AUTHORITY_BINDING_REQUIRED = "AUTHORITY_BINDING_REQUIRED"
    AUTHORITY_SCOPE_VIOLATION = "AUTHORITY_SCOPE_VIOLATION"
    CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
    CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
    HANDOFF_SCHEMA_NOT_FOUND = "HANDOFF_SCHEMA_NOT_FOUND"
    HANDOFF_VALIDATION_FAILED = "HANDOFF_VALIDATION_FAILED"
    UNGOVERNED_TOOL_FAMILY = "UNGOVERNED_TOOL_FAMILY"
    SESSION_CLOSED = "SESSION_CLOSED"
    SESSION_SUSPENDED = "SESSION_SUSPENDED"
    AGENT_SUSPENDED = "AGENT_SUSPENDED"
    CONTRACT_REVOKED = "CONTRACT_REVOKED"
    CONTRACT_EXPIRED = "CONTRACT_EXPIRED"
    BREACH_ESCALATED = "BREACH_ESCALATED"
    GUARDRAIL_BLOCKED = "GUARDRAIL_BLOCKED"


class NormalizationStatus(str, Enum):
    """Result of payload canonicalization."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class KillSwitchScope(str, Enum):
    """Scopes at which a kill switch can be active."""

    GLOBAL = "global"
    AGENT = "agent"
    TOOL_FAMILY = "tool_family"
    SESSION = "session"


class ToolFamily(str, Enum):
    """Governed tool families. Any tool family not listed here is ungoverned."""

    SHELL = "shell"
    HTTP = "http"
    FILESYSTEM = "filesystem"
    MESSAGING = "messaging"


class PolicyEffect(str, Enum):
    """Effect of an explicit policy rule."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    GOVERNED = "GOVERNED"


class GuardrailIntervention(str, Enum):
    """Control actions a guardrail can recommend or enforce."""

    NONE = "none"
    PAUSE = "pause"
    TERMINATE = "terminate"


class StreamingMode(str, Enum):
    """Streaming release strategies surfaced to runtime adapters."""

    BUFFERED = "buffered"
    VALIDATED_RELEASE = "validated_release"


class GalStage(str, Enum):
    """Canonical Governed Action Lifecycle stages."""

    INTENT = "intent"
    NORMALIZATION = "normalization"
    POLICY_CONTEXT = "policy_context"
    RISK_EVALUATION = "risk_evaluation"
    DECISION = "decision"
    EXECUTION = "execution"
    EVIDENCE = "evidence"


class EnforcementModuleOrigin(str, Enum):
    """Primary module or control stage responsible for an enforcement decision."""

    IDENTITY = "identity"
    DELEGATION = "delegation"
    AUTHORITY_CONTEXT = "authority_context"
    CREDENTIALING = "credentialing"
    HANDOFF_FIREWALL = "handoff_firewall"
    NORMALIZATION = "normalization"
    POLICY_CONTEXT = "policy_context"
    RISK_EVALUATION = "risk_evaluation"
    DECISION = "decision"
    GUARDRAILS = "guardrails"
    EXECUTION = "execution"


DANGEROUS_FAMILIES: set[str] = {
    ToolFamily.SHELL,
    ToolFamily.FILESYSTEM,
    ToolFamily.HTTP,
    ToolFamily.MESSAGING,
}

KILLSWITCH_PRECEDENCE: list[KillSwitchScope] = [
    KillSwitchScope.GLOBAL,
    KillSwitchScope.AGENT,
    KillSwitchScope.TOOL_FAMILY,
    KillSwitchScope.SESSION,
]


class CredentialLeaseState(str, Enum):
    """Lease states for first-pass scoped credential grants."""

    ISSUED = "issued"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class HandoffValidationState(str, Enum):
    """Validation states for typed handoff enforcement."""

    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"


class ContractState(str, Enum):
    """Lifecycle states for an agent contract binding."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
