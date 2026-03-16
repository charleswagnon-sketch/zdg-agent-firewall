"""
wrappers/base.py - Abstract base class and execution context for governed wrappers.

Every wrapper must implement:
  - normalize(args) -> family-specific request dataclass
  - execute(request) -> WrapperResult

All real execution stays behind an explicit ExecutionContext so routes do not
need to bypass wrappers to perform side effects.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.modes import CredentialLeaseState, DANGEROUS_FAMILIES


@dataclass(frozen=True)
class ExecutionContext:
    """Runtime controls shared by all wrappers."""

    real_exec: bool = False
    real_exec_shell: bool = False
    real_exec_http: bool = False
    real_exec_filesystem: bool = False
    real_exec_messaging: bool = False
    workspace_root: str = "~/workspace"
    filesystem_allowed_roots: tuple[str, ...] = field(default_factory=tuple)
    fs_read_approval_bytes: int = 10 * 1024 * 1024
    maildir_path: str = "~/.zdg/maildir"
    bulk_send_threshold: int = 5
    approved_domains: tuple[str, ...] = field(default_factory=tuple)
    approved_recipient_domains: tuple[str, ...] = field(default_factory=tuple)
    shell_timeout_seconds: int = 15
    shell_max_output_bytes: int = 16 * 1024
    shell_allowed_env: tuple[str, ...] = field(default_factory=tuple)
    http_timeout_seconds: float = 10.0
    http_max_response_bytes: int = 64 * 1024
    http_max_redirects: int = 3
    request_id: str | None = None
    trace_id: str | None = None
    attempt_id: str | None = None
    session_id: str | None = None
    agent_id: str | None = None
    actor_id: str | None = None
    delegation_chain_id: str | None = None
    tool_family: str | None = None
    credential_grant_id: str | None = None
    credential_lease_state: str | None = None
    privilege_scope: dict[str, Any] = field(default_factory=dict)

    def is_real_exec_enabled(self, family: str) -> bool:
        family_flag = {
            "shell": self.real_exec_shell,
            "http": self.real_exec_http,
            "filesystem": self.real_exec_filesystem,
            "messaging": self.real_exec_messaging,
        }.get(family, False)
        return self.real_exec or family_flag

    @property
    def workspace_root_resolved(self) -> str:
        return str(Path(self.workspace_root).expanduser().resolve())

    @property
    def filesystem_allowed_roots_resolved(self) -> tuple[str, ...]:
        roots = self.filesystem_allowed_roots or (self.workspace_root,)
        return tuple(str(Path(root).expanduser().resolve()) for root in roots)

    @property
    def maildir_path_resolved(self) -> str:
        return str(Path(self.maildir_path).expanduser().resolve())


@dataclass
class WrapperResult:
    """Standardized result from any wrapper execution."""

    executed: bool = False
    mock: bool = True
    output_summary: str = ""
    raw_output: dict[str, Any] | None = None
    blocked_reason: str | None = None


class BaseWrapper(ABC):
    """Abstract base for all governed tool wrappers."""

    tool_family: str = "unknown"

    def __init__(self, context: ExecutionContext | None = None) -> None:
        self.context = context or ExecutionContext()

    @abstractmethod
    def normalize(self, args: dict[str, Any]) -> Any:
        """Convert raw args dict into a typed, validated request dataclass."""

    @abstractmethod
    def execute(self, request: Any) -> WrapperResult:
        """Execute or simulate the tool action."""

    def run(self, args: dict[str, Any]) -> WrapperResult:
        """Convenience method: normalize + execute in one call."""

        if self._credential_required() and not self._credential_is_active():
            return WrapperResult(
                executed=False,
                mock=False,
                output_summary="Credential grant missing or inactive for privileged real execution.",
                blocked_reason="Scoped credential grant is required before privileged real execution.",
            )
        try:
            request = self.normalize(args)
        except (ValueError, KeyError, TypeError) as exc:
            return WrapperResult(
                executed=False,
                mock=False,
                output_summary=f"Normalization failed: {exc}",
                blocked_reason=str(exc),
            )
        return self.execute(request)

    def _credential_required(self) -> bool:
        return self.context.is_real_exec_enabled(self.tool_family) and self.tool_family in DANGEROUS_FAMILIES

    def _credential_is_active(self) -> bool:
        return (
            bool(self.context.credential_grant_id)
            and self.context.credential_lease_state == CredentialLeaseState.ACTIVE.value
        )
