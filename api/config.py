"""
api/config.py - Application settings loaded from environment / .env file.

All configuration is sourced from environment variables.
No secrets are hardcoded.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Server
    zdg_host: str = "127.0.0.1"
    zdg_port: int = 8000
    zdg_env: str = "development"

    # Database
    zdg_db_path: str = "./zdg_firewall.db"

    # Policy bundle
    zdg_policy_bundle_path: str = "./policies/bundles/local_default.yaml"

    # Workspace and filesystem execution
    zdg_workspace: str = "~/workspace"
    zdg_filesystem_allowed_roots: list[str] = Field(default_factory=list)
    zdg_fs_read_approval_bytes: int = 10 * 1024 * 1024

    # Approval, idempotency, and repeated-denial risk tuning
    zdg_approval_expiry_seconds: int = 600
    zdg_idempotency_window_seconds: int = 300
    zdg_risk_block_count_window_seconds: int = 300
    zdg_risk_repeated_denials_threshold: int = 3

    # Guardrail execution and streaming
    zdg_guardrail_parallel_enabled: bool = True
    zdg_guardrail_parallel_workers: int = 4
    zdg_guardrail_pii_enabled: bool = True
    zdg_guardrail_toxicity_enabled: bool = True
    zdg_guardrail_jailbreak_enabled: bool = True
    zdg_streaming_guardrails_enabled: bool = True
    zdg_streaming_release_hold_chars: int = 160
    zdg_credential_ttl_seconds: int = 300
    zdg_contract_ttl_seconds: int = 3600
    # Background contract expiry sweep interval. Set to 0 to disable the sweeper.
    zdg_contract_expiry_sweep_interval_seconds: int = 60

    # Real execution gating
    zdg_real_exec: bool = False
    zdg_real_exec_shell: bool = False
    zdg_real_exec_http: bool = False
    zdg_real_exec_filesystem: bool = False
    zdg_real_exec_messaging: bool = False

    # Messaging execution
    zdg_maildir_path: str = "~/.zdg/maildir"

    # Shell execution limits
    zdg_shell_timeout_seconds: int = 15
    zdg_shell_max_output_bytes: int = 16 * 1024
    zdg_shell_allowed_env: list[str] = Field(
        default_factory=lambda: ["PATH", "HOME", "TMP", "TEMP", "TMPDIR", "LANG", "LC_ALL"]
    )

    # HTTP execution limits
    zdg_http_timeout_seconds: float = 10.0
    zdg_http_max_response_bytes: int = 64 * 1024
    zdg_http_max_redirects: int = 3

    # Contract breach warn thresholds (session-scoped, authoritative fields only)
    zdg_breach_warn_session_invocations: int = 100
    zdg_breach_warn_session_elapsed_ms: float = 600_000.0  # 10 minutes in ms
    # Escalation threshold: escalate session after this many BREACH_WARN events.
    # Set to 0 to disable escalation entirely.
    zdg_breach_escalation_warn_count: int = 3

    # Kill switch auto-trigger thresholds
    zdg_ks_shell_block_count: int = 3
    zdg_ks_shell_block_window: int = 120
    zdg_ks_http_block_count: int = 10
    zdg_ks_http_block_window: int = 300
    zdg_ks_escalate_count: int = 3

    # Control-plane auth
    zdg_admin_token: str = ""

    # Stripe billing (PAY-01)
    # Leave empty to run without Stripe. Billing routes return 503 when unconfigured.
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    # Stripe price IDs for each paid plan. Set these to your Stripe price IDs.
    stripe_price_id_dev_monthly: str = ""
    stripe_price_id_dev_annual: str = ""
    # Redirect URLs returned to Stripe-hosted pages.
    stripe_success_url: str = "http://localhost:8000/billing/success"
    stripe_cancel_url: str = "http://localhost:8000/billing/cancel"
    stripe_portal_return_url: str = "http://localhost:8000/billing"

    # Logging
    zdg_log_format: str = "text"

    # Audit chain ID
    zdg_chain_id: str = "zdg-local-chain-01"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    @property
    def db_path_resolved(self) -> str:
        return str(Path(self.zdg_db_path).expanduser().resolve())

    @property
    def policy_bundle_path_resolved(self) -> str:
        return str(Path(self.zdg_policy_bundle_path).expanduser().resolve())

    @property
    def workspace_resolved(self) -> str:
        return str(Path(self.zdg_workspace).expanduser().resolve())

    @property
    def filesystem_allowed_roots_resolved(self) -> list[str]:
        roots = self.zdg_filesystem_allowed_roots or [self.zdg_workspace]
        return [str(Path(root).expanduser().resolve()) for root in roots]

    @property
    def maildir_path_resolved(self) -> str:
        return str(Path(self.zdg_maildir_path).expanduser().resolve())


@lru_cache()
def get_settings() -> Settings:
    """Return cached Settings instance. Call once at startup."""

    return Settings()
