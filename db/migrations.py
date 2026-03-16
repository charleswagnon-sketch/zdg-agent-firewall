"""
db/migrations.py - Schema migrations with safe, idempotent column additions.

All migrations use _safe_add_column() which inspects existing schema before
applying any ALTER TABLE. init_db() can be called any number of times without
error or data corruption.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from db.sqlite import get_engine


def _get_raw_connection() -> sqlite3.Connection:
    """Get a raw sqlite3 connection for PRAGMA-level operations."""

    engine = get_engine()
    return sqlite3.connect(engine.url.database)


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    cursor = conn.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cursor.fetchall())


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    )
    return cursor.fetchone() is not None


def _safe_create_index(
    conn: sqlite3.Connection, index_name: str, table: str, columns: str
) -> None:
    """Create an index if it does not already exist. Always idempotent."""
    conn.execute(f"CREATE INDEX IF NOT EXISTS {index_name} ON {table} ({columns})")
    conn.commit()


def _safe_create_unique_index(
    conn: sqlite3.Connection,
    index_name: str,
    table: str,
    columns: str,
    where: str | None = None,
) -> None:
    """Create a unique index if it does not already exist. Always idempotent.

    Pass where= for a partial unique index, e.g. where="seq IS NOT NULL".
    """
    sql = f"CREATE UNIQUE INDEX IF NOT EXISTS {index_name} ON {table} ({columns})"
    if where:
        sql += f" WHERE {where}"
    conn.execute(sql)
    conn.commit()


def _safe_add_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> bool:
    if not _table_exists(conn, table):
        return False
    if _column_exists(conn, table, column):
        return False
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    conn.commit()
    return True


def _check_no_null_seq_rows(conn: sqlite3.Connection) -> None:
    """Guard: raise RuntimeError if any audit_events rows have seq IS NULL.

    Must be called before enforcing NOT NULL on seq. If any legacy NULL-seq rows
    exist, the operator must resolve them manually — no auto-backfill or silent
    repair. Raises RuntimeError with an explicit operator-facing message.

    Does nothing if the audit_events table does not yet exist (new DB).
    """
    if not _table_exists(conn, "audit_events"):
        return
    cursor = conn.execute("SELECT COUNT(*) FROM audit_events WHERE seq IS NULL")
    count = cursor.fetchone()[0]
    if count > 0:
        raise RuntimeError(
            f"DB-05 guard: {count} row(s) in audit_events have seq IS NULL. "
            "Cannot enforce NOT NULL on audit_events.seq while legacy NULL-seq rows exist. "
            "Resolve manually before restarting — no auto-backfill will be performed."
        )


def _add_seq_not_null_trigger(conn: sqlite3.Connection) -> None:
    """Add a BEFORE INSERT trigger that rejects NULL seq on audit_events.

    This is the DB-layer NOT NULL enforcement for audit_events.seq on databases
    where the column was originally created as nullable. New databases created
    via create_all() will have seq INTEGER NOT NULL at the DDL level; this trigger
    provides defence-in-depth for upgraded databases.
    """
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS audit_events_seq_not_null "
        "BEFORE INSERT ON audit_events "
        "WHEN NEW.seq IS NULL "
        "BEGIN SELECT RAISE(ABORT, 'audit_events.seq must not be null'); END"
    )
    conn.commit()


def _upgrade_chain_seq_to_full_unique(conn: sqlite3.Connection) -> None:
    """Replace the partial (chain_id, seq) unique index with a full unique index.

    The original partial index (WHERE seq IS NOT NULL) was added during DB-05 as a
    migration escape hatch: it let existing databases with legacy nullable-seq rows
    adopt a uniqueness constraint without failing. That escape hatch is now closed:
    - _check_no_null_seq_rows() refuses startup if any NULL-seq rows remain
    - _add_seq_not_null_trigger() blocks all new NULL seq inserts
    - seq is NOT NULL at DDL level for all newly created databases

    A full UNIQUE(chain_id, seq) is stronger: it covers every row unconditionally,
    making the uniqueness guarantee explicit and audit-defensible. There is no
    legitimate path for NULL seq values to exist in a post-DB-05 database, so the
    partial exclusion clause provides no benefit and should be removed.

    Upgrade procedure:
    1. DROP the old partial index IF EXISTS (no-op on fresh databases).
    2. CREATE the full unique index IF NOT EXISTS (no-op if already upgraded).
    Idempotent: safe to run on any number of re-migrations.

    Scope rationale: UNIQUE(chain_id, seq) — not UNIQUE(session_id, seq) — because
    AuditEvent has no session_id column. Session scope is encoded in chain_id as
    "session:{session_id}". The global chain uses a different chain_id. This single
    constraint covers both global and session-scoped chains with one index.
    """
    conn.execute("DROP INDEX IF EXISTS ix_audit_events_chain_seq")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_audit_events_chain_seq "
        "ON audit_events (chain_id, seq)"
    )
    conn.commit()


def _add_append_only_triggers(conn: Any) -> None:
    import sqlalchemy

    triggers = [
        (
            "audit_events_no_update",
            "CREATE TRIGGER IF NOT EXISTS audit_events_no_update "
            "BEFORE UPDATE ON audit_events "
            "BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END",
        ),
        (
            "audit_events_no_delete",
            "CREATE TRIGGER IF NOT EXISTS audit_events_no_delete "
            "BEFORE DELETE ON audit_events "
            "BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END",
        ),
    ]

    if isinstance(conn, sqlite3.Connection):
        for _name, sql in triggers:
            conn.execute(sql)
        conn.commit()
        return

    for _name, sql in triggers:
        conn.execute(sqlalchemy.text(sql))
    conn.commit()


def run_migrations() -> None:
    """Apply all schema migrations after create_tables()."""

    conn = _get_raw_connection()
    try:
        # Guard first: refuse to proceed if legacy NULL-seq rows exist.
        _check_no_null_seq_rows(conn)
        _add_append_only_triggers(conn)
        _add_seq_not_null_trigger(conn)
        _safe_add_column(conn, "approvals", "consumed_at", "DATETIME")
        _safe_add_column(conn, "approvals", "consumed_attempt_id", "TEXT")
        _safe_add_column(conn, "idempotency_cache", "approval_id", "TEXT")
        _safe_add_column(conn, "execution_results", "mock", "BOOLEAN DEFAULT 0")
        _safe_add_column(conn, "execution_results", "blocked_reason", "TEXT")
        _safe_add_column(conn, "execution_results", "raw_output_json", "TEXT")
        _safe_add_column(conn, "tool_attempts", "actor_id", "TEXT")
        _safe_add_column(conn, "tool_attempts", "delegation_chain_id", "TEXT")
        _safe_add_column(conn, "tool_attempts", "authority_context_json", "TEXT")
        _safe_add_column(conn, "tool_attempts", "run_id", "TEXT")
        _safe_add_column(conn, "tool_attempts", "trace_id", "TEXT")
        _safe_add_column(conn, "tool_attempts", "authority_scope_json", "TEXT")
        _safe_add_column(conn, "tool_attempts", "handoff_id", "TEXT")
        _safe_add_column(conn, "tool_attempts", "handoff_schema_version", "TEXT")
        _safe_add_column(conn, "tool_attempts", "handoff_validation_state", "TEXT")
        _safe_add_column(conn, "tool_attempts", "handoff_disposition", "TEXT")
        _safe_add_column(conn, "policy_decisions", "decision_state_canonical", "TEXT")
        _safe_add_column(conn, "policy_decisions", "disposition", "TEXT")
        _safe_add_column(conn, "policy_decisions", "module_origin", "TEXT")
        _safe_add_column(conn, "policy_decisions", "source_component", "TEXT")
        _safe_add_column(conn, "agent_records", "status_changed_at", "DATETIME")
        _safe_add_column(conn, "agent_records", "status_changed_by", "TEXT")
        _safe_add_column(conn, "agent_records", "status_reason", "TEXT")
        _safe_add_column(conn, "session_records", "created_by", "TEXT")
        _safe_add_column(conn, "session_records", "creation_source", "TEXT DEFAULT 'api'")
        _safe_add_column(conn, "session_records", "suspended_at", "DATETIME")
        _safe_add_column(conn, "session_records", "suspended_by", "TEXT")
        _safe_add_column(conn, "session_records", "suspend_reason", "TEXT")
        _safe_add_column(conn, "agent_contracts", "expires_at", "DATETIME")
        _safe_add_column(conn, "agent_contracts", "renewed_at", "DATETIME")
        _safe_add_column(conn, "agent_contracts", "renewed_by", "TEXT")
        _safe_add_column(conn, "agent_contracts", "renewed_reason", "TEXT")
        _safe_add_column(conn, "agent_contracts", "reinstated_at", "DATETIME")
        _safe_add_column(conn, "agent_contracts", "reinstated_by", "TEXT")
        _safe_add_column(conn, "agent_contracts", "reinstated_reason", "TEXT")
        _safe_create_index(conn, "ix_killswitch_scope", "killswitch_events", "scope")
        _safe_create_index(conn, "ix_killswitch_scope_value", "killswitch_events", "scope_value")
        _safe_create_index(conn, "ix_killswitch_reset_at", "killswitch_events", "reset_at")
        _safe_create_index(
            conn, "ix_contract_usage_last_updated_at", "contract_usage", "last_updated_at"
        )
        _safe_create_index(
            conn, "ix_credential_grants_expires_at", "credential_grants", "expires_at"
        )
        _safe_create_index(
            conn, "ix_credential_grants_revoked_at", "credential_grants", "revoked_at"
        )
        # tool_attempts columns added via ALTER TABLE — indexes not created by create_all()
        _safe_create_index(conn, "ix_tool_attempts_run_id", "tool_attempts", "run_id")
        _safe_create_index(conn, "ix_tool_attempts_trace_id", "tool_attempts", "trace_id")
        _safe_create_index(conn, "ix_tool_attempts_actor_id", "tool_attempts", "actor_id")
        _safe_create_index(
            conn, "ix_tool_attempts_delegation_chain_id", "tool_attempts", "delegation_chain_id"
        )
        _safe_create_index(conn, "ix_tool_attempts_handoff_id", "tool_attempts", "handoff_id")
        _safe_create_index(
            conn,
            "ix_tool_attempts_handoff_validation_state",
            "tool_attempts",
            "handoff_validation_state",
        )
        _safe_create_index(
            conn, "ix_tool_attempts_handoff_disposition", "tool_attempts", "handoff_disposition"
        )
        # policy_decisions columns added via ALTER TABLE
        _safe_create_index(
            conn,
            "ix_policy_decisions_decision_state_canonical",
            "policy_decisions",
            "decision_state_canonical",
        )
        _safe_create_index(
            conn, "ix_policy_decisions_disposition", "policy_decisions", "disposition"
        )
        _safe_create_index(
            conn, "ix_policy_decisions_module_origin", "policy_decisions", "module_origin"
        )
        _safe_create_index(
            conn, "ix_policy_decisions_source_component", "policy_decisions", "source_component"
        )
        # approvals columns added via ALTER TABLE
        _safe_create_index(conn, "ix_approvals_consumed_at", "approvals", "consumed_at")
        _safe_create_index(
            conn, "ix_approvals_consumed_attempt_id", "approvals", "consumed_attempt_id"
        )
        # idempotency_cache column added via ALTER TABLE
        _safe_create_index(
            conn, "ix_idempotency_cache_approval_id", "idempotency_cache", "approval_id"
        )
        # agent_contracts expires_at and reinstated_at added via ALTER TABLE
        _safe_create_index(
            conn, "ix_agent_contracts_expires_at", "agent_contracts", "expires_at"
        )
        _safe_create_index(
            conn, "ix_agent_contracts_reinstated_at", "agent_contracts", "reinstated_at"
        )
        # audit_events: enforce full UNIQUE(chain_id, seq) across all rows.
        # DB-05 created a partial index (WHERE seq IS NOT NULL) to let existing
        # databases with legacy nullable-seq rows adopt the constraint without
        # failing. That escape hatch is now closed: _check_no_null_seq_rows()
        # above refuses startup if any NULL-seq rows exist, and the NOT NULL
        # trigger blocks new ones. The partial index is vestigial — it excludes
        # NULL rows that can no longer exist. Replace it with a full constraint.
        _upgrade_chain_seq_to_full_unique(conn)
        # LIC-01: licensing table indexes (tables created via create_all()).
        _safe_create_index(conn, "ix_license_accounts_status", "license_accounts", "status")
        _safe_create_index(conn, "ix_licenses_account_id", "licenses", "account_id")
        _safe_create_index(conn, "ix_licenses_status", "licenses", "status")
        _safe_create_index(conn, "ix_licenses_expires_at", "licenses", "expires_at")
        _safe_create_index(conn, "ix_license_entitlements_license_id", "license_entitlements", "license_id")
        _safe_create_index(conn, "ix_license_entitlements_feature_code", "license_entitlements", "feature_code")
        _safe_create_index(conn, "ix_license_installations_account_id", "license_installations", "account_id")
        _safe_create_index(conn, "ix_license_installations_license_id", "license_installations", "license_id")
        _safe_create_index(conn, "ix_license_installations_revoked_at", "license_installations", "revoked_at")
        _safe_create_index(conn, "ix_license_events_license_id", "license_events", "license_id")
        _safe_create_index(conn, "ix_license_events_event_type", "license_events", "event_type")
        _safe_create_index(conn, "ix_license_usage_license_id", "license_usage", "license_id")
        _safe_create_index(conn, "ix_license_usage_feature_code", "license_usage", "feature_code")
        _safe_create_index(conn, "ix_license_usage_used_at", "license_usage", "used_at")
        _safe_create_index(conn, "ix_trial_feedback_feedback_type", "trial_feedback", "feedback_type")
        _safe_create_index(conn, "ix_trial_feedback_created_at", "trial_feedback", "created_at")
        # PAY-01: Stripe billing columns
        _safe_add_column(conn, "license_accounts", "stripe_customer_id", "TEXT")
        _safe_add_column(conn, "licenses", "stripe_subscription_id", "TEXT")
        _safe_add_column(conn, "licenses", "stripe_price_id", "TEXT")
        _safe_create_index(
            conn, "ix_license_accounts_stripe_customer_id", "license_accounts", "stripe_customer_id"
        )
        _safe_create_index(
            conn, "ix_licenses_stripe_subscription_id", "licenses", "stripe_subscription_id"
        )
    finally:
        conn.close()
