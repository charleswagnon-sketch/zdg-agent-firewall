"""
Unit tests: DB schema structure, migration idempotency, and audit immutability.
"""
from __future__ import annotations

import os
import sqlite3
import tempfile

import pytest
from sqlmodel import SQLModel, create_engine


def _make_db():
    """Create a temp-file SQLite DB with all tables applied via SQLModel.

    Returns (conn, path). Caller is responsible for conn.close() and os.unlink(path).
    SQLModel tables are created via the SQLAlchemy engine; the engine is then
    disposed and a raw sqlite3 connection opened to the same file so migration
    helpers (which take sqlite3.Connection) can operate on the same data.
    """
    import db.models  # noqa: F401 — register all tables in SQLModel metadata

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}")
    SQLModel.metadata.create_all(engine)
    engine.dispose()
    return sqlite3.connect(path), path


EXPECTED_TABLES = {
    "tool_attempts",
    "policy_decisions",
    "credential_grants",
    "execution_results",
    "approvals",
    "killswitch_events",
    "audit_events",
    "idempotency_cache",
    "agent_records",
    "agent_contracts",
    "contract_usage",
    "session_records",
}


def test_all_expected_tables_exist():
    conn, path = _make_db()
    try:
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing = {row[0] for row in cursor.fetchall()}
        missing = EXPECTED_TABLES - existing
        assert not missing, f"Missing tables: {missing}"
    finally:
        conn.close()
        os.unlink(path)


def test_safe_add_column_idempotent():
    """Calling _safe_add_column for an already-existing column returns False without error."""
    from db.migrations import _safe_add_column

    conn, path = _make_db()
    try:
        result = _safe_add_column(conn, "tool_attempts", "agent_id", "TEXT")
    finally:
        conn.close()
        os.unlink(path)
    assert result is False


def test_safe_add_column_adds_missing_column():
    """_safe_add_column adds a genuinely new column and returns True."""
    from db.migrations import _safe_add_column

    conn, path = _make_db()
    try:
        result = _safe_add_column(conn, "tool_attempts", "_test_col_xyz", "TEXT")
        cursor = conn.execute("PRAGMA table_info(tool_attempts)")
        cols = {row[1] for row in cursor.fetchall()}
    finally:
        conn.close()
        os.unlink(path)
    assert result is True
    assert "_test_col_xyz" in cols


def test_safe_add_column_missing_table_returns_false():
    """_safe_add_column returns False when the table does not exist."""
    from db.migrations import _safe_add_column

    conn, path = _make_db()
    try:
        result = _safe_add_column(conn, "nonexistent_table", "some_col", "TEXT")
    finally:
        conn.close()
        os.unlink(path)
    assert result is False


def test_killswitch_hot_path_indexes_exist():
    """scope, scope_value, and reset_at indexes exist on killswitch_events after _safe_create_index."""
    from db.migrations import _safe_create_index

    conn, path = _make_db()
    try:
        _safe_create_index(conn, "ix_killswitch_scope", "killswitch_events", "scope")
        _safe_create_index(conn, "ix_killswitch_scope_value", "killswitch_events", "scope_value")
        _safe_create_index(conn, "ix_killswitch_reset_at", "killswitch_events", "reset_at")
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='killswitch_events'"
        )
        index_names = {row[0] for row in cursor.fetchall()}
    finally:
        conn.close()
        os.unlink(path)

    assert "ix_killswitch_scope" in index_names
    assert "ix_killswitch_scope_value" in index_names
    assert "ix_killswitch_reset_at" in index_names


def test_credential_grants_expires_at_index_exists():
    """ix_credential_grants_expires_at exists on credential_grants after _safe_create_index."""
    from db.migrations import _safe_create_index

    conn, path = _make_db()
    try:
        _safe_create_index(
            conn, "ix_credential_grants_expires_at", "credential_grants", "expires_at"
        )
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='credential_grants'"
        )
        index_names = {row[0] for row in cursor.fetchall()}
    finally:
        conn.close()
        os.unlink(path)

    assert "ix_credential_grants_expires_at" in index_names


def test_credential_grants_revoked_at_index_exists():
    """ix_credential_grants_revoked_at exists on credential_grants after _safe_create_index."""
    from db.migrations import _safe_create_index

    conn, path = _make_db()
    try:
        _safe_create_index(
            conn, "ix_credential_grants_revoked_at", "credential_grants", "revoked_at"
        )
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='credential_grants'"
        )
        index_names = {row[0] for row in cursor.fetchall()}
    finally:
        conn.close()
        os.unlink(path)

    assert "ix_credential_grants_revoked_at" in index_names


def test_tool_attempts_migration_added_indexes_exist():
    """Indexes for columns added to tool_attempts via ALTER TABLE exist after _safe_create_index."""
    from db.migrations import _safe_create_index

    expected = {
        "ix_tool_attempts_run_id",
        "ix_tool_attempts_trace_id",
        "ix_tool_attempts_actor_id",
        "ix_tool_attempts_delegation_chain_id",
        "ix_tool_attempts_handoff_id",
        "ix_tool_attempts_handoff_validation_state",
        "ix_tool_attempts_handoff_disposition",
    }
    conn, path = _make_db()
    try:
        for ix, col in [
            ("ix_tool_attempts_run_id", "run_id"),
            ("ix_tool_attempts_trace_id", "trace_id"),
            ("ix_tool_attempts_actor_id", "actor_id"),
            ("ix_tool_attempts_delegation_chain_id", "delegation_chain_id"),
            ("ix_tool_attempts_handoff_id", "handoff_id"),
            ("ix_tool_attempts_handoff_validation_state", "handoff_validation_state"),
            ("ix_tool_attempts_handoff_disposition", "handoff_disposition"),
        ]:
            _safe_create_index(conn, ix, "tool_attempts", col)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='tool_attempts'"
        )
        index_names = {row[0] for row in cursor.fetchall()}
    finally:
        conn.close()
        os.unlink(path)

    missing = expected - index_names
    assert not missing, f"Missing tool_attempts indexes: {missing}"


def test_policy_decisions_migration_added_indexes_exist():
    """Indexes for columns added to policy_decisions via ALTER TABLE exist after _safe_create_index."""
    from db.migrations import _safe_create_index

    expected = {
        "ix_policy_decisions_decision_state_canonical",
        "ix_policy_decisions_disposition",
        "ix_policy_decisions_module_origin",
        "ix_policy_decisions_source_component",
    }
    conn, path = _make_db()
    try:
        for ix, col in [
            ("ix_policy_decisions_decision_state_canonical", "decision_state_canonical"),
            ("ix_policy_decisions_disposition", "disposition"),
            ("ix_policy_decisions_module_origin", "module_origin"),
            ("ix_policy_decisions_source_component", "source_component"),
        ]:
            _safe_create_index(conn, ix, "policy_decisions", col)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='policy_decisions'"
        )
        index_names = {row[0] for row in cursor.fetchall()}
    finally:
        conn.close()
        os.unlink(path)

    missing = expected - index_names
    assert not missing, f"Missing policy_decisions indexes: {missing}"


def test_approvals_migration_added_indexes_exist():
    """Indexes for columns added to approvals via ALTER TABLE exist after _safe_create_index."""
    from db.migrations import _safe_create_index

    conn, path = _make_db()
    try:
        _safe_create_index(conn, "ix_approvals_consumed_at", "approvals", "consumed_at")
        _safe_create_index(
            conn, "ix_approvals_consumed_attempt_id", "approvals", "consumed_attempt_id"
        )
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='approvals'"
        )
        index_names = {row[0] for row in cursor.fetchall()}
    finally:
        conn.close()
        os.unlink(path)

    assert "ix_approvals_consumed_at" in index_names
    assert "ix_approvals_consumed_attempt_id" in index_names


def test_idempotency_cache_approval_id_index_exists():
    """ix_idempotency_cache_approval_id exists on idempotency_cache after _safe_create_index."""
    from db.migrations import _safe_create_index

    conn, path = _make_db()
    try:
        _safe_create_index(
            conn, "ix_idempotency_cache_approval_id", "idempotency_cache", "approval_id"
        )
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='idempotency_cache'"
        )
        index_names = {row[0] for row in cursor.fetchall()}
    finally:
        conn.close()
        os.unlink(path)

    assert "ix_idempotency_cache_approval_id" in index_names


def test_agent_contracts_reinstated_at_index_exists():
    """ix_agent_contracts_reinstated_at exists on agent_contracts after _safe_create_index."""
    from db.migrations import _safe_create_index

    conn, path = _make_db()
    try:
        _safe_create_index(
            conn, "ix_agent_contracts_reinstated_at", "agent_contracts", "reinstated_at"
        )
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='agent_contracts'"
        )
        index_names = {row[0] for row in cursor.fetchall()}
    finally:
        conn.close()
        os.unlink(path)

    assert "ix_agent_contracts_reinstated_at" in index_names


def test_audit_events_chain_seq_unique_index_exists():
    """ix_audit_events_chain_seq full unique index exists after _upgrade_chain_seq_to_full_unique."""
    from db.migrations import _upgrade_chain_seq_to_full_unique

    conn, path = _make_db()
    try:
        _upgrade_chain_seq_to_full_unique(conn)
        cursor = conn.execute(
            "SELECT name, sql FROM sqlite_master "
            "WHERE type='index' AND name='ix_audit_events_chain_seq'"
        )
        row = cursor.fetchone()
    finally:
        conn.close()
        os.unlink(path)

    assert row is not None, "ix_audit_events_chain_seq index not found"
    assert "UNIQUE" in row[1].upper(), "index is not UNIQUE"
    assert "WHERE" not in row[1].upper(), (
        "Full unique index must not have a WHERE clause — "
        f"got: {row[1]}"
    )


def test_audit_events_chain_seq_unique_rejects_duplicate():
    """Inserting two audit events with the same (chain_id, seq) raises IntegrityError."""
    from db.migrations import _upgrade_chain_seq_to_full_unique

    def _row(event_id: str, seq: int) -> tuple:
        return (
            event_id, "TEST", None, "chain-a", "prev", "hash",
            '{}', "2026-01-01", seq,
        )

    conn, path = _make_db()
    try:
        _upgrade_chain_seq_to_full_unique(conn)
        insert = (
            "INSERT INTO audit_events "
            "(event_id, event_type, related_attempt_id, chain_id, "
            "prev_event_hash, event_hash, event_payload, created_at, seq) "
            "VALUES (?,?,?,?,?,?,?,?,?)"
        )
        conn.execute(insert, _row("ev1", 1))
        conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(insert, _row("ev2", 1))  # same chain_id + seq
    finally:
        conn.close()
        os.unlink(path)


def test_audit_events_chain_seq_unique_permits_same_seq_different_chains():
    """Two different chains may independently use seq=1 without conflict."""
    from db.migrations import _upgrade_chain_seq_to_full_unique

    def _row(event_id: str, chain_id: str, seq: int) -> tuple:
        return (
            event_id, "TEST", None, chain_id, "prev", "hash",
            '{}', "2026-01-01", seq,
        )

    conn, path = _make_db()
    try:
        _upgrade_chain_seq_to_full_unique(conn)
        insert = (
            "INSERT INTO audit_events "
            "(event_id, event_type, related_attempt_id, chain_id, "
            "prev_event_hash, event_hash, event_payload, created_at, seq) "
            "VALUES (?,?,?,?,?,?,?,?,?)"
        )
        conn.execute(insert, _row("ev1", "chain-a", 1))
        conn.execute(insert, _row("ev2", "chain-b", 1))  # different chain, same seq
        conn.commit()
    finally:
        conn.close()
        os.unlink(path)
    # no exception — test passes if we reach here


def test_seq_null_guard_passes_when_no_null_rows():
    """_check_no_null_seq_rows does not raise when audit_events has no NULL-seq rows."""
    from db.migrations import _check_no_null_seq_rows

    conn, path = _make_db()
    try:
        # Insert a row with a valid seq value
        conn.execute(
            "INSERT INTO audit_events "
            "(event_id, event_type, related_attempt_id, chain_id, "
            "prev_event_hash, event_hash, event_payload, created_at, seq) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            ("ev1", "TEST", None, "chain-a", "prev", "hash", '{}', "2026-01-01", 1),
        )
        conn.commit()
        _check_no_null_seq_rows(conn)  # must not raise
    finally:
        conn.close()
        os.unlink(path)


def test_seq_null_guard_passes_on_empty_table():
    """_check_no_null_seq_rows does not raise when audit_events is empty."""
    from db.migrations import _check_no_null_seq_rows

    conn, path = _make_db()
    try:
        _check_no_null_seq_rows(conn)  # must not raise
    finally:
        conn.close()
        os.unlink(path)


def test_seq_null_guard_fails_when_null_rows_exist():
    """_check_no_null_seq_rows raises RuntimeError when any seq IS NULL rows exist.

    Simulates a pre-DB-05 (legacy) database where audit_events.seq was nullable,
    by creating the table with a nullable seq column via raw DDL rather than
    SQLModel.metadata.create_all (which now produces seq INTEGER NOT NULL).
    """
    from db.migrations import _check_no_null_seq_rows

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    try:
        # Create the table with the old nullable seq schema (legacy pre-DB-05 shape).
        conn.execute(
            "CREATE TABLE audit_events ("
            "  event_id TEXT PRIMARY KEY, "
            "  event_type TEXT NOT NULL, "
            "  related_attempt_id TEXT, "
            "  chain_id TEXT NOT NULL, "
            "  prev_event_hash TEXT NOT NULL, "
            "  event_hash TEXT NOT NULL, "
            "  event_payload TEXT NOT NULL, "
            "  created_at DATETIME NOT NULL, "
            "  seq INTEGER"  # nullable — legacy pre-DB-05 shape
            ")"
        )
        conn.execute(
            "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?,?)",
            ("ev-null", "TEST", None, "chain-a", "prev", "hash", '{}', "2026-01-01", None),
        )
        conn.commit()
        with pytest.raises(RuntimeError, match="seq IS NULL"):
            _check_no_null_seq_rows(conn)
    finally:
        conn.close()
        os.unlink(path)


def test_seq_not_null_trigger_rejects_null_insert():
    """BEFORE INSERT trigger on audit_events must abort inserts with NULL seq."""
    from db.migrations import _add_seq_not_null_trigger

    conn, path = _make_db()
    try:
        _add_seq_not_null_trigger(conn)
        # RAISE(ABORT, ...) in a trigger maps to OperationalError or IntegrityError
        # depending on the Python/SQLite version — accept both.
        with pytest.raises(
            (sqlite3.OperationalError, sqlite3.IntegrityError),
            match="seq must not be null|NOT NULL constraint",
        ):
            conn.execute(
                "INSERT INTO audit_events "
                "(event_id, event_type, related_attempt_id, chain_id, "
                "prev_event_hash, event_hash, event_payload, created_at, seq) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                ("ev-null", "TEST", None, "chain-a", "prev", "hash", '{}', "2026-01-01", None),
            )
    finally:
        conn.close()
        os.unlink(path)


def test_seq_not_null_trigger_permits_nonnull_insert():
    """BEFORE INSERT trigger on audit_events permits inserts with a non-NULL seq."""
    from db.migrations import _add_seq_not_null_trigger

    conn, path = _make_db()
    try:
        _add_seq_not_null_trigger(conn)
        conn.execute(
            "INSERT INTO audit_events "
            "(event_id, event_type, related_attempt_id, chain_id, "
            "prev_event_hash, event_hash, event_payload, created_at, seq) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            ("ev1", "TEST", None, "chain-a", "prev", "hash", '{}', "2026-01-01", 1),
        )
        conn.commit()
    finally:
        conn.close()
        os.unlink(path)
    # no exception — non-NULL seq is accepted


def test_audit_events_seq_not_null_in_schema():
    """seq column in audit_events is NOT NULL in a freshly created database."""
    conn, path = _make_db()
    try:
        cursor = conn.execute("PRAGMA table_info(audit_events)")
        cols = {row[1]: row for row in cursor.fetchall()}
    finally:
        conn.close()
        os.unlink(path)

    assert "seq" in cols, "seq column not found in audit_events"
    # PRAGMA table_info: col[3] is notnull (1 = NOT NULL, 0 = nullable)
    assert cols["seq"][3] == 1, (
        f"seq column must be NOT NULL (notnull=1), got notnull={cols['seq'][3]}"
    )


def test_audit_events_append_only_trigger_rejects_update():
    """BEFORE UPDATE trigger on audit_events must abort any UPDATE attempt."""
    from db.migrations import _add_append_only_triggers

    conn, path = _make_db()
    try:
        _add_append_only_triggers(conn)
        conn.execute(
            "INSERT INTO audit_events "
            "(event_id, event_type, chain_id, prev_event_hash, event_hash, event_payload, created_at, seq) "
            "VALUES ('ev1', 'TEST', 'chain1', 'prev', 'hash', '{}', '2026-01-01', 1)"
        )
        conn.commit()
        with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError), match="append-only"):
            conn.execute("UPDATE audit_events SET event_type='TAMPERED' WHERE event_id='ev1'")
    finally:
        conn.close()
        os.unlink(path)


# ---------------------------------------------------------------------------
# SEQ-01 — Full unique index: upgrade and scope tests
# ---------------------------------------------------------------------------


def test_upgrade_partial_to_full_chain_seq_index():
    """_upgrade_chain_seq_to_full_unique drops the old partial index and creates a full one.

    Simulates the upgrade path: a legacy partial index (WHERE seq IS NOT NULL)
    is replaced by a full UNIQUE(chain_id, seq) covering all rows.
    """
    from db.migrations import _safe_create_unique_index, _upgrade_chain_seq_to_full_unique

    conn, path = _make_db()
    try:
        # Simulate the legacy pre-upgrade state: partial index exists.
        _safe_create_unique_index(
            conn,
            "ix_audit_events_chain_seq",
            "audit_events",
            "chain_id, seq",
            where="seq IS NOT NULL",
        )
        cursor = conn.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='index' AND name='ix_audit_events_chain_seq'"
        )
        old_sql = cursor.fetchone()[0]
        assert "WHERE" in old_sql.upper(), f"Pre-upgrade index should be partial, got: {old_sql}"

        # Run the upgrade migration.
        _upgrade_chain_seq_to_full_unique(conn)

        cursor = conn.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='index' AND name='ix_audit_events_chain_seq'"
        )
        new_sql = cursor.fetchone()[0]
    finally:
        conn.close()
        os.unlink(path)

    assert "UNIQUE" in new_sql.upper(), "Post-upgrade index must be UNIQUE"
    assert "WHERE" not in new_sql.upper(), (
        f"Post-upgrade index must not have a WHERE clause, got: {new_sql}"
    )


def test_upgrade_is_idempotent_on_fresh_db():
    """_upgrade_chain_seq_to_full_unique is safe to run on a database with no prior index.

    On a fresh database (partial index never created), the DROP is a no-op and
    the full index is created. Running it a second time is also a no-op.
    """
    from db.migrations import _upgrade_chain_seq_to_full_unique

    conn, path = _make_db()
    try:
        _upgrade_chain_seq_to_full_unique(conn)  # first run
        _upgrade_chain_seq_to_full_unique(conn)  # second run — must not raise
        cursor = conn.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='index' AND name='ix_audit_events_chain_seq'"
        )
        row = cursor.fetchone()
    finally:
        conn.close()
        os.unlink(path)

    assert row is not None, "Index must exist after idempotent upgrade"
    assert "WHERE" not in row[0].upper(), "Idempotent result must still be a full index"


def test_seq_monotonic_within_chain():
    """Events appended to a chain receive sequential seq values starting at 1.

    Proves _next_seq() produces a gapless ascending sequence per chain_id,
    and that the sequence is independent across chains (each starts at 1).
    """
    import db.models  # noqa: F401 — register tables
    from core.audit import append_audit_event
    from db.models import AuditEvent
    from sqlmodel import Session, SQLModel, create_engine, select

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)

    with Session(engine) as session:
        chain_a = "mono-chain-a"
        chain_b = "mono-chain-b"
        for i in range(5):
            append_audit_event(session, chain_id=chain_a, event_type="T", event_payload={"i": i})
        for i in range(3):
            append_audit_event(session, chain_id=chain_b, event_type="T", event_payload={"i": i})
        session.commit()

        seqs_a = session.exec(
            select(AuditEvent.seq)
            .where(AuditEvent.chain_id == chain_a)
            .order_by(AuditEvent.seq)
        ).all()
        seqs_b = session.exec(
            select(AuditEvent.seq)
            .where(AuditEvent.chain_id == chain_b)
            .order_by(AuditEvent.seq)
        ).all()

    assert list(seqs_a) == [1, 2, 3, 4, 5], f"chain-a seqs: {seqs_a}"
    assert list(seqs_b) == [1, 2, 3], f"chain-b seqs: {seqs_b}"


def test_replay_order_matches_seq_order():
    """export_chain_document returns events ordered by seq; replay order is deterministic.

    Verifies that:
    - Events are emitted in the order they were appended (seq 1, 2, 3 ...)
    - export_chain_document preserves that order
    - The seq field in the exported payload matches insertion order
    """
    import db.models  # noqa: F401 — register tables
    from core.audit import append_audit_event, export_chain_document
    from sqlmodel import Session, SQLModel, create_engine

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)

    event_types = ["ALPHA", "BETA", "GAMMA", "DELTA"]
    chain_id = "replay-order-chain"

    with Session(engine) as session:
        for et in event_types:
            append_audit_event(session, chain_id=chain_id, event_type=et, event_payload={})
        session.commit()
        doc = export_chain_document(session, chain_id)

    events = doc["events"]
    assert len(events) == 4, f"Expected 4 events, got {len(events)}"
    assert [e["seq"] for e in events] == [1, 2, 3, 4], (
        f"Seq values must be 1,2,3,4: {[e['seq'] for e in events]}"
    )
    assert [e["event_type"] for e in events] == event_types, (
        f"Event types out of order: {[e['event_type'] for e in events]}"
    )
    # Strictly ascending: each event's seq is greater than the prior
    for i in range(1, len(events)):
        assert events[i]["seq"] > events[i - 1]["seq"], (
            f"seq not strictly ascending at position {i}: "
            f"{events[i-1]['seq']} → {events[i]['seq']}"
        )


def test_seq_collision_is_rejected_fail_closed():
    """A duplicate (chain_id, seq) raises IntegrityError — never silently corrupts replay.

    This is the fail-closed guarantee: the full UNIQUE(chain_id, seq) index
    ensures any seq collision at the DB layer aborts the transaction and raises
    IntegrityError. Duplicate seq values cannot be written silently; replay
    ordering is never ambiguous.
    """
    from db.migrations import _upgrade_chain_seq_to_full_unique

    conn, path = _make_db()
    try:
        _upgrade_chain_seq_to_full_unique(conn)
        insert = (
            "INSERT INTO audit_events "
            "(event_id, event_type, related_attempt_id, chain_id, "
            "prev_event_hash, event_hash, event_payload, created_at, seq) "
            "VALUES (?,?,?,?,?,?,?,?,?)"
        )
        conn.execute(insert, ("ev1", "T", None, "c1", "p", "h1", '{}', "2026-01-01", 1))
        conn.commit()
        conn.execute(insert, ("ev2", "T", None, "c1", "p", "h2", '{}', "2026-01-01", 2))
        conn.commit()
        # ev3 attempts to reuse seq=1 — must fail
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(insert, ("ev3", "T", None, "c1", "p", "h3", '{}', "2026-01-01", 1))
            conn.commit()
    finally:
        conn.close()
        os.unlink(path)
