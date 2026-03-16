"""SQLite backup and restore tooling for bounded pilot deployments."""

from __future__ import annotations

import argparse
import json
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from api.config import Settings, get_settings
from core.audit import compute_event_hash, compute_document_hash
from db.migrations import run_migrations
from db.sqlite import create_tables, init_engine


DURABLE_TABLES = [
    "tool_attempts",
    "policy_decisions",
    "execution_results",
    "approvals",
    "killswitch_events",
    "audit_events",
    "agent_records",
    "session_records",
]
TRANSIENT_TABLES = ["idempotency_cache"]


@dataclass
class BackupResult:
    output_path: str
    table_counts: dict[str, int]
    audit_verification: list[dict[str, Any]]


@dataclass
class RestoreResult:
    target_db_path: str
    table_counts: dict[str, int]
    audit_verification: list[dict[str, Any]]



def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()



def export_backup(
    settings: Settings,
    output_path: str | Path,
    admin_token: str,
    include_transient: bool = False,
) -> BackupResult:
    _require_admin_token(settings, admin_token)
    db_path = Path(settings.db_path_resolved)
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    table_names = _table_names(include_transient)
    with _sqlite_snapshot(db_path) as snapshot_path:
        table_data = _export_tables(snapshot_path, table_names)
        audit_verification = _verify_audit_rows(table_data.get("audit_events", []))

    document = {
        "metadata": {
            "exported_at": utc_now_iso(),
            "source_db_path": str(db_path),
            "include_transient": include_transient,
            "table_order": table_names,
        },
        "tables": table_data,
        "audit_verification": audit_verification,
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")

    return BackupResult(
        output_path=str(output.resolve()),
        table_counts={table: len(rows) for table, rows in table_data.items()},
        audit_verification=audit_verification,
    )



def restore_backup(
    settings: Settings,
    input_path: str | Path,
    admin_token: str,
    target_db_path: str | Path | None = None,
    include_transient: bool = False,
) -> RestoreResult:
    _require_admin_token(settings, admin_token)
    backup_document = json.loads(Path(input_path).read_text(encoding="utf-8"))
    table_data: dict[str, list[dict[str, Any]]] = backup_document.get("tables") or {}

    destination = Path(target_db_path or settings.db_path_resolved).expanduser().resolve()
    init_engine(str(destination))
    create_tables()
    run_migrations()

    with sqlite3.connect(destination) as conn:
        _ensure_fresh_destination(conn, include_transient)
        for table in _table_names(include_transient):
            rows = table_data.get(table, [])
            if not rows:
                continue
            _insert_rows(conn, table, rows)
        conn.commit()

    audit_verification = _verify_audit_rows(table_data.get("audit_events", []))
    failed = [report for report in audit_verification if not report["ok"]]
    if failed:
        raise ValueError(f"Audit verification failed after import: {failed[0]['reason']}")

    return RestoreResult(
        target_db_path=str(destination),
        table_counts={table: len(table_data.get(table, [])) for table in _table_names(include_transient)},
        audit_verification=audit_verification,
    )



def _require_admin_token(settings: Settings, provided_token: str) -> None:
    if not settings.zdg_admin_token:
        raise PermissionError("Backup and restore are disabled until ZDG_ADMIN_TOKEN is configured.")
    if provided_token != settings.zdg_admin_token:
        raise PermissionError("Invalid admin token.")



def _table_names(include_transient: bool) -> list[str]:
    return DURABLE_TABLES + (TRANSIENT_TABLES if include_transient else [])



def _export_tables(snapshot_path: Path, table_names: list[str]) -> dict[str, list[dict[str, Any]]]:
    exported: dict[str, list[dict[str, Any]]] = {}
    with sqlite3.connect(snapshot_path) as conn:
        conn.row_factory = sqlite3.Row
        for table in table_names:
            exported[table] = [dict(row) for row in conn.execute(f"SELECT * FROM {table}").fetchall()]
    return exported



def _ensure_fresh_destination(conn: sqlite3.Connection, include_transient: bool) -> None:
    for table in _table_names(include_transient):
        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        if count:
            raise ValueError(f"Target database is not fresh; table '{table}' already contains rows.")



def _insert_rows(conn: sqlite3.Connection, table: str, rows: list[dict[str, Any]]) -> None:
    columns = list(rows[0].keys())
    placeholders = ", ".join(["?"] * len(columns))
    column_sql = ", ".join(columns)
    values = [tuple(row.get(column) for column in columns) for row in rows]
    conn.executemany(
        f"INSERT INTO {table} ({column_sql}) VALUES ({placeholders})",
        values,
    )



def _verify_audit_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chains: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        chains.setdefault(row["chain_id"], []).append(row)

    reports: list[dict[str, Any]] = []
    for chain_id, chain_rows in sorted(chains.items()):
        chain_rows.sort(key=lambda row: row["seq"])
        prev_hash = "GENESIS"
        broken_position: int | None = None
        reason = "CHAIN OK"

        events = []
        for index, row in enumerate(chain_rows):
            created_at = _normalize_created_at(row.get("created_at"))
            event_payload = _load_json(row.get("event_payload"))
            hashable_fields = {
                "chain_id": chain_id,
                "created_at": created_at,
                "event_id": row.get("event_id"),
                "event_payload": event_payload,
                "event_type": row.get("event_type"),
                "related_attempt_id": row.get("related_attempt_id") or "",
                "seq": row.get("seq"),
            }
            expected_hash = compute_event_hash(hashable_fields, prev_hash)
            if row.get("prev_event_hash") != prev_hash:
                broken_position = index
                reason = "Previous-event hash mismatch"
                break
            if row.get("event_hash") != expected_hash:
                broken_position = index
                reason = "Event hash mismatch"
                break
            prev_hash = row.get("event_hash") or "GENESIS"
            events.append(
                {
                    "event_id": row.get("event_id"),
                    "event_type": row.get("event_type"),
                    "related_attempt_id": row.get("related_attempt_id"),
                    "chain_id": chain_id,
                    "prev_event_hash": row.get("prev_event_hash"),
                    "event_hash": row.get("event_hash"),
                    "created_at": created_at,
                    "seq": row.get("seq"),
                    "event_payload": event_payload,
                }
            )

        document = {
            "chain_id": chain_id,
            "export_timestamp": utc_now_iso(),
            "genesis_hash": "GENESIS",
            "event_count": len(chain_rows),
            "first_event_at": events[0]["created_at"] if events else None,
            "last_event_at": events[-1]["created_at"] if events else None,
            "final_hash": prev_hash if events else "GENESIS",
            "events": events,
        }
        document_hash = compute_document_hash(document)
        reports.append(
            {
                "chain_id": chain_id,
                "ok": broken_position is None,
                "verified_event_count": len(events),
                "first_broken_position": broken_position,
                "reason": reason,
                "document_hash": document_hash,
            }
        )
    return reports



def _load_json(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value



def _normalize_created_at(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value.isoformat()

    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed.isoformat()



def _sqlite_snapshot(db_path: Path):
    class _SnapshotContext:
        def __enter__(self_nonlocal) -> Path:
            temp = tempfile.NamedTemporaryFile(prefix="zdg-backup-", suffix=".db", delete=False)
            temp.close()
            self_nonlocal.path = Path(temp.name)
            with sqlite3.connect(db_path) as source, sqlite3.connect(self_nonlocal.path) as dest:
                source.backup(dest)
            return self_nonlocal.path

        def __exit__(self_nonlocal, exc_type, exc, tb) -> None:
            if hasattr(self_nonlocal, "path") and self_nonlocal.path.exists():
                self_nonlocal.path.unlink()

    return _SnapshotContext()



def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export or restore ZDG pilot databases.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    export_parser = subparsers.add_parser("export", help="Export a JSON backup.")
    export_parser.add_argument("--output", required=True)
    export_parser.add_argument("--admin-token", required=True)
    export_parser.add_argument("--include-transient", action="store_true")

    restore_parser = subparsers.add_parser("restore", help="Restore a JSON backup into a fresh DB.")
    restore_parser.add_argument("--input", required=True)
    restore_parser.add_argument("--admin-token", required=True)
    restore_parser.add_argument("--target-db")
    restore_parser.add_argument("--include-transient", action="store_true")

    return parser



def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    settings = get_settings()

    if args.command == "export":
        result = export_backup(
            settings=settings,
            output_path=args.output,
            admin_token=args.admin_token,
            include_transient=args.include_transient,
        )
        print(json.dumps({
            "output_path": result.output_path,
            "table_counts": result.table_counts,
            "audit_verification": result.audit_verification,
        }, indent=2, sort_keys=True))
        return 0

    result = restore_backup(
        settings=settings,
        input_path=args.input,
        admin_token=args.admin_token,
        target_db_path=args.target_db,
        include_transient=args.include_transient,
    )
    print(json.dumps({
        "target_db_path": result.target_db_path,
        "table_counts": result.table_counts,
        "audit_verification": result.audit_verification,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

