"""Phase 3C unit tests for validation, backup/restore, and deployment artifacts."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from sqlmodel import Session

from adapters.openclaw.config import OpenClawSettings
from api.config import Settings
from cli.db_backup import export_backup, restore_backup
from cli.validate_config import validate_configuration
from core import agents as agent_manager
from core import sessions as session_manager
from core.audit import append_audit_event_with_session_chain
from db.migrations import run_migrations
from db.models import ExecutionResult, IdempotencyCache, PolicyDecision, ToolAttempt
from db.sqlite import create_tables, get_engine, init_engine


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_PATH = PROJECT_ROOT / "policies" / "bundles" / "local_default.yaml"
TOOL_MAP_PATH = PROJECT_ROOT / "adapters" / "openclaw" / "tool_map.yaml"



def _build_settings(tmp_path: Path, admin_token: str = "secret-token", db_name: str = "pilot.db") -> Settings:
    tmp_path.mkdir(parents=True, exist_ok=True)
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    maildir = tmp_path / "maildir"
    maildir.mkdir(exist_ok=True)
    return Settings(
        zdg_db_path=str(tmp_path / db_name),
        zdg_policy_bundle_path=str(BUNDLE_PATH),
        zdg_workspace=str(workspace),
        zdg_filesystem_allowed_roots=[str(workspace)],
        zdg_maildir_path=str(maildir),
        zdg_admin_token=admin_token,
    )



def _seed_sample_db(settings: Settings) -> None:
    init_engine(settings.db_path_resolved)
    create_tables()
    run_migrations()

    with Session(get_engine()) as session:
        agent_manager.register_agent(
            session=session,
            agent_id="agent-backup",
            agent_type="openclaw",
            metadata={"team": "ops"},
            registered_by="ops@example.com",
        )
        session_record = session_manager.create_session(
            session=session,
            agent_id="agent-backup",
            metadata={"purpose": "backup-test"},
            created_by="ops@example.com",
        )
        attempt_id = "atm_backup_1"
        decision_id = "dec_backup_1"
        payload_hash = "sha256:" + "a" * 64

        session.add(
            ToolAttempt(
                attempt_id=attempt_id,
                session_id=session_record["session_id"],
                agent_id="agent-backup",
                runtime="direct",
                tool_family="shell",
                action="execute",
                raw_payload=json.dumps({"command": "echo safe"}),
                normalized_payload=json.dumps({"command": "echo safe"}),
                payload_hash=payload_hash,
                normalization_status="COMPLETE",
                idempotency_key="idem-backup-1",
            )
        )
        session.flush()

        session.add(
            PolicyDecision(
                decision_id=decision_id,
                attempt_id=attempt_id,
                policy_bundle_id="local-default-v1",
                policy_bundle_version="1.0.0",
                ruleset_hash="sha256:" + "b" * 64,
                risk_score=0,
                decision="ALLOW",
                reason_code="ALLOW",
                triggered_rules=json.dumps([]),
                reason="Allowed",
            )
        )
        session.add(
            ExecutionResult(
                result_id="res_backup_1",
                attempt_id=attempt_id,
                executed=False,
                mock=True,
                execution_status="mock_success",
                output_summary="[MOCK] Would execute",
                blocked_reason=None,
                raw_output_json=json.dumps({"stdout": "[mock output]"}),
            )
        )
        session.add(
            IdempotencyCache(
                idempotency_key="idem-backup-1",
                agent_id="agent-backup",
                approval_id=None,
                payload_hash=payload_hash,
                attempt_id=attempt_id,
                response_json=json.dumps({"decision": "ALLOW"}),
                expires_at=agent_manager.utc_now(),
            )
        )
        append_audit_event_with_session_chain(
            session=session,
            global_chain_id=settings.zdg_chain_id,
            session_id=session_record["session_id"],
            event_type="ACTION_ALLOWED",
            event_payload={
                "attempt_id": attempt_id,
                "decision_id": decision_id,
                "session_id": session_record["session_id"],
                "agent_id": "agent-backup",
                "tool_family": "shell",
                "action": "execute",
                "reason_code": "ALLOW",
                "risk_score": 0,
                "policy_bundle_version": "1.0.0",
                "ruleset_hash": "sha256:" + "b" * 64,
            },
            related_attempt_id=attempt_id,
        )
        session.commit()



def test_validate_configuration_passes_for_bounded_pilot(tmp_path):
    settings = _build_settings(tmp_path)
    report = validate_configuration(
        settings=settings,
        openclaw_settings=OpenClawSettings(openclaw_tool_map_path=str(TOOL_MAP_PATH)),
    )

    assert report.ok is True
    assert report.errors == []
    assert report.details["policy_bundle"]["bundle_id"] == "local-default-v1"



def test_validate_configuration_fails_for_missing_filesystem_root(tmp_path):
    settings = _build_settings(tmp_path)
    missing_root = tmp_path / "missing-root"
    settings = Settings(
        zdg_db_path=settings.zdg_db_path,
        zdg_policy_bundle_path=settings.zdg_policy_bundle_path,
        zdg_workspace=settings.zdg_workspace,
        zdg_filesystem_allowed_roots=[str(missing_root)],
        zdg_maildir_path=settings.zdg_maildir_path,
        zdg_admin_token=settings.zdg_admin_token,
    )

    report = validate_configuration(
        settings=settings,
        openclaw_settings=OpenClawSettings(openclaw_tool_map_path=str(TOOL_MAP_PATH)),
    )

    assert report.ok is False
    assert any("Filesystem allowed root does not exist" in message for message in report.errors)



def test_validate_configuration_warns_for_empty_admin_token_and_open_fail_mode(tmp_path):
    settings = _build_settings(tmp_path, admin_token="")
    report = validate_configuration(
        settings=settings,
        openclaw_settings=OpenClawSettings(
            openclaw_tool_map_path=str(TOOL_MAP_PATH),
            openclaw_fail_mode="open",
        ),
    )

    assert report.ok is True
    assert any("ZDG_ADMIN_TOKEN is empty" in message for message in report.warnings)
    assert any("OPENCLAW_FAIL_MODE is not 'closed'" in message for message in report.warnings)



def test_export_backup_excludes_transient_by_default(tmp_path):
    settings = _build_settings(tmp_path)
    _seed_sample_db(settings)
    output_path = tmp_path / "backup.json"

    result = export_backup(settings=settings, output_path=output_path, admin_token="secret-token")
    document = json.loads(output_path.read_text(encoding="utf-8"))

    assert Path(result.output_path).exists()
    assert "idempotency_cache" not in document["tables"]
    assert document["tables"]["tool_attempts"]
    assert all(report["ok"] for report in result.audit_verification)



def test_export_backup_includes_transient_when_requested(tmp_path):
    settings = _build_settings(tmp_path)
    _seed_sample_db(settings)
    output_path = tmp_path / "backup-with-transient.json"

    export_backup(
        settings=settings,
        output_path=output_path,
        admin_token="secret-token",
        include_transient=True,
    )
    document = json.loads(output_path.read_text(encoding="utf-8"))

    assert "idempotency_cache" in document["tables"]
    assert len(document["tables"]["idempotency_cache"]) == 1



def test_restore_backup_round_trips_audit_integrity(tmp_path):
    source_settings = _build_settings(tmp_path, db_name="source.db")
    _seed_sample_db(source_settings)
    backup_path = tmp_path / "roundtrip.json"
    export_backup(settings=source_settings, output_path=backup_path, admin_token="secret-token")

    target_settings = _build_settings(tmp_path / "target", db_name="restored.db")
    result = restore_backup(
        settings=target_settings,
        input_path=backup_path,
        admin_token="secret-token",
        target_db_path=tmp_path / "restored.db",
    )

    assert Path(result.target_db_path).exists()
    assert result.table_counts["tool_attempts"] == 1
    assert all(report["ok"] for report in result.audit_verification)

    with sqlite3.connect(result.target_db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM session_records").fetchone()[0] == 1



def test_restore_backup_requires_fresh_destination(tmp_path):
    source_settings = _build_settings(tmp_path, db_name="source-existing.db")
    _seed_sample_db(source_settings)
    backup_path = tmp_path / "existing.json"
    export_backup(settings=source_settings, output_path=backup_path, admin_token="secret-token")

    target_settings = _build_settings(tmp_path / "existing-target", db_name="existing.db")
    _seed_sample_db(target_settings)

    with pytest.raises(ValueError):
        restore_backup(
            settings=target_settings,
            input_path=backup_path,
            admin_token="secret-token",
            target_db_path=target_settings.db_path_resolved,
        )



def test_deployment_artifacts_include_pilot_hardening_markers():
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
    compose = (PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    service = (PROJECT_ROOT / "deploy" / "zdg-firewall.service").read_text(encoding="utf-8")

    assert "HEALTHCHECK" in dockerfile
    assert "USER zdg" in dockerfile
    assert "env_file:" in compose
    assert "caddy" in compose
    assert "NoNewPrivileges=true" in service
    assert "ReadWritePaths=" in service



