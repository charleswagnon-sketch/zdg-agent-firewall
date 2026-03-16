"""Config validation CLI for pilot and production readiness checks."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from adapters.openclaw.config import OpenClawSettings, SUPPORTED_OPENCLAW_VERSION
from adapters.openclaw.translator import OpenClawTranslator
from api.config import Settings, get_settings
from core.policy import load_bundle
from db.migrations import run_migrations
from db.sqlite import create_tables, get_engine, init_engine
from wrappers import get_wrapper, registered_families


EXPECTED_WRAPPER_FAMILIES = {"shell", "http", "filesystem", "messaging"}


@dataclass
class ValidationReport:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)



def validate_configuration(
    settings: Settings | None = None,
    openclaw_settings: OpenClawSettings | None = None,
) -> ValidationReport:
    settings = settings or get_settings()
    openclaw_settings = openclaw_settings or OpenClawSettings()

    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {
        "db_path": settings.db_path_resolved,
        "policy_bundle_path": settings.policy_bundle_path_resolved,
        "workspace": settings.workspace_resolved,
        "filesystem_allowed_roots": settings.filesystem_allowed_roots_resolved,
        "maildir_path": settings.maildir_path_resolved,
        "real_exec": {
            "global": settings.zdg_real_exec,
            "shell": settings.zdg_real_exec_shell,
            "http": settings.zdg_real_exec_http,
            "filesystem": settings.zdg_real_exec_filesystem,
            "messaging": settings.zdg_real_exec_messaging,
        },
        "adapter": {
            "tool_map_path": openclaw_settings.tool_map_path_resolved,
            "fail_mode": openclaw_settings.openclaw_fail_mode,
            "version": openclaw_settings.openclaw_version,
        },
    }

    try:
        bundle = load_bundle(settings.policy_bundle_path_resolved)
        details["policy_bundle"] = {
            "bundle_id": bundle.bundle_id,
            "version": bundle.version,
            "ruleset_hash": bundle.ruleset_hash,
        }
    except Exception as exc:  # pragma: no cover - tested by behavior
        errors.append(f"Policy bundle validation failed: {exc}")

    for root in settings.filesystem_allowed_roots_resolved:
        path = Path(root)
        if not path.exists():
            errors.append(f"Filesystem allowed root does not exist: {path}")
        elif not path.is_dir():
            errors.append(f"Filesystem allowed root is not a directory: {path}")

    maildir_path = Path(settings.maildir_path_resolved)
    if maildir_path.exists() and not maildir_path.is_dir():
        errors.append(f"Configured maildir path is not a directory: {maildir_path}")
    elif not maildir_path.exists():
        if settings.zdg_real_exec or settings.zdg_real_exec_messaging:
            warnings.append(f"Maildir path does not exist yet and will be created at runtime: {maildir_path}")
        else:
            warnings.append(f"Maildir path does not exist yet: {maildir_path}")

    db_parent = Path(settings.db_path_resolved).parent
    if not db_parent.exists():
        errors.append(f"Database parent directory does not exist: {db_parent}")
    else:
        try:
            init_engine(settings.db_path_resolved)
            create_tables()
            run_migrations()
            get_engine().connect().close()
        except Exception as exc:  # pragma: no cover - tested by behavior
            errors.append(f"Database validation failed: {exc}")

    try:
        translator = OpenClawTranslator(
            tool_map_path=openclaw_settings.tool_map_path_resolved,
            agent_id_field=openclaw_settings.openclaw_agent_id_field,
        )
        details["adapter"]["mapped_tools"] = sorted(mapping.name for mapping in translator.tool_map)
    except Exception as exc:  # pragma: no cover - tested by behavior
        errors.append(f"OpenClaw tool map validation failed: {exc}")

    families = set(registered_families())
    details["registered_wrappers"] = sorted(families)
    missing = EXPECTED_WRAPPER_FAMILIES - families
    if missing:
        errors.append(f"Missing registered wrappers: {sorted(missing)}")
    else:
        for family in sorted(families):
            try:
                get_wrapper(family)
            except Exception as exc:  # pragma: no cover - tested by behavior
                errors.append(f"Wrapper '{family}' could not be instantiated: {exc}")

    if not settings.zdg_admin_token:
        warnings.append("ZDG_ADMIN_TOKEN is empty; admin endpoints fail closed and backup export is disabled.")

    if openclaw_settings.openclaw_fail_mode != "closed":
        warnings.append("OPENCLAW_FAIL_MODE is not 'closed'; this is unsupported for production.")

    if openclaw_settings.openclaw_version != SUPPORTED_OPENCLAW_VERSION:
        warnings.append(
            f"OPENCLAW_VERSION='{openclaw_settings.openclaw_version}' differs from supported '{SUPPORTED_OPENCLAW_VERSION}'."
        )

    return ValidationReport(ok=not errors, errors=errors, warnings=warnings, details=details)



def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate ZDG pilot configuration.")
    parser.add_argument("--json", action="store_true", help="Emit the report as JSON.")
    return parser



def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    report = validate_configuration()
    if args.json:
        print(json.dumps(asdict(report), indent=2, sort_keys=True))
    else:
        print(f"ZDG configuration validation: {'PASS' if report.ok else 'FAIL'}")
        for message in report.errors:
            print(f"ERROR: {message}")
        for message in report.warnings:
            print(f"WARN: {message}")
        if report.ok and not report.warnings:
            print("Configuration looks ready for bounded pilot use.")

    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

