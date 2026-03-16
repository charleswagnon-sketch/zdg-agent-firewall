"""Shared integration-test fixtures for the full FastAPI app."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.config import Settings


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_PATH = PROJECT_ROOT / "policies" / "bundles" / "local_default.yaml"
DEFAULT_ADMIN_TOKEN = "integration-admin-token"


@pytest.fixture
def admin_headers():
    return {"X-ZDG-Admin-Token": DEFAULT_ADMIN_TOKEN}


@pytest.fixture
def make_client(tmp_path, monkeypatch):
    @contextmanager
    def factory(**settings_overrides):
        workspace = tmp_path / "workspace"
        workspace.mkdir(exist_ok=True)

        settings_kwargs = {
            "zdg_db_path": str(tmp_path / "test.db"),
            "zdg_policy_bundle_path": str(BUNDLE_PATH),
            "zdg_workspace": str(workspace),
            "zdg_admin_token": DEFAULT_ADMIN_TOKEN,
        }
        settings_kwargs.update(settings_overrides)
        settings = Settings(**settings_kwargs)

        import api.app as app_module

        monkeypatch.setattr(app_module, "get_settings", lambda: settings)
        with TestClient(create_app()) as client:
            yield client

    return factory