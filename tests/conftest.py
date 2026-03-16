"""
tests/conftest.py — Shared pytest fixtures for all test suites.
"""
from __future__ import annotations
import os
import pytest
from pathlib import Path

# Point to the test policy bundle
BUNDLE_PATH = str(Path(__file__).parent.parent / "policies" / "bundles" / "local_default.yaml")

@pytest.fixture
def bundle():
    from core.policy import load_bundle
    return load_bundle(BUNDLE_PATH)

@pytest.fixture
def settings():
    from api.config import Settings
    return Settings(
        zdg_db_path=":memory:",
        zdg_policy_bundle_path=BUNDLE_PATH,
        zdg_workspace=os.path.expanduser("~/workspace"),
    )
