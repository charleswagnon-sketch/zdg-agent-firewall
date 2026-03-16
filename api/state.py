"""
api/state.py - Shared application state attached to app.state.zdg.

Holds the active policy bundle, settings, and logger so routes can
access them without re-loading from disk on every request.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging

from api.config import Settings
from core.policy import PolicyBundle


@dataclass
class AppState:
    settings: Settings
    bundle: PolicyBundle
    logger: logging.Logger