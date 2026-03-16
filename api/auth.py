"""api/auth.py - Shared admin authorization helpers for control-plane routes."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass

from fastapi import Header, HTTPException, Request

logger = logging.getLogger(__name__)


@dataclass
class AdminContext:
    request_id: str | None = None


def require_admin(
    request: Request,
    x_zdg_admin_token: str | None = Header(default=None, alias="X-ZDG-Admin-Token"),
) -> AdminContext:
    state = request.app.state.zdg
    expected_token = state.settings.zdg_admin_token.strip()

    if not expected_token:
        raise HTTPException(
            status_code=503,
            detail={
                "reason": "Admin token is not configured for control-plane access.",
            },
        )

    if not x_zdg_admin_token or not secrets.compare_digest(x_zdg_admin_token, expected_token):
        logger.warning(
            "admin_auth_failed method=%s path=%s token_present=%s",
            request.method,
            request.url.path,
            bool(x_zdg_admin_token),
        )
        raise HTTPException(
            status_code=401,
            detail={
                "reason": "Valid X-ZDG-Admin-Token header required.",
            },
        )

    return AdminContext(request_id=getattr(request.state, "request_id", None))