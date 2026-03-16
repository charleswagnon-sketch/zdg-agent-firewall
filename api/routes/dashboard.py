"""Serve the operator console UI."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse


router = APIRouter()

_CONSOLE_PATH = Path(__file__).resolve().parents[2] / "dashboard" / "index.html"


@router.get("/dashboard", include_in_schema=False)
def dashboard_index() -> FileResponse:
    return FileResponse(_CONSOLE_PATH)


@router.get("/console", include_in_schema=False)
def console_index() -> FileResponse:
    return FileResponse(_CONSOLE_PATH)
