"""
api/app.py - FastAPI application factory and startup lifecycle.

Creates and configures the FastAPI app.
All route modules are registered here.
DB initialization and policy bundle loading happen in the lifespan context.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from time import perf_counter
from typing import AsyncGenerator
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from api.config import Settings, get_settings
from api.state import AppState
from core.logging import configure_logging, log_request

APP_VERSION = "0.1.0"


async def _contract_expiry_sweep_loop(global_chain_id: str, interval_seconds: int) -> None:
    """Background loop: sweep ACTIVE→EXPIRED contracts at the configured interval.

    Sleeps first so the initial sweep does not race app startup. Exceptions are
    swallowed per iteration so a transient DB error does not kill the loop.
    Disabled (not started) when zdg_contract_expiry_sweep_interval_seconds == 0.
    """
    from core.contracts import sweep_expired_contracts

    while True:
        await asyncio.sleep(interval_seconds)
        try:
            sweep_expired_contracts(global_chain_id=global_chain_id)
        except Exception:
            pass  # log-silent: don't crash the sweep loop on transient errors


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup and shutdown lifecycle."""

    settings = get_settings()
    _validate_startup_settings(settings)

    from db.sqlite import create_tables, init_engine

    init_engine(settings.db_path_resolved)
    create_tables()

    from db.migrations import run_migrations

    run_migrations()

    from core.policy import load_bundle

    bundle = load_bundle(settings.policy_bundle_path_resolved)
    logger = configure_logging(settings.zdg_log_format)
    app.state.zdg = AppState(settings=settings, bundle=bundle, logger=logger)

    print("ZDG Agent Firewall started")
    print(f"  Version: {APP_VERSION}")
    print(f"  Policy bundle: {bundle.bundle_id} v{bundle.version}")
    print(f"  DB: {settings.db_path_resolved}")
    print(f"  Ruleset hash: {bundle.ruleset_hash[:32]}...")

    _sweep_task: asyncio.Task | None = None
    if settings.zdg_contract_expiry_sweep_interval_seconds > 0:
        _sweep_task = asyncio.create_task(
            _contract_expiry_sweep_loop(
                global_chain_id=settings.zdg_chain_id,
                interval_seconds=settings.zdg_contract_expiry_sweep_interval_seconds,
            )
        )

    yield

    if _sweep_task is not None:
        _sweep_task.cancel()
        try:
            await _sweep_task
        except asyncio.CancelledError:
            pass



def create_app() -> FastAPI:
    """Create and return the configured FastAPI application."""

    app = FastAPI(
        title="ZDG Agent Firewall",
        description=(
            "Runtime enforcement control plane for autonomous AI agents. "
            "Evaluates actions against policy before execution."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def request_logging_middleware(request: Request, call_next):
        request_id = request.headers.get("X-Request-Id") or f"req_{uuid4().hex[:12]}"
        request.state.request_id = request_id
        start = perf_counter()
        try:
            response = await call_next(request)
        except Exception as exc:
            duration_ms = round((perf_counter() - start) * 1000, 2)
            if hasattr(request.app.state, "zdg"):
                log_request(
                    request.app.state.zdg.logger,
                    request_id=request_id,
                    method=request.method,
                    path=request.url.path,
                    status_code=500,
                    duration_ms=duration_ms,
                    exception_type=type(exc).__name__,
                    exception_message=str(exc),
                )
            raise

        response.headers["X-Request-Id"] = request_id
        duration_ms = round((perf_counter() - start) * 1000, 2)
        if hasattr(request.app.state, "zdg"):
            log_request(
                request.app.state.zdg.logger,
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=duration_ms,
            )
        return response

    from api.routes.agents import router as agents_router
    from api.routes.approvals import router as approvals_router
    from api.routes.audit import router as audit_router
    from api.routes.dashboard import router as dashboard_router
    from api.routes.evaluate import router as evaluate_router
    from api.routes.events import router as events_router
    from api.routes.investigate import router as investigate_router
    from api.routes.killswitch import router as killswitch_router
    from api.routes.license import router as license_router
    from api.routes.metrics import router as metrics_router
    from api.routes.policy import router as policy_router
    from api.routes.sessions import router as sessions_router
    from api.routes.billing import router as billing_router
    from api.routes.support import router as support_router

    app.include_router(evaluate_router, prefix="/v1", tags=["evaluate"])
    app.include_router(investigate_router, prefix="/v1", tags=["investigate"])
    app.include_router(approvals_router, prefix="/v1", tags=["approvals"])
    app.include_router(events_router, prefix="/v1", tags=["events"])
    app.include_router(killswitch_router, prefix="/v1", tags=["killswitch"])
    app.include_router(metrics_router, prefix="/v1", tags=["metrics"])
    app.include_router(policy_router, prefix="/v1", tags=["policy"])
    app.include_router(agents_router, prefix="/v1", tags=["agents"])
    app.include_router(sessions_router, prefix="/v1", tags=["sessions"])
    app.include_router(audit_router, prefix="/v1", tags=["audit"])
    app.include_router(license_router, prefix="/v1", tags=["license"])
    app.include_router(billing_router, prefix="/v1", tags=["billing"])
    app.include_router(support_router, prefix="/v1", tags=["support"])
    app.include_router(dashboard_router, tags=["dashboard"])
    app.mount(
        "/dashboard-assets",
        StaticFiles(directory=Path(__file__).resolve().parents[1] / "dashboard"),
        name="dashboard-assets",
    )

    @app.get("/health")
    def health():
        return {"status": "ok", "version": APP_VERSION}

    return app



def _validate_startup_settings(settings: Settings) -> None:
    if not settings.zdg_admin_token.strip():
        raise RuntimeError(
            "ZDG_ADMIN_TOKEN is not set. "
            "Admin control-plane access (audit, replay, runs) requires a non-empty token. "
            "Set ZDG_ADMIN_TOKEN in your environment or .env file."
        )
    if not settings.zdg_chain_id.strip():
        raise RuntimeError(
            "ZDG_CHAIN_ID is not set. "
            "A non-empty audit chain ID is required for tamper-evident event ordering."
        )
    for root in settings.filesystem_allowed_roots_resolved:
        path = Path(root)
        if not path.exists():
            raise RuntimeError(f"Configured filesystem allowed root does not exist: {path}")
        if not path.is_dir():
            raise RuntimeError(f"Configured filesystem allowed root is not a directory: {path}")


app = create_app()