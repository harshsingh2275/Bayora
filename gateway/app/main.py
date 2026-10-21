"""
gateway/app/main.py
FastAPI application entry point for the Bayora gateway.

Wires together:
  - Lifespan: database init, logger client setup
  - Routers: probe, work, run_lifecycle, admin
  - Health endpoint (public, no auth)

SECURITY notes:
  - CORS is disabled (same-origin through web proxy; architecture §5, SI-11).
  - OpenAPI is served at /api/openapi.json only.
  - /v1/* is never reachable through the web proxy (Caddy returns 404).
  - All structured logs go to stdout as JSON; no secrets or prompt text (SI-10).
"""
import asyncio
import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse

from .config import DEFAULT_CACHE_MODE, LOGGER_URL, MODEL_BLUE_URL, MODEL_RED_URL, MODEL_URL, VERIFIER_URL
from .database import get_setting, init_db, set_setting
from .logger_client import RealLoggerClient, set_logger_client
from .models import AggregatedHealthResponse, HealthResponse
from .rate_limit import check_public_rate
from .routes import admin, audit, probe, run_lifecycle, work

# ── Structured JSON logging ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":%(message)s}',
)
log = logging.getLogger("gateway.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown tasks."""
    # ── Startup ──────────────────────────────────────────────────────────────
    log.info({"event": "gateway_starting"})

    # Initialise SQLite database (idempotent schema migrations)
    app.state.db = await init_db()

    # Seed default cache mode if not already set
    current_mode = await get_setting(app.state.db, "cache_mode")
    if current_mode is None:
        await set_setting(app.state.db, "cache_mode", DEFAULT_CACHE_MODE)

    # SECURITY SI-07: RealLoggerClient connecting to logger service on log-net.
    # Fails closed (503) if logger is unavailable.
    app.state.logger_client = RealLoggerClient()
    set_logger_client(app.state.logger_client)
    log.info({"event": "logger_client_set", "type": type(app.state.logger_client).__name__})

    # SECURITY SI-08: Log gateway_started audit event
    try:
        await app.state.logger_client.append(
            run_id=None,
            actor="gateway",
            event="gateway_started",
            data={},
        )
    except Exception as err:
        log.warning({"event": "gateway_started_audit_notice", "detail": str(err)})

    yield  # Application runs

    # ── Shutdown ─────────────────────────────────────────────────────────────
    log.info({"event": "gateway_stopping"})
    await app.state.db.close()


# ── FastAPI application ──────────────────────────────────────────────────────
# SECURITY SI-11: OpenAPI docs only at /api/openapi.json; Caddy blocks /v1/*
app = FastAPI(
    title="Bayora Gateway",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# ── Register routers ──────────────────────────────────────────────────────────
app.include_router(probe.router)
app.include_router(work.router)
app.include_router(run_lifecycle.router)
app.include_router(admin.router)
app.include_router(audit.router)


# ── Health endpoints ──────────────────────────────────────────────────────────
# Internal healthcheck for Docker (no rate limit to prevent healthcheck flapping)
@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """SECURITY SI-10: No sensitive data in health response."""
    return HealthResponse(status="ok")


# Public health endpoint (health aggregation across gateway, model, logger, verifier)
@app.get(
    "/api/health",
    response_model=AggregatedHealthResponse,
    dependencies=[Depends(check_public_rate)],
)
async def api_health() -> AggregatedHealthResponse:
    """
    Public aggregated health endpoint.
    Checks gateway, model, logger, and verifier status.
    SECURITY SI-10: No sensitive data in health response.
    """
    async def _check_service(url: str) -> str:
        try:
            async with httpx.AsyncClient(timeout=1.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return "ok"
                return f"error_{resp.status_code}"
        except Exception:
            return "unreachable"

    # Gateway self-check: verify DB connection responsiveness
    gw_status = "ok"
    try:
        if hasattr(app.state, "db") and app.state.db:
            async with app.state.db.execute("SELECT 1") as cur:
                await cur.fetchone()
    except Exception:
        gw_status = "error"

    # Concurrently probe external services (§9 fallback: dual model instances)
    model_red_status, model_blue_status, logger_status, verifier_status = await asyncio.gather(
        _check_service(f"{MODEL_RED_URL}/health"),
        _check_service(f"{MODEL_BLUE_URL}/health"),
        _check_service(f"{LOGGER_URL}/health"),
        _check_service(f"{VERIFIER_URL}/health"),
    )

    model_ok = (model_red_status == "ok" and model_blue_status == "ok")

    services = {
        "gateway": gw_status,
        "model": "ok" if model_ok else "degraded",
        "model_red": model_red_status,
        "model_blue": model_blue_status,
        "logger": logger_status,
        "verifier": verifier_status,
    }
    all_ok = all(v == "ok" for v in (gw_status, model_red_status, model_blue_status, logger_status, verifier_status))
    return AggregatedHealthResponse(
        status="ok" if all_ok else "degraded",
        services=services,
    )


# ── Catch-all for unmatched /v1/* paths ──────────────────────────────────────
# Defence-in-depth: Caddy also blocks /v1/* at the edge (SI-11)
@app.api_route(
    "/v1/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    include_in_schema=False,
)
async def v1_catch_all(path: str) -> JSONResponse:
    """SECURITY SI-11: Any /v1/* path not matched by a router returns 404."""
    return JSONResponse(status_code=404, content={"detail": "Not found"})
