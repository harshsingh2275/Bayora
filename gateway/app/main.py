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
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from .config import DEFAULT_CACHE_MODE
from .database import get_setting, init_db, set_setting
from .logger_client import FailClosedStub
from .models import HealthResponse
from .routes import admin, probe, run_lifecycle, work

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

    # SECURITY SI-07: Logger client stored in app.state.
    # Default is FailClosedStub — every audit call returns 503 until T04
    # calls set_logger_client() with the real implementation.
    app.state.logger_client = FailClosedStub()
    log.info({"event": "logger_client_set", "type": type(app.state.logger_client).__name__})

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


# ── Health endpoint (public, no auth) ────────────────────────────────────────
@app.get("/health", response_model=HealthResponse)
@app.get("/api/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """SECURITY SI-10: No sensitive data in health response."""
    return HealthResponse(status="ok")


# ── Catch-all for unmatched /v1/* paths ──────────────────────────────────────
# Defence-in-depth: Caddy also blocks /v1/* at the edge (SI-11)
@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def v1_catch_all(path: str) -> JSONResponse:
    """SECURITY SI-11: Any /v1/* path not matched by a router returns 404."""
    return JSONResponse(status_code=404, content={"detail": "Not found"})
