"""
gateway/app/routes/admin.py
Operator endpoints: run creation, cache-mode control, abort.

Auth: X-Admin-Token header (require_admin dependency).
Cache-mode is fully implemented (needed for T03 tests + T08 experiment).
Run creation is basic (full workflow in T05/T07).
"""
import logging
import uuid
from datetime import datetime, timezone

import aiosqlite
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from ..auth import require_admin
from ..database import get_setting, set_setting
from ..deps import get_db
from ..models import CacheModeRequest, CacheModeResponse, CreateRunRequest, CreateRunResponse
from ..rate_limit import check_public_rate

log = logging.getLogger("gateway.routes.admin")

router = APIRouter()


# ── Cache-mode control ────────────────────────────────────────────────────────
@router.get(
    "/api/cache-mode",
    response_model=CacheModeResponse,
    dependencies=[Depends(check_public_rate)],
)
async def get_cache_mode(db: aiosqlite.Connection = Depends(get_db)) -> CacheModeResponse:
    """Public: current cache mode."""
    mode = await get_setting(db, "cache_mode") or "isolated"
    return CacheModeResponse(mode=mode)


@router.post("/api/admin/cache-mode", response_model=CacheModeResponse)
async def set_cache_mode(
    body: CacheModeRequest,
    _auth: None = Depends(require_admin),
    db: aiosqlite.Connection = Depends(get_db),
) -> CacheModeResponse:
    """Operator: set cache mode (isolated | shared)."""
    await set_setting(db, "cache_mode", body.mode)
    log.info({"event": "cache_mode_changed", "mode": body.mode})
    return CacheModeResponse(mode=body.mode)


# ── Run creation ───────────────────────────────────────────────────────────────
@router.post("/api/runs", status_code=201)
async def create_run(
    body: CreateRunRequest,
    _auth: None = Depends(require_admin),
    db: aiosqlite.Connection = Depends(get_db),
) -> JSONResponse:
    """Operator: create a new run.  One active run at a time."""
    # Check for existing active run
    async with db.execute(
        "SELECT run_id FROM runs WHERE state NOT IN ('concluded','aborted','failed') LIMIT 1"
    ) as cur:
        if await cur.fetchone():
            return JSONResponse(status_code=409, content={"detail": "A run is already active"})

    run_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "INSERT INTO runs (run_id, name, state, attack_count, seed, bundle_name, created_at, updated_at) "
        "VALUES (?, ?, 'created', ?, ?, ?, ?, ?)",
        (run_id, body.name, body.attack_count, body.seed, body.bundle, now, now),
    )
    await db.commit()
    log.info({"event": "run_created", "run_id": run_id})
    return JSONResponse(status_code=201, content={"run_id": run_id, "state": "created"})


@router.post("/api/runs/{run_id}/abort")
async def abort_run(
    run_id: str,
    _auth: None = Depends(require_admin),
) -> JSONResponse:
    """Operator: abort a run.  Returns 501 until T05."""
    return JSONResponse(status_code=501, content={"detail": "Not implemented (T05)"})


@router.get("/api/admin/runs/{run_id}/items/{idx}")
async def get_run_item(
    run_id: str,
    idx: int,
    _auth: None = Depends(require_admin),
) -> JSONResponse:
    """Operator: full prompt+response for a run item.  Returns 501 until T05."""
    return JSONResponse(status_code=501, content={"detail": "Not implemented (T05)"})


# ── Report ingestion stubs ─────────────────────────────────────────────────────
@router.post("/api/breakit/report")
async def ingest_breakit(_auth: None = Depends(require_admin)) -> JSONResponse:
    return JSONResponse(status_code=501, content={"detail": "Not implemented (T09)"})


@router.post("/api/experiments/timing/report")
async def ingest_timing(_auth: None = Depends(require_admin)) -> JSONResponse:
    return JSONResponse(status_code=501, content={"detail": "Not implemented (T08)"})
