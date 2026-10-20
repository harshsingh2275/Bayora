"""
gateway/app/routes/work.py
GET /v1/{role}/work – tenant work polling endpoint.

Architecture §5: Returns {"run": null} if no active run, or {"run": {...}} with
the run's state and role-specific params.

SECURITY: Role check ensures red cannot poll blue's endpoint and vice versa.
"""
import logging

import aiosqlite
from fastapi import APIRouter, Depends

from ..auth import require_blue, require_red
from ..deps import get_db, get_logger
from ..logger_client import LoggerClient
from ..models import WorkResponse
from ..rate_limit import check_tenant_rate
from .run_lifecycle import get_run_with_timeout_check

log = logging.getLogger("gateway.routes.work")

router = APIRouter()


async def _get_active_run(
    db: aiosqlite.Connection,
    logger: LoggerClient | None = None,
) -> dict | None:
    """Return the active (non-concluded, non-aborted) run or None, checking timeouts."""
    async with db.execute(
        "SELECT run_id FROM runs WHERE state NOT IN ('concluded','aborted','failed') "
        "ORDER BY created_at DESC LIMIT 1"
    ) as cur:
        row = await cur.fetchone()
        if not row:
            return None
        run_id = row["run_id"]

    run = await get_run_with_timeout_check(db, run_id, logger)
    if run and run["state"] not in ("concluded", "aborted", "failed"):
        return run
    return None


@router.get("/v1/red/work", response_model=WorkResponse)
async def red_work(
    _auth: None = Depends(require_red),
    db: aiosqlite.Connection = Depends(get_db),
    logger: LoggerClient = Depends(get_logger),
) -> WorkResponse:
    """Red team work polling."""
    await check_tenant_rate("red")
    run = await _get_active_run(db, logger)
    if run is None:
        return WorkResponse(run=None)
    return WorkResponse(run={
        "run_id": run["run_id"],
        "state": run["state"],
        "params": {
            "attack_count": run["attack_count"],
            "seed": run["seed"],
        },
    })


@router.get("/v1/blue/work", response_model=WorkResponse)
async def blue_work(
    _auth: None = Depends(require_blue),
    db: aiosqlite.Connection = Depends(get_db),
    logger: LoggerClient = Depends(get_logger),
) -> WorkResponse:
    """Blue team work polling."""
    await check_tenant_rate("blue")
    run = await _get_active_run(db, logger)
    if run is None:
        return WorkResponse(run=None)
    return WorkResponse(run={
        "run_id": run["run_id"],
        "state": run["state"],
        "params": {
            "bundle": run["bundle_name"],
        },
    })
