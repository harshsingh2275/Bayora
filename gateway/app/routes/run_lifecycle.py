"""
gateway/app/routes/run_lifecycle.py
Commit, defense, attack, done, and report endpoints.

T03: commit, defense, attack, done, report endpoints return 501 (not implemented)
     as specified in the prompt.  They will be fully implemented in T05.

SECURITY: Auth dependencies enforce role isolation on every endpoint.
"""
import logging

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from ..auth import require_blue, require_red
from ..models import (
    AttackRequest,
    CommitRequest,
    DefenseRequest,
    DoneRequest,
)

log = logging.getLogger("gateway.routes.run_lifecycle")

router = APIRouter()

_NOT_IMPLEMENTED = JSONResponse(
    status_code=501,
    content={"detail": "Not implemented yet (T05)"},
)


# ── Commit (red) ──────────────────────────────────────────────────────────────
@router.post("/v1/red/runs/{run_id}/commit")
async def red_commit(
    run_id: str,
    body: CommitRequest,
    _auth: None = Depends(require_red),
) -> JSONResponse:
    """Red team commit endpoint.  Returns 501 until T05."""
    return _NOT_IMPLEMENTED


# ── Defense (blue) ────────────────────────────────────────────────────────────
@router.put("/v1/blue/runs/{run_id}/defense")
async def blue_defense(
    run_id: str,
    body: DefenseRequest,
    _auth: None = Depends(require_blue),
) -> JSONResponse:
    """Blue team defense bundle upload.  Returns 501 until T05."""
    return _NOT_IMPLEMENTED


# ── Attack (red) ──────────────────────────────────────────────────────────────
@router.post("/v1/red/runs/{run_id}/attack")
async def red_attack(
    run_id: str,
    body: AttackRequest,
    _auth: None = Depends(require_red),
) -> JSONResponse:
    """Red team attack endpoint.  Returns 501 until T05."""
    return _NOT_IMPLEMENTED


# ── Done (red) ────────────────────────────────────────────────────────────────
@router.post("/v1/red/runs/{run_id}/done")
async def red_done(
    run_id: str,
    body: DoneRequest,
    _auth: None = Depends(require_red),
) -> JSONResponse:
    """Red team done endpoint.  Returns 501 until T05."""
    return _NOT_IMPLEMENTED


# ── Reports ───────────────────────────────────────────────────────────────────
@router.get("/v1/red/runs/{run_id}/report")
async def red_report(
    run_id: str,
    _auth: None = Depends(require_red),
) -> JSONResponse:
    """Red team report.  Returns 501 until T05."""
    return _NOT_IMPLEMENTED


@router.get("/v1/blue/runs/{run_id}/report")
async def blue_report(
    run_id: str,
    _auth: None = Depends(require_blue),
) -> JSONResponse:
    """Blue team report.  Returns 501 until T05."""
    return _NOT_IMPLEMENTED
