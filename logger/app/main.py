"""
logger/app/main.py
FastAPI application for the Bayora Audit Logger Service.

Architecture §8:
  - Single writer behind an asyncio lock
  - fsync per append
  - Token-protected POST /append, GET /head, GET /entries?after=&limit=
  - Refuses to append if the on-disk chain is inconsistent.
"""
from __future__ import annotations

import hmac
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .chain import AuditChain
from .config import load_logger_token

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":%(message)s}',
)
log = logging.getLogger("logger.main")

chain = AuditChain()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise and verify audit chain at startup."""
    log.info({"event": "logger_starting"})
    # SECURITY: Verify on-disk chain integrity at startup
    chain.verify_on_disk_chain()
    yield
    log.info({"event": "logger_stopping"})


app = FastAPI(
    title="Bayora Audit Logger",
    version="0.1.0",
    lifespan=lifespan,
)


def verify_logger_token(
    authorization: str | None = Header(default=None),
    x_logger_token: str | None = Header(default=None),
) -> None:
    """
    Authenticate caller against logger shared secret token.
    SECURITY SI-05: Constant-time comparison using hmac.compare_digest.
    """
    expected = load_logger_token()
    if not expected:
        # If no token configured, reject all requests
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Logger token not configured")

    provided = None
    if authorization and authorization.startswith("Bearer "):
        provided = authorization[7:].strip()
    elif x_logger_token:
        provided = x_logger_token.strip()

    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid logger credentials")


class AppendRequest(BaseModel):
    """Request model for appending to audit log."""
    # SECURITY SI-06: Strict validation forbids injection of unwhitelisted parameters
    model_config = ConfigDict(extra="forbid")

    run_id: str | None = None
    actor: str = Field(..., max_length=64)
    event: str = Field(..., max_length=128)
    data: dict[str, Any] = Field(default_factory=dict)
    checkpoint: bool = False


@app.get("/health")
async def health() -> dict[str, Any]:
    """Service health endpoint (unauthenticated for Docker healthcheck)."""
    return {
        "status": "ok" if chain.is_consistent else "degraded",
        "service": "logger",
        "chain_consistent": chain.is_consistent,
        "entry_count": chain.entry_count,
    }


@app.post("/append", status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_logger_token)])
async def append_entry(body: AppendRequest) -> dict[str, Any]:
    """Append a validated event to the audit log."""
    try:
        entry = await chain.append(
            run_id=body.run_id,
            actor=body.actor,
            event=body.event,
            data=body.data,
            checkpoint=body.checkpoint,
        )
        return entry
    except RuntimeError as err:
        log.error({"event": "append_rejected", "reason": str(err)})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Append rejected: {err}",
        )


@app.get("/head", dependencies=[Depends(verify_logger_token)])
async def get_head() -> dict[str, Any]:
    """Return latest sequence and hash."""
    if not chain.is_consistent:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Audit chain is inconsistent: {chain.inconsistency_error}",
        )
    return chain.get_head()


@app.get("/entries", dependencies=[Depends(verify_logger_token)])
async def get_entries(
    after: int | None = Query(default=None, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    """Read audit entries with optional after sequence and limit."""
    entries = chain.get_entries(after=after, limit=limit)
    return {"entries": entries}


@app.post("/checkpoint", status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_logger_token)])
async def create_checkpoint() -> dict[str, Any]:
    """Create a signed checkpoint for current head on demand."""
    try:
        cp = await chain.create_checkpoint_on_demand()
        return cp
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))
    except RuntimeError as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
