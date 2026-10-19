"""
gateway/app/routes/probe.py
/v1/red/probe and /v1/blue/probe endpoints.

Architecture §5: Raw model access for tenants, no defense applied.
  - max_tokens capped at 128 (PROBE_MAX_TOKENS_CAP)
  - Returns only {"text": ...}
  - Logged as probe_processed with digests only (SI-08)
  - Fails closed (503) if logger is unavailable (SI-07)

SECURITY SI-06: ProbeRequest has extra="forbid" so id_slot, cache_prompt
                and unknown fields yield 422 before reaching this handler.
"""
import hashlib
import logging

import aiosqlite
from fastapi import APIRouter, Depends

from ..auth import require_blue, require_red
from ..database import get_setting
from ..deps import get_db, get_logger
from ..logger_client import LoggerClient
from ..model_client import call_model
from ..models import ProbeRequest, ProbeResponse
from ..rate_limit import check_tenant_rate

log = logging.getLogger("gateway.routes.probe")

router = APIRouter()


async def _handle_probe(
    *,
    role: str,
    body: ProbeRequest,
    logger: LoggerClient,
    db: aiosqlite.Connection,
) -> ProbeResponse:
    """Shared probe logic for red and blue.

    SECURITY SI-07: logger.append MUST succeed before we return the result.
    With the FailClosedStub the append raises 503 — the model call still
    happened, but the 503 propagates to the client so the interaction is
    not silently unaudited.

    T03 acceptance: with the FailClosedStub logger, all probes return 503.
    """
    # ── Rate limit ────────────────────────────────────────────────────────
    await check_tenant_rate(role)

    # ── Fetch current cache mode from DB ──────────────────────────────────
    cache_mode = await get_setting(db, "cache_mode") or "isolated"

    # ── SECURITY SI-08: compute prompt digest before calling model ────────
    prompt_digest = hashlib.sha256(body.prompt.encode()).hexdigest()

    # ── Call model (gateway builds request; never forwards client params) ─
    # SECURITY SI-06: max_tokens already validated ≤128 by Pydantic
    text = await call_model(
        prompt=body.prompt,
        max_tokens=body.max_tokens,
        role=role,  # type: ignore[arg-type]
        cache_mode=cache_mode,
    )

    response_digest = hashlib.sha256(text.encode()).hexdigest()

    # ── SECURITY SI-07: Append audit entry; FAIL CLOSED if logger raises ─
    # With the FailClosedStub this raises HTTPException(503).
    # With the real logger (T04) this persists to the hash chain.
    # SECURITY SI-08: only digests go into the audit log, never raw text
    await logger.append(
        run_id=None,
        actor=role,
        event="probe_processed",
        data={
            "prompt_digest": prompt_digest,
            "response_digest": response_digest,
            "max_tokens": body.max_tokens,
        },
    )

    # SECURITY SI-08: return only {"text": ...}; no timings, usage, slot info
    return ProbeResponse(text=text)


@router.post("/v1/red/probe", response_model=ProbeResponse)
async def red_probe(
    body: ProbeRequest,
    _auth: None = Depends(require_red),
    logger: LoggerClient = Depends(get_logger),
    db: aiosqlite.Connection = Depends(get_db),
) -> ProbeResponse:
    """Red team raw model probe."""
    return await _handle_probe(role="red", body=body, logger=logger, db=db)


@router.post("/v1/blue/probe", response_model=ProbeResponse)
async def blue_probe(
    body: ProbeRequest,
    _auth: None = Depends(require_blue),
    logger: LoggerClient = Depends(get_logger),
    db: aiosqlite.Connection = Depends(get_db),
) -> ProbeResponse:
    """Blue team raw model probe."""
    return await _handle_probe(role="blue", body=body, logger=logger, db=db)
