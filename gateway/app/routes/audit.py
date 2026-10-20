"""
gateway/app/routes/audit.py
Public audit log and verification proxy endpoints.

Architecture §5:
  - GET /api/log?after=&limit= -> Audit entries (digests only)
  - GET /api/verify -> Proxies the verifier: full verification result
  - GET /api/verify/tamper-demo -> Proxies the verifier's in-memory tamper demonstration
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..config import LOGGER_URL as DEFAULT_LOGGER_URL
from ..config import VERIFIER_URL as DEFAULT_VERIFIER_URL
from ..logger_client import _read_logger_token
from ..rate_limit import check_heavy_rate, check_public_rate

log = logging.getLogger("gateway.routes.audit")

router = APIRouter()


@router.get("/api/log", dependencies=[Depends(check_public_rate)])
async def get_audit_log(
    after: int | None = Query(default=None, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    """Public proxy for reading audit log entries (digests only)."""
    token = _read_logger_token()
    headers = {"Authorization": f"Bearer {token}"}
    params: dict[str, Any] = {"limit": limit}
    if after is not None:
        params["after"] = after

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{DEFAULT_LOGGER_URL}/entries", headers=headers, params=params)
            if resp.status_code != 200:
                raise HTTPException(status_code=503, detail="Audit log service error")
            return resp.json()
    except HTTPException:
        raise
    except Exception as err:
        log.error({"event": "audit_log_fetch_failed", "error": type(err).__name__})
        raise HTTPException(status_code=503, detail="Audit log service unavailable")


@router.get(
    "/api/verify",
    dependencies=[Depends(check_public_rate), Depends(check_heavy_rate)],
)
async def proxy_verify() -> dict[str, Any]:
    """Public proxy for verifier result."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{DEFAULT_VERIFIER_URL}/verify")
            if resp.status_code != 200:
                raise HTTPException(status_code=503, detail="Verifier service error")
            return resp.json()
    except HTTPException:
        raise
    except Exception as err:
        log.error({"event": "verifier_proxy_failed", "error": type(err).__name__})
        raise HTTPException(status_code=503, detail="Verifier service unavailable")


@router.get(
    "/api/verify/tamper-demo",
    dependencies=[Depends(check_public_rate), Depends(check_heavy_rate)],
)
async def proxy_tamper_demo() -> dict[str, Any]:
    """Public proxy for verifier in-memory tamper demo."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{DEFAULT_VERIFIER_URL}/verify/tamper-demo")
            if resp.status_code == 400:
                raise HTTPException(status_code=400, detail=resp.json().get("detail", "Bad Request"))
            if resp.status_code != 200:
                raise HTTPException(status_code=503, detail="Verifier service error")
            return resp.json()
    except HTTPException:
        raise
    except Exception as err:
        log.error({"event": "tamper_demo_proxy_failed", "error": type(err).__name__})
        raise HTTPException(status_code=503, detail="Verifier service unavailable")
