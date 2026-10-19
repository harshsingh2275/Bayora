"""
verifier/app/main.py
FastAPI application for the Bayora Independent Verifier Service.

Architecture §8:
  - Independent code path (never imports logger code)
  - Read-only mount of log volume
  - Pinned Ed25519 public key mounted read-only
  - GET /verify -> {ok, entries, checkpoints, head, errors[]}
  - GET /verify/tamper-demo -> in-memory tamper demo evaluating 6 cases
"""
from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import FastAPI, HTTPException, status

from .config import LOG_DIR, load_trusted_pubkey
from .verifier import run_tamper_demo, verify_log_chain

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":%(message)s}',
)
log = logging.getLogger("verifier.main")

app = FastAPI(
    title="Bayora Audit Verifier",
    version="0.1.0",
)


def _read_disk_log() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Read entries and checkpoints from disk (read-only mount)."""
    entries: list[dict[str, Any]] = []
    checkpoints: list[dict[str, Any]] = []

    log_path = LOG_DIR / "log.jsonl"
    cp_path = LOG_DIR / "checkpoints.jsonl"

    if log_path.exists():
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))

    if cp_path.exists():
        with open(cp_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    checkpoints.append(json.loads(line))

    return entries, checkpoints


@app.get("/health")
async def health() -> dict[str, str]:
    """Service health endpoint (unauthenticated for Docker healthcheck)."""
    return {"status": "ok", "service": "verifier"}


@app.get("/verify")
async def verify_endpoint() -> dict[str, Any]:
    """
    Verify complete audit log and checkpoint signatures.
    Returns: {ok, entries, checkpoints, head, errors[]}
    """
    try:
        pubkey = load_trusted_pubkey()
    except Exception as err:
        log.error({"event": "pubkey_load_failed", "error": str(err)})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load trusted public key: {err}",
        )

    entries, checkpoints = _read_disk_log()
    result = verify_log_chain(entries, checkpoints, pubkey)
    log.info({
        "event": "verification_completed",
        "ok": result["ok"],
        "entries": result["entries"],
        "checkpoints": result["checkpoints"],
    })
    return result


@app.get("/verify/tamper-demo")
async def tamper_demo_endpoint() -> dict[str, Any]:
    """
    Run in-memory tamper demonstration across 6 attack scenarios.
    SECURITY: Operates strictly on in-memory deep copies without touching disk.
    """
    try:
        pubkey = load_trusted_pubkey()
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load trusted public key: {err}",
        )

    entries, checkpoints = _read_disk_log()
    if not entries or not checkpoints:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tamper demonstration requires at least 1 checkpoint and log entries on disk (append entries first)",
        )

    return run_tamper_demo(entries, checkpoints, pubkey)
