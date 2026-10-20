"""
gateway/app/routes/admin.py
Operator endpoints: run creation, abort, item details, cache-mode control.
Public run viewer endpoints: list runs, get run.

Architecture references: §5, §6
Auth:
  - Operator endpoints require X-Admin-Token (require_admin dependency).
  - Public endpoints have no auth and are rate limited.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse

from ..auth import require_admin
from ..database import (
    get_latest_breakit_report,
    get_latest_timing_report,
    get_setting,
    save_breakit_report,
    save_timing_report,
    set_setting,
)
from ..deps import get_db, get_logger
from ..logger_client import LoggerClient
from ..models import (
    AbortRunResponse,
    BreakitReportIngestResponse,
    BreakitReportRequest,
    BreakitReportResponse,
    CacheModeRequest,
    CacheModeResponse,
    CreateRunRequest,
    CreateRunResponse,
    OperatorRunItemResponse,
    RunDetailResponse,
    RunListItem,
    RunListResponse,
    TimingReportIngestResponse,
    TimingReportRequest,
    TimingReportResponse,
    TopologyResponse,
)
from ..rate_limit import check_public_rate
from .run_lifecycle import get_run_with_timeout_check

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
    logger: LoggerClient = Depends(get_logger),
) -> CacheModeResponse:
    """Operator: set cache mode (isolated | shared)."""
    await set_setting(db, "cache_mode", body.mode)
    # SECURITY SI-07/SI-08: Log cache_mode_changed event to audit chain
    await logger.append(
        run_id=None,
        actor="operator",
        event="cache_mode_changed",
        data={"mode": body.mode},
    )
    log.info({"event": "cache_mode_changed", "mode": body.mode})
    return CacheModeResponse(mode=body.mode)


# ── Run creation & management ──────────────────────────────────────────────────
@router.post("/api/runs", status_code=201, response_model=CreateRunResponse)
async def create_run(
    body: CreateRunRequest,
    _auth: None = Depends(require_admin),
    db: aiosqlite.Connection = Depends(get_db),
    logger: LoggerClient = Depends(get_logger),
) -> JSONResponse:
    """
    Operator: create a new run.
    One active run at a time; otherwise 409 Conflict.
    Auto-aborts any prior timed-out run first.
    Logs run_created audit event.
    """
    # Check for active run, running timeout check first on any candidate
    async with db.execute(
        "SELECT run_id FROM runs WHERE state NOT IN ('concluded','aborted','failed') "
        "ORDER BY created_at DESC"
    ) as cur:
        rows = await cur.fetchall()

    for r in rows:
        active_candidate = await get_run_with_timeout_check(db, r["run_id"], logger)
        if active_candidate and active_candidate["state"] not in ("concluded", "aborted", "failed"):
            return JSONResponse(
                status_code=409,
                content={"detail": "A run is already active"},
            )

    run_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "INSERT INTO runs ("
        "run_id, name, state, attack_count, seed, bundle_name, created_at, updated_at"
        ") VALUES (?, ?, 'created', ?, ?, ?, ?, ?)",
        (run_id, body.name, body.attack_count, body.seed, body.bundle, now_iso, now_iso),
    )
    await db.commit()

    # SECURITY SI-07/SI-08: Log run_created event to audit logger
    await logger.append(
        run_id=run_id,
        actor="operator",
        event="run_created",
        data={
            "name": body.name,
            "attack_count": body.attack_count,
            "seed": body.seed,
            "bundle": body.bundle,
        },
    )
    log.info({"event": "run_created", "run_id": run_id, "name": body.name})

    return JSONResponse(status_code=201, content={"run_id": run_id, "state": "created"})


@router.post("/api/runs/{run_id}/abort", response_model=AbortRunResponse)
async def abort_run(
    run_id: str,
    _auth: None = Depends(require_admin),
    db: aiosqlite.Connection = Depends(get_db),
    logger: LoggerClient = Depends(get_logger),
) -> JSONResponse:
    """
    Operator: abort an active run.
    If run does not exist -> 404.
    If run is already concluded or aborted -> 409 Conflict.
    Logs run_aborted audit event.
    """
    run = await get_run_with_timeout_check(db, run_id, logger)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    if run["state"] in ("concluded", "aborted", "failed"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot abort run in terminal state '{run['state']}'",
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "UPDATE runs SET state = 'aborted', updated_at = ? WHERE run_id = ?",
        (now_iso, run_id),
    )
    await db.commit()

    # SECURITY SI-07/SI-08: Log run_aborted audit event
    await logger.append(
        run_id=run_id,
        actor="operator",
        event="run_aborted",
        data={},
    )
    log.info({"event": "run_aborted", "run_id": run_id})

    return JSONResponse(status_code=200, content={"run_id": run_id, "state": "aborted"})


@router.get("/api/admin/runs/{run_id}/items/{idx}", response_model=OperatorRunItemResponse)
async def get_run_item(
    run_id: str,
    idx: int,
    _auth: None = Depends(require_admin),
    db: aiosqlite.Connection = Depends(get_db),
    logger: LoggerClient = Depends(get_logger),
) -> OperatorRunItemResponse:
    """
    Operator: full prompt and model response for an item (architecture §5).
    Requires X-Admin-Token.
    """
    run = await get_run_with_timeout_check(db, run_id, logger)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    async with db.execute(
        "SELECT run_id, idx, prompt, response_text, outcome, rule_id, latency_ms "
        "FROM attacks WHERE run_id = ? AND idx = ?",
        (run_id, idx),
    ) as cur:
        row = await cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Item idx {idx} not found for run")

    return OperatorRunItemResponse(
        run_id=row["run_id"],
        idx=row["idx"],
        prompt=row["prompt"],
        response_text=row["response_text"],
        outcome=row["outcome"],
        rule_id=row["rule_id"],
        latency_ms=round(row["latency_ms"], 2) if row["latency_ms"] is not None else None,
    )


# ── Public run viewer endpoints ────────────────────────────────────────────────
@router.get(
    "/api/runs",
    response_model=RunListResponse,
    dependencies=[Depends(check_public_rate)],
)
async def list_runs(
    db: aiosqlite.Connection = Depends(get_db),
    logger: LoggerClient = Depends(get_logger),
) -> RunListResponse:
    """
    Public: list of runs with state, commitment status, digests, and timeline info.
    SECURITY §5: Never exposes prompts or rules.
    """
    async with db.execute(
        "SELECT r.run_id, r.name, r.state, r.attack_count, r.seed, r.bundle_name, "
        "r.created_at, r.updated_at, "
        "MAX(CASE WHEN c.role = 'red' THEN 1 ELSE 0 END) as red_committed, "
        "MAX(CASE WHEN c.role = 'blue' THEN 1 ELSE 0 END) as blue_committed, "
        "MAX(CASE WHEN c.role = 'red' THEN c.set_digest ELSE NULL END) as set_digest, "
        "MAX(CASE WHEN c.role = 'blue' THEN c.bundle_digest ELSE NULL END) as bundle_digest "
        "FROM runs r "
        "LEFT JOIN commitments c ON r.run_id = c.run_id "
        "GROUP BY r.run_id "
        "ORDER BY r.created_at DESC"
    ) as cur:
        rows = [dict(r) for r in await cur.fetchall()]

    for r in rows:
        r["red_committed"] = bool(r["red_committed"])
        r["blue_committed"] = bool(r["blue_committed"])

    return RunListResponse(runs=[RunListItem(**r) for r in rows])


@router.get(
    "/api/runs/{run_id}",
    response_model=RunDetailResponse,
    dependencies=[Depends(check_public_rate)],
)
async def get_run_detail(
    run_id: str,
    db: aiosqlite.Connection = Depends(get_db),
    logger: LoggerClient = Depends(get_logger),
) -> RunDetailResponse:
    """
    Public: run state, commitment digests, and timeline.
    SECURITY §5: Never reveals prompts or rules before conclusion.
    """
    run = await get_run_with_timeout_check(db, run_id, logger)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    # Fetch commitments
    async with db.execute(
        "SELECT role, set_digest, bundle_digest FROM commitments WHERE run_id = ?",
        (run_id,),
    ) as cur:
        comms = {r["role"]: dict(r) for r in await cur.fetchall()}

    red_c = comms.get("red")
    blue_c = comms.get("blue")

    return RunDetailResponse(
        run_id=run["run_id"],
        name=run["name"],
        state=run["state"],
        attack_count=run["attack_count"],
        seed=run["seed"],
        bundle_name=run["bundle_name"],
        created_at=run["created_at"],
        updated_at=run["updated_at"],
        red_committed=red_c is not None,
        blue_committed=blue_c is not None,
        set_digest=red_c["set_digest"] if red_c else None,
        bundle_digest=blue_c["bundle_digest"] if blue_c else None,
    )


# ── Topology endpoint (/api/topology) ─────────────────────────────────────────
TOPOLOGY_DATA = {
    "services": [
        {
            "name": "web",
            "image": "Caddy 2",
            "networks": ["front-net"],
            "purpose": "Public reverse proxy and frontend static files (SI-11)",
            "tcb": False,
            "isolated": True,
        },
        {
            "name": "gateway",
            "image": "Python 3.12, FastAPI",
            "networks": ["front-net", "red-net", "blue-net", "model-net", "log-net"],
            "purpose": "Central coordinator, authorization, scoring, and proxy",
            "tcb": True,
            "isolated": False,
        },
        {
            "name": "model",
            "image": "llama.cpp server",
            "networks": ["model-net"],
            "purpose": "Client LLM under test (isolated on model-net)",
            "tcb": False,
            "isolated": True,
        },
        {
            "name": "logger",
            "image": "Python 3.12, FastAPI",
            "networks": ["log-net"],
            "purpose": "Sole writer of the append-only signed audit log (SI-04)",
            "tcb": True,
            "isolated": True,
        },
        {
            "name": "verifier",
            "image": "Python 3.12, FastAPI",
            "networks": ["log-net"],
            "purpose": "Independent audit log verification service (read-only mount)",
            "tcb": False,
            "isolated": True,
        },
        {
            "name": "red",
            "image": "Python 3.12",
            "networks": ["red-net"],
            "purpose": "Red-team adversarial testing agent",
            "tcb": False,
            "isolated": True,
        },
        {
            "name": "blue",
            "image": "Python 3.12",
            "networks": ["blue-net"],
            "purpose": "Blue-team defensive bundle agent",
            "tcb": False,
            "isolated": True,
        },
    ],
    "networks": [
        {
            "name": "front-net",
            "internal": False,
            "description": "Public-facing bridge carrying web and gateway only",
            "services": ["web", "gateway"],
        },
        {
            "name": "red-net",
            "internal": True,
            "description": "Internal network for red tenant and gateway (SI-03)",
            "services": ["red", "gateway"],
        },
        {
            "name": "blue-net",
            "internal": True,
            "description": "Internal network for blue tenant and gateway (SI-03)",
            "services": ["blue", "gateway"],
        },
        {
            "name": "model-net",
            "internal": True,
            "description": "Internal network for target LLM model server and gateway (SI-03)",
            "services": ["model", "gateway"],
        },
        {
            "name": "log-net",
            "internal": True,
            "description": "Internal network for audit logger, verifier, and gateway (SI-03)",
            "services": ["logger", "verifier", "gateway"],
        },
    ],
    "invariants": [
        "No container is privileged; no host networking or devices (SI-01)",
        "Non-root user, cap_drop ALL, no-new-privileges, read-only root with tmpfs (SI-02)",
        "Tenant networks (red-net, blue-net, model-net, log-net) are internal: true (SI-03)",
        "Gateway is the sole route to the model and logger (SI-04)",
        "Public proxy exposes /api/* only; /v1/* blocked with 404 (SI-11)",
    ],
}


@router.get(
    "/api/topology",
    response_model=TopologyResponse,
    dependencies=[Depends(check_public_rate)],
)
async def get_topology() -> TopologyResponse:
    """
    Public: static description of networks, services, and security boundaries.
    Used by frontend architecture diagram (architecture §5, §11).
    """
    return TopologyResponse(**TOPOLOGY_DATA)


# ── Break-it reports ───────────────────────────────────────────────────────────
@router.post(
    "/api/breakit/report",
    status_code=status.HTTP_201_CREATED,
    response_model=BreakitReportIngestResponse,
)
async def ingest_breakit(
    body: BreakitReportRequest,
    _auth: None = Depends(require_admin),
    db: aiosqlite.Connection = Depends(get_db),
    logger: LoggerClient = Depends(get_logger),
) -> BreakitReportIngestResponse:
    """
    Operator: break-it harness posts its report.
    Stored in DB and logged as breakit_reported audit event.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    report_dict = body.model_dump()
    report_json = json.dumps(report_dict, sort_keys=True, separators=(",", ":"))
    await save_breakit_report(db, report_json, now_iso)

    # SECURITY SI-08: Log event with summary metadata only (no secrets)
    await logger.append(
        run_id=None,
        actor="operator",
        event="breakit_reported",
        data={
            "generated_at": body.generated_at or now_iso,
            "git_commit": body.git_commit,
            "summary": body.summary.model_dump(),
        },
    )
    log.info({"event": "breakit_reported", "summary": body.summary.model_dump()})
    return BreakitReportIngestResponse(status="ok", summary=body.summary)


@router.get(
    "/api/breakit/latest",
    response_model=BreakitReportResponse,
    dependencies=[Depends(check_public_rate)],
)
async def get_latest_breakit(
    db: aiosqlite.Connection = Depends(get_db),
) -> BreakitReportResponse:
    """Public: latest break-it report."""
    report_json = await get_latest_breakit_report(db)
    if not report_json:
        raise HTTPException(status_code=404, detail="No break-it report found")
    data = json.loads(report_json)
    return BreakitReportResponse(**data)


# ── Timing experiment reports ─────────────────────────────────────────────────
@router.post(
    "/api/experiments/timing/report",
    status_code=status.HTTP_201_CREATED,
    response_model=TimingReportIngestResponse,
)
async def ingest_timing(
    body: TimingReportRequest,
    _auth: None = Depends(require_admin),
    db: aiosqlite.Connection = Depends(get_db),
    logger: LoggerClient = Depends(get_logger),
) -> TimingReportIngestResponse:
    """
    Operator: timing side-channel experiment script posts its report.
    Stored in DB and logged as timing_reported audit event.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    report_dict = body.model_dump()
    report_json = json.dumps(report_dict, sort_keys=True, separators=(",", ":"))
    await save_timing_report(db, report_json, now_iso)

    # SECURITY SI-08: Log event with verdict and timestamp (no sensitive data)
    await logger.append(
        run_id=None,
        actor="operator",
        event="timing_reported",
        data={
            "generated_at": body.generated_at or now_iso,
            "verdict": body.verdict if isinstance(body.verdict, dict) else {"verdict": body.verdict},
        },
    )
    log.info({"event": "timing_reported"})
    return TimingReportIngestResponse(status="ok", verdict=body.verdict)


@router.get(
    "/api/experiments/timing/latest",
    response_model=TimingReportResponse,
    dependencies=[Depends(check_public_rate)],
)
async def get_latest_timing(
    db: aiosqlite.Connection = Depends(get_db),
) -> TimingReportResponse:
    """Public: latest timing experiment report."""
    report_json = await get_latest_timing_report(db)
    if not report_json:
        raise HTTPException(status_code=404, detail="No timing experiment report found")
    data = json.loads(report_json)
    return TimingReportResponse(**data)
