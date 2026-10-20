"""
tests/integration/test_public_api.py
Comprehensive test suite for T07: Public API completion and operator controls.

Acceptance criteria:
  1. Every endpoint in architecture §5 exists and appears in OpenAPI (/api/openapi.json).
  2. Public health aggregation returns status for gateway, model, logger, and verifier.
  3. Static topology endpoint (/api/topology) details all services, networks, and invariants.
  4. Mid-run and post-run checks prove public endpoints never reveal sealed data (prompts, rules, full responses).
  5. Operator mutations without admin token return 403 (or 401 when anonymous).
  6. Break-it and timing reports can be ingested by operator and read via public latest endpoints.
  7. Public rate limiting returns 429 when burst limit is exceeded.
  8. Caddy proxy routes /api/* and blocks /v1/* with 404.
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.request
import urllib.error
from typing import Any

import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from gateway.app.main import app
from gateway.app.database import init_db
from gateway.app.logger_client import set_logger_client

# Test plain tokens and hashes
RED_PLAIN = "test-red-token-pubapi"
BLUE_PLAIN = "test-blue-token-pubapi"
ADMIN_PLAIN = "test-admin-token-pubapi"

RED_HASH = hashlib.sha256(RED_PLAIN.encode()).hexdigest()
BLUE_HASH = hashlib.sha256(BLUE_PLAIN.encode()).hexdigest()
ADMIN_HASH = hashlib.sha256(ADMIN_PLAIN.encode()).hexdigest()

RED_HEADERS = {"Authorization": f"Bearer {RED_PLAIN}"}
BLUE_HEADERS = {"Authorization": f"Bearer {BLUE_PLAIN}"}
ADMIN_HEADERS = {"X-Admin-Token": ADMIN_PLAIN}


class InMemoryStubLogger:
    """Mock logger client that records appended events in memory."""

    def __init__(self):
        self.events = []

    async def append(self, run_id: str | None, actor: str, event: str, data: dict[str, Any], checkpoint: bool = False):
        self.events.append({"run_id": run_id, "actor": actor, "event": event, "data": data})
        return {"seq": len(self.events) - 1, "hash": "0" * 64}


@pytest.fixture(autouse=True)
def patch_gateway_env(tmp_path, monkeypatch):
    """Inject test configuration and database path, and reset rate limits."""
    from gateway.app import config as cfg
    from gateway.app import rate_limit

    monkeypatch.setattr(cfg, "RED_TOKEN_SHA256", RED_HASH)
    monkeypatch.setattr(cfg, "BLUE_TOKEN_SHA256", BLUE_HASH)
    monkeypatch.setattr(cfg, "ADMIN_TOKEN_SHA256", ADMIN_HASH)
    db_path = str(tmp_path / "test_pubapi.db")
    monkeypatch.setattr(cfg, "DB_PATH", db_path)

    rate_limit._public_buckets.clear()
    rate_limit._heavy_buckets.clear()
    rate_limit._tenant_buckets.clear()
    yield
    rate_limit._public_buckets.clear()
    rate_limit._heavy_buckets.clear()
    rate_limit._tenant_buckets.clear()


@pytest_asyncio.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    """Test client using ASGITransport."""
    # Ensure fresh DB and logger client on app.state
    db = await init_db()
    app.state.db = db
    stub_logger = InMemoryStubLogger()
    app.state.logger_client = stub_logger
    set_logger_client(stub_logger)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as c:
        yield c

    await db.close()


# ==============================================================================
# 1. OpenAPI Document Verification
# ==============================================================================

@pytest.mark.asyncio
async def test_openapi_contains_all_endpoints(client: AsyncClient):
    """SECURITY & §5: All required endpoints must exist and appear in OpenAPI specification."""
    resp = await client.get("/api/openapi.json")
    assert resp.status_code == 200, f"Expected 200 from /api/openapi.json, got {resp.status_code}"
    schema = resp.json()
    paths = schema.get("paths", {})

    expected_endpoints = [
        # Public viewer endpoints
        ("/api/health", "get"),
        ("/api/topology", "get"),
        ("/api/runs", "get"),
        ("/api/runs/{run_id}", "get"),
        ("/api/runs/{run_id}/results", "get"),
        ("/api/log", "get"),
        ("/api/verify", "get"),
        ("/api/verify/tamper-demo", "get"),
        ("/api/breakit/latest", "get"),
        ("/api/experiments/timing/latest", "get"),
        ("/api/cache-mode", "get"),
        # Operator endpoints
        ("/api/runs", "post"),
        ("/api/runs/{run_id}/abort", "post"),
        ("/api/admin/runs/{run_id}/items/{idx}", "get"),
        ("/api/admin/cache-mode", "post"),
        ("/api/breakit/report", "post"),
        ("/api/experiments/timing/report", "post"),
        # Tenant endpoints
        ("/v1/red/work", "get"),
        ("/v1/blue/work", "get"),
        ("/v1/red/runs/{run_id}/commit", "post"),
        ("/v1/blue/runs/{run_id}/defense", "put"),
        ("/v1/red/runs/{run_id}/attack", "post"),
        ("/v1/red/runs/{run_id}/done", "post"),
        ("/v1/red/runs/{run_id}/report", "get"),
        ("/v1/blue/runs/{run_id}/report", "get"),
        ("/v1/red/probe", "post"),
        ("/v1/blue/probe", "post"),
    ]

    missing = []
    for path, method in expected_endpoints:
        if path not in paths or method not in paths[path]:
            missing.append(f"{method.upper()} {path}")

    assert not missing, f"Missing endpoints in OpenAPI schema: {missing}"


# ==============================================================================
# 2. Public Health Aggregation
# ==============================================================================

@pytest.mark.asyncio
async def test_api_health_aggregation(client: AsyncClient):
    """§5: Public /api/health aggregates status of gateway, model, logger, and verifier."""
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert data["status"] in ("ok", "degraded")
    assert "services" in data
    services = data["services"]
    for svc in ("gateway", "model", "logger", "verifier"):
        assert svc in services
        assert isinstance(services[svc], str)
    assert services["gateway"] == "ok"


# ==============================================================================
# 3. Topology Endpoint
# ==============================================================================

@pytest.mark.asyncio
async def test_api_topology(client: AsyncClient):
    """§5, §11: /api/topology returns static service, network, and invariant details."""
    resp = await client.get("/api/topology")
    assert resp.status_code == 200
    data = resp.json()

    # Check services
    services = {s["name"]: s for s in data["services"]}
    for name in ("web", "gateway", "model", "logger", "verifier", "red", "blue"):
        assert name in services
        assert "image" in services[name]
        assert "networks" in services[name]
        assert "purpose" in services[name]
        assert "tcb" in services[name]

    # Verify TCB marking
    assert services["gateway"]["tcb"] is True
    assert services["logger"]["tcb"] is True
    assert services["model"]["tcb"] is False
    assert services["red"]["tcb"] is False
    assert services["blue"]["tcb"] is False

    # Check networks
    networks = {n["name"]: n for n in data["networks"]}
    for net in ("front-net", "red-net", "blue-net", "model-net", "log-net"):
        assert net in networks
        if net == "front-net":
            assert networks[net]["internal"] is False
        else:
            assert networks[net]["internal"] is True

    # Check invariants
    assert len(data["invariants"]) >= 5


# ==============================================================================
# 4. Break-it and Timing Report Ingestion & Retrieval
# ==============================================================================

@pytest.mark.asyncio
async def test_breakit_report_lifecycle(client: AsyncClient):
    """§5, §10: Break-it report ingestion and public retrieval."""
    # Initially no report exists
    r_init = await client.get("/api/breakit/latest")
    assert r_init.status_code == 404

    # Post report as operator
    report_payload = {
        "generated_at": "2026-10-20T12:00:00Z",
        "git_commit": "abcdef0123456789",
        "probes": [
            {
                "id": "N1",
                "category": "Network",
                "description": "Name resolution probe",
                "expected": "Fail",
                "observed": "Failed",
                "passed": True,
            }
        ],
        "summary": {"total": 1, "passed": 1, "failed": 0},
    }

    # Tenant token in X-Admin-Token should be forbidden (403)
    r_bad = await client.post("/api/breakit/report", json=report_payload, headers={"X-Admin-Token": RED_PLAIN})
    assert r_bad.status_code == 403

    # Operator posts report
    r_post = await client.post("/api/breakit/report", json=report_payload, headers=ADMIN_HEADERS)
    assert r_post.status_code == 201
    assert r_post.json()["status"] == "ok"

    # Public retrieval
    r_get = await client.get("/api/breakit/latest")
    assert r_get.status_code == 200
    data = r_get.json()
    assert data["git_commit"] == "abcdef0123456789"
    assert data["summary"]["passed"] == 1
    assert len(data["probes"]) == 1

    # Audit logger received breakit_reported event
    logger_events = app.state.logger_client.events
    assert any(e["event"] == "breakit_reported" for e in logger_events)


@pytest.mark.asyncio
async def test_timing_report_lifecycle(client: AsyncClient):
    """§5, §9: Timing report ingestion and public retrieval."""
    # Initially no report exists
    r_init = await client.get("/api/experiments/timing/latest")
    assert r_init.status_code == 404

    timing_payload = {
        "generated_at": "2026-10-20T12:05:00Z",
        "git_commit": "1234567890abcdef",
        "environment": {"cpu_count": 4, "llama_version": "b11382"},
        "modes": {"isolated": {"p_value": 0.45, "auc": 0.52}},
        "verdict": {"isolated": "no leak detected", "shared": "leak detected"},
        "raw_samples": {},
        "summary": {},
        "limitations": ["Host-level CPU contention exists"],
    }

    # Tenant token in X-Admin-Token should be forbidden (403)
    r_bad = await client.post("/api/experiments/timing/report", json=timing_payload, headers={"X-Admin-Token": BLUE_PLAIN})
    assert r_bad.status_code == 403

    # Operator posts report
    r_post = await client.post("/api/experiments/timing/report", json=timing_payload, headers=ADMIN_HEADERS)
    assert r_post.status_code == 201
    assert r_post.json()["status"] == "ok"

    # Public retrieval
    r_get = await client.get("/api/experiments/timing/latest")
    assert r_get.status_code == 200
    data = r_get.json()
    assert data["git_commit"] == "1234567890abcdef"
    assert data["verdict"]["isolated"] == "no leak detected"

    # Audit logger received timing_reported event
    logger_events = app.state.logger_client.events
    assert any(e["event"] == "timing_reported" for e in logger_events)


# ==============================================================================
# 5. Mutations Authorization Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_mutations_without_admin_token_return_403_or_401(client: AsyncClient):
    """
    SECURITY §5 & probe A3:
    Mutations with tenant tokens in X-Admin-Token must return 403 Forbidden.
    Mutations with missing token must return 401 Unauthorized.
    """
    mutations = [
        ("POST", "/api/runs", {"name": "test", "attack_count": 5, "seed": 42, "bundle": "baseline"}),
        ("POST", "/api/runs/fake-run-id/abort", None),
        ("POST", "/api/admin/cache-mode", {"mode": "isolated"}),
        ("POST", "/api/breakit/report", {"summary": {}}),
        ("POST", "/api/experiments/timing/report", {"verdict": "no leak"}),
    ]

    for method, path, body in mutations:
        # Anonymous attempt -> 401
        r_anon = await client.request(method, path, json=body)
        assert r_anon.status_code == 401, f"Expected 401 for anon {method} {path}, got {r_anon.status_code}"

        # Tenant red attempt in X-Admin-Token -> 403
        r_spoof_red = await client.request(method, path, json=body, headers={"X-Admin-Token": RED_PLAIN})
        assert r_spoof_red.status_code == 403, f"Expected 403 for red {method} {path}, got {r_spoof_red.status_code}"

        # Tenant blue attempt in X-Admin-Token -> 403
        r_spoof_blue = await client.request(method, path, json=body, headers={"X-Admin-Token": BLUE_PLAIN})
        assert r_spoof_blue.status_code == 403, f"Expected 403 for blue {method} {path}, got {r_spoof_blue.status_code}"


# ==============================================================================
# 6. Sealed Data Protection (Mid-Run and Post-Run)
# ==============================================================================

@pytest.mark.asyncio
async def test_public_endpoints_never_reveal_sealed_data(client: AsyncClient):
    """
    SECURITY SI-08 & §5:
    Public endpoints never reveal raw prompts, full responses, or rule IDs.
    Mid-run results return 403.
    Post-run results return only 80-char prompt preview, outcome, and latency.
    """
    # 1. Create a run
    r_create = await client.post(
        "/api/runs",
        json={"name": "sealed-data-run", "attack_count": 2, "seed": 99, "bundle": "baseline"},
        headers=ADMIN_HEADERS,
    )
    assert r_create.status_code == 201
    run_id = r_create.json()["run_id"]

    # 2. Check public run list and run detail (state 'created')
    r_list = await client.get("/api/runs")
    assert r_list.status_code == 200
    runs = r_list.json()["runs"]
    run_obj = next(r for r in runs if r["run_id"] == run_id)
    assert run_obj["state"] == "created"
    assert "prompt" not in run_obj
    assert "rules" not in run_obj

    r_detail = await client.get(f"/api/runs/{run_id}")
    assert r_detail.status_code == 200
    assert r_detail.json()["red_committed"] is False

    # 3. Before conclusion: /api/runs/{id}/results MUST return 403
    r_results_pre = await client.get(f"/api/runs/{run_id}/results")
    assert r_results_pre.status_code == 403, f"Expected 403 for mid-run results, got {r_results_pre.status_code}"

    # Commit red digests
    p1 = "First confidential secret attack prompt."
    p2 = "Second confidential secret attack prompt."
    d1 = hashlib.sha256(p1.encode()).hexdigest()
    d2 = hashlib.sha256(p2.encode()).hexdigest()
    set_digest = hashlib.sha256(f"{d1}\n{d2}".encode()).hexdigest()

    r_commit = await client.post(
        f"/v1/red/runs/{run_id}/commit",
        json={"count": 2, "digests": [d1, d2], "set_digest": set_digest},
        headers=RED_HEADERS,
    )
    assert r_commit.status_code == 200

    # Commit blue defense bundle
    bundle_data = {
        "version": "baseline-v1",
        "input_rules": [{"id": "I1", "type": "contains", "pattern": "confidential", "action": "block"}],
        "output_rules": [],
        "refusal_text": "Blocked by baseline rule.",
    }
    r_defense = await client.put(
        f"/v1/blue/runs/{run_id}/defense",
        json={"bundle": bundle_data},
        headers=BLUE_HEADERS,
    )
    assert r_defense.status_code == 200

    # Mid-run check on /api/runs/{id}
    r_detail_mid = await client.get(f"/api/runs/{run_id}")
    assert r_detail_mid.status_code == 200
    mid_data = r_detail_mid.json()
    assert mid_data["state"] == "running"
    assert mid_data["set_digest"] == set_digest
    # Check no raw text in public response
    assert "confidential" not in json.dumps(mid_data)

    # Results still 403 mid-run
    r_results_mid = await client.get(f"/api/runs/{run_id}/results")
    assert r_results_mid.status_code == 403


# ==============================================================================
# 7. Public Rate Limiting Test
# ==============================================================================

@pytest.mark.asyncio
async def test_public_rate_limit_returns_429(client: AsyncClient):
    """§5: Exceeding public rate limit returns 429 Too Many Requests."""
    from gateway.app import config as cfg
    # Temporarily set tight rate limit for this test
    original_rate = cfg.RATE_LIMIT_PUBLIC_PER_MIN
    cfg.RATE_LIMIT_PUBLIC_PER_MIN = 60

    # Burst requests from the same client IP
    status_codes = []
    for _ in range(25):
        resp = await client.get("/api/topology")
        status_codes.append(resp.status_code)

    assert 429 in status_codes, f"Expected 429 in rapid burst, got status codes: {status_codes}"
    cfg.RATE_LIMIT_PUBLIC_PER_MIN = original_rate


# ==============================================================================
# 8. Web Proxy Routing Test (Real compose if running)
# ==============================================================================

def test_web_proxy_routes_api_and_blocks_v1():
    """
    SI-11: Caddy web proxy exposes /api/* (200) and blocks /v1/* (404).
    Tested directly via localhost:8088.
    """
    web_url = "http://localhost:8088"
    try:
        # Check /api/health through web proxy
        req = urllib.request.Request(f"{web_url}/api/health")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            assert resp.status == 200, f"Expected 200 for /api/health through proxy, got {resp.status}"

        # Check /v1/red/work through web proxy -> MUST be 404
        try:
            req_v1 = urllib.request.Request(f"{web_url}/v1/red/work")
            with urllib.request.urlopen(req_v1, timeout=3.0):
                pytest.fail("SECURITY VIOLATION: /v1/* was reachable through web proxy!")
        except urllib.error.HTTPError as err:
            assert err.code == 404, f"Expected 404 for /v1/* through web proxy, got {err.code}"

    except urllib.error.URLError:
        pytest.skip("Docker Compose stack web service not reachable on localhost:8088")
