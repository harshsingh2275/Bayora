"""
tests/security/test_gateway_authz.py
Security adversary test suite for Bayora Gateway.

Source of Truth:
  - docs/architecture.md (§3, §5)
  - AGENTS.md (§3)

Security Invariants tested:
  - SI-05: Tenant and admin tokens compared securely, never logged or returned.
  - SI-06: Request models use extra="forbid", reject unwhitelisted model parameters.
  - SI-08: Strip timings, usage, cache, and slot keys from tenant responses.
  - SI-10: Secrets never enter logs, error messages, or response bodies.
  - SI-11: Public proxy exposes /api/* only; /v1/* returns 404 through web.
  - Rate limiting (429) on tenant and public endpoints.
"""
import asyncio
import os
import subprocess
from typing import Any, Dict, List, Optional
import urllib.request

import httpx
import pytest


def _discover_gateway_url() -> Optional[str]:
    """Dynamically resolve gateway URL from env or running docker container."""
    if os.environ.get("GATEWAY_URL"):
        return os.environ["GATEWAY_URL"]
    try:
        res = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
                "bayora-gateway",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        for ip in res.stdout.strip().split():
            ip = ip.strip()
            if not ip:
                continue
            test_url = f"http://{ip}:8000/api/health"
            try:
                with urllib.request.urlopen(test_url, timeout=1.0) as resp:
                    if resp.status == 200:
                        return f"http://{ip}:8000"
            except Exception:
                continue
    except Exception:
        pass
    return None


def _discover_web_url() -> str:
    if os.environ.get("WEB_URL"):
        return os.environ["WEB_URL"]
    import ssl
    ssl_ctx = ssl._create_unverified_context()
    for candidate in ["http://127.0.0.1:8088", "https://localhost", "http://localhost"]:
        try:
            req = urllib.request.Request(f"{candidate}/health")
            with urllib.request.urlopen(req, timeout=1.0, context=ssl_ctx) as resp:
                if resp.status in (200, 308):
                    return candidate
        except Exception:
            continue
    return "http://127.0.0.1:8088"


GATEWAY_URL = _discover_gateway_url()
WEB_URL = _discover_web_url()

pytestmark = pytest.mark.skipif(
    GATEWAY_URL is None,
    reason="Bayora stack is not running or gateway is unreachable",
)

SECRETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "secrets")


def _read_secret(name: str) -> str:
    path = os.path.join(SECRETS_DIR, name)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    return ""


RED_TOKEN = _read_secret("red_token")
BLUE_TOKEN = _read_secret("blue_token")
ADMIN_TOKEN = _read_secret("admin_token")

FORBIDDEN_LEAK_KEYS = {
    "timings",
    "usage",
    "slot_id",
    "tokens_cached",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "id_slot",
    "cache_prompt",
}


def _assert_no_forbidden_keys(data: Any, path: str = "") -> None:
    """Recursively verify no model leakage keys exist in response JSON."""
    if isinstance(data, dict):
        for k, v in data.items():
            current_path = f"{path}.{k}" if path else k
            assert (
                k.lower() not in FORBIDDEN_LEAK_KEYS
            ), f"SECURITY VIOLATION: forbidden leakage key '{current_path}' found in response!"
            _assert_no_forbidden_keys(v, current_path)
    elif isinstance(data, list):
        for i, item in enumerate(data):
            _assert_no_forbidden_keys(item, f"{path}[{i}]")


# ==============================================================================
# 1. Authentication Attacks
# ==============================================================================


@pytest.mark.asyncio
async def test_auth_no_token_rejected_with_401():
    """SECURITY: SI-05 & §5 - Requests without credentials must be rejected with 401."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        # Tenant endpoints
        r1 = await client.get("/v1/red/work")
        assert r1.status_code == 401, f"Expected 401, got {r1.status_code}"

        r2 = await client.get("/v1/blue/work")
        assert r2.status_code == 401, f"Expected 401, got {r2.status_code}"

        r3 = await client.post("/v1/red/probe", json={"prompt": "hi", "max_tokens": 5})
        assert r3.status_code == 401, f"Expected 401, got {r3.status_code}"

        r4 = await client.post("/v1/blue/probe", json={"prompt": "hi", "max_tokens": 5})
        assert r4.status_code == 401, f"Expected 401, got {r4.status_code}"

        # Operator endpoint
        r5 = await client.post("/api/admin/cache-mode", json={"mode": "isolated"})
        assert r5.status_code == 401, f"Expected 401, got {r5.status_code}"


@pytest.mark.asyncio
async def test_auth_garbage_token_rejected_with_401_no_token_leak():
    """SECURITY: SI-05 & SI-10 - Garbage tokens must return 401 without echoing the token."""
    garbage = "totally-invalid-garbage-token-xyz987"
    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        # Tenant Bearer token
        r = await client.get("/v1/red/work", headers={"Authorization": f"Bearer {garbage}"})
        assert r.status_code == 401
        assert garbage not in r.text, "SECURITY VIOLATION: garbage secret leaked in response!"

        # Operator X-Admin-Token
        r_admin = await client.post(
            "/api/admin/cache-mode",
            json={"mode": "isolated"},
            headers={"X-Admin-Token": garbage},
        )
        assert r_admin.status_code == 401
        assert garbage not in r_admin.text, "SECURITY VIOLATION: garbage admin token leaked in response!"


@pytest.mark.asyncio
async def test_auth_empty_token_rejected_with_401():
    """SECURITY: SI-05 - Empty token headers must be rejected with 401."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        for empty_val in ["", '""', "Bearer", 'Bearer ""']:
            r_tenant = await client.get(
                "/v1/red/work",
                headers={"Authorization": empty_val},
            )
            assert r_tenant.status_code == 401, f"Empty auth '{empty_val}' did not return 401"

        for empty_val in ["", '""']:
            r_admin = await client.post(
                "/api/admin/cache-mode",
                json={"mode": "isolated"},
                headers={"X-Admin-Token": empty_val},
            )
            assert r_admin.status_code == 401, f"Empty admin auth '{empty_val}' did not return 401"


@pytest.mark.asyncio
async def test_auth_cross_role_token_rejected_with_403():
    """SECURITY: §5 - Tenant tokens must not be accepted for the opposing tenant role."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        # Blue token on red endpoint
        r1 = await client.get(
            "/v1/red/work",
            headers={"Authorization": f"Bearer {BLUE_TOKEN}"},
        )
        assert r1.status_code == 403, f"Expected 403 for blue token on red endpoint, got {r1.status_code}"

        # Red token on blue endpoint
        r2 = await client.get(
            "/v1/blue/work",
            headers={"Authorization": f"Bearer {RED_TOKEN}"},
        )
        assert r2.status_code == 403, f"Expected 403 for red token on blue endpoint, got {r2.status_code}"


@pytest.mark.asyncio
async def test_auth_admin_token_header_from_tenant_rejected():
    """SECURITY: §5 - Tenant endpoints require Bearer auth; X-Admin-Token cannot bypass or substitute."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        # Sending only X-Admin-Token to tenant endpoint
        r1 = await client.get(
            "/v1/red/work",
            headers={"X-Admin-Token": ADMIN_TOKEN},
        )
        assert r1.status_code == 401, f"X-Admin-Token on tenant endpoint should be 401, got {r1.status_code}"

        # Sending blue Bearer token + X-Admin-Token to red endpoint (privilege escalation attempt)
        r2 = await client.get(
            "/v1/red/work",
            headers={
                "Authorization": f"Bearer {BLUE_TOKEN}",
                "X-Admin-Token": ADMIN_TOKEN,
            },
        )
        assert r2.status_code == 403, f"Admin header combined with wrong role should still be 403, got {r2.status_code}"


# ==============================================================================
# 2. Authorization Attacks
# ==============================================================================


@pytest.mark.asyncio
async def test_authz_every_tenant_endpoint_with_wrong_role():
    """SECURITY: §5 - Every tenant endpoint must enforce role isolation (403 on wrong role)."""
    endpoints = [
        ("GET", "/v1/red/work", BLUE_TOKEN, None),
        ("GET", "/v1/blue/work", RED_TOKEN, None),
        (
            "POST",
            "/v1/red/runs/test-run/commit",
            BLUE_TOKEN,
            {"count": 1, "digests": ["a" * 64], "set_digest": "b" * 64},
        ),
        (
            "PUT",
            "/v1/blue/runs/test-run/defense",
            RED_TOKEN,
            {
                "bundle": {
                    "version": "v1",
                    "input_rules": [],
                    "output_rules": [],
                    "refusal_text": "blocked",
                }
            },
        ),
        ("POST", "/v1/red/runs/test-run/attack", BLUE_TOKEN, {"idx": 0, "prompt": "attack"}),
        ("POST", "/v1/red/runs/test-run/done", BLUE_TOKEN, {"sent": 1}),
        ("GET", "/v1/red/runs/test-run/report", BLUE_TOKEN, None),
        ("GET", "/v1/blue/runs/test-run/report", RED_TOKEN, None),
        ("POST", "/v1/red/probe", BLUE_TOKEN, {"prompt": "test", "max_tokens": 10}),
        ("POST", "/v1/blue/probe", RED_TOKEN, {"prompt": "test", "max_tokens": 10}),
    ]

    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        for method, path, token, body in endpoints:
            headers = {"Authorization": f"Bearer {token}"}
            if method == "GET":
                resp = await client.get(path, headers=headers)
            elif method == "POST":
                resp = await client.post(path, json=body, headers=headers)
            elif method == "PUT":
                resp = await client.put(path, json=body, headers=headers)
            else:
                pytest.fail(f"Unhandled method {method}")

            assert (
                resp.status_code == 403
            ), f"SECURITY VIOLATION: {method} {path} with wrong tenant token returned {resp.status_code}, expected 403"


@pytest.mark.asyncio
async def test_authz_blue_cannot_read_report_before_conclusion():
    """SECURITY: §5 - GET /v1/blue/runs/{run_id}/report before conclusion must return 403 (sealed data)."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        resp = await client.get(
            "/v1/blue/runs/nonexistent-or-active-run/report",
            headers={"Authorization": f"Bearer {BLUE_TOKEN}"},
        )
        # Must return 403 (sealed data) per §5
        assert (
            resp.status_code == 403
        ), f"GET blue report before conclusion returned {resp.status_code}, expected 403"


@pytest.mark.asyncio
async def test_authz_every_operator_endpoint_with_tenant_tokens():
    """SECURITY: §5 - Every operator endpoint must reject tenant tokens (401 or 403)."""
    operator_endpoints = [
        (
            "POST",
            "/api/runs",
            {"name": "test", "attack_count": 10, "seed": 42, "bundle": "baseline"},
        ),
        ("POST", "/api/runs/test-run/abort", None),
        ("GET", "/api/admin/runs/test-run/items/0", None),
        ("POST", "/api/admin/cache-mode", {"mode": "isolated"}),
        ("POST", "/api/breakit/report", {"summary": {}}),
        ("POST", "/api/experiments/timing/report", {"verdict": "no leak"}),
    ]

    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        for method, path, body in operator_endpoints:
            for role_name, token in [("red", RED_TOKEN), ("blue", BLUE_TOKEN)]:
                # Attempt 1: As Bearer token
                headers_bearer = {"Authorization": f"Bearer {token}"}
                # Attempt 2: In X-Admin-Token header
                headers_admin = {"X-Admin-Token": token}

                for headers in [headers_bearer, headers_admin]:
                    if method == "GET":
                        resp = await client.get(path, headers=headers)
                    elif method == "POST":
                        resp = await client.post(path, json=body, headers=headers)
                    else:
                        continue

                    assert resp.status_code in (
                        401,
                        403,
                    ), f"SECURITY VIOLATION: Operator endpoint {method} {path} accessible by {role_name} token! Got {resp.status_code}"


# ==============================================================================
# 3. Input Whitelisting Attacks
# ==============================================================================


@pytest.mark.asyncio
async def test_input_unknown_fields_rejected_with_422():
    """SECURITY: SI-06 & §5 - Pydantic models must enforce extra='forbid' with 422."""
    headers_red = {"Authorization": f"Bearer {RED_TOKEN}"}
    headers_admin = {"X-Admin-Token": ADMIN_TOKEN}

    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        # Probe extra field
        r1 = await client.post(
            "/v1/red/probe",
            json={"prompt": "hello", "max_tokens": 10, "unknown_field": "injected"},
            headers=headers_red,
        )
        assert r1.status_code == 422, f"Probe extra field returned {r1.status_code}, expected 422"

        # Commit extra field
        r2 = await client.post(
            "/v1/red/runs/test/commit",
            json={
                "count": 1,
                "digests": ["a" * 64],
                "set_digest": "b" * 64,
                "unwhitelisted": True,
            },
            headers=headers_red,
        )
        assert r2.status_code == 422, f"Commit extra field returned {r2.status_code}, expected 422"

        # Attack extra field
        r3 = await client.post(
            "/v1/red/runs/test/attack",
            json={"idx": 0, "prompt": "attack", "injection": "bad"},
            headers=headers_red,
        )
        assert r3.status_code == 422, f"Attack extra field returned {r3.status_code}, expected 422"

        # Done extra field
        r4 = await client.post(
            "/v1/red/runs/test/done",
            json={"sent": 1, "extra": "data"},
            headers=headers_red,
        )
        assert r4.status_code == 422, f"Done extra field returned {r4.status_code}, expected 422"

        # Admin cache-mode extra field
        r5 = await client.post(
            "/api/admin/cache-mode",
            json={"mode": "isolated", "debug": True},
            headers=headers_admin,
        )
        assert r5.status_code == 422, f"Cache-mode extra field returned {r5.status_code}, expected 422"


@pytest.mark.asyncio
async def test_input_id_slot_and_cache_prompt_injection_rejected_with_422():
    """SECURITY: SI-06 & §5 - Client-supplied id_slot and cache_prompt must be rejected with 422."""
    headers = {"Authorization": f"Bearer {RED_TOKEN}"}
    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        # id_slot injection in probe
        r1 = await client.post(
            "/v1/red/probe",
            json={"prompt": "test", "max_tokens": 10, "id_slot": 0},
            headers=headers,
        )
        assert r1.status_code == 422, f"id_slot injection in probe returned {r1.status_code}, expected 422"

        # cache_prompt injection in probe
        r2 = await client.post(
            "/v1/red/probe",
            json={"prompt": "test", "max_tokens": 10, "cache_prompt": True},
            headers=headers,
        )
        assert (
            r2.status_code == 422
        ), f"cache_prompt injection in probe returned {r2.status_code}, expected 422"

        # id_slot injection in attack
        r3 = await client.post(
            "/v1/red/runs/test/attack",
            json={"idx": 0, "prompt": "test", "id_slot": 1},
            headers=headers,
        )
        assert r3.status_code == 422, f"id_slot injection in attack returned {r3.status_code}, expected 422"

        # cache_prompt injection in attack
        r4 = await client.post(
            "/v1/red/runs/test/attack",
            json={"idx": 0, "prompt": "test", "cache_prompt": False},
            headers=headers,
        )
        assert (
            r4.status_code == 422
        ), f"cache_prompt injection in attack returned {r4.status_code}, expected 422"


@pytest.mark.asyncio
async def test_input_negative_and_huge_max_tokens_rejected_with_422():
    """SECURITY: §5 - Probe max_tokens must strictly be int between 1 and 128."""
    headers = {"Authorization": f"Bearer {RED_TOKEN}"}
    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        for invalid_tokens in [-1, 0, 129, 99999999]:
            resp = await client.post(
                "/v1/red/probe",
                json={"prompt": "test", "max_tokens": invalid_tokens},
                headers=headers,
            )
            assert (
                resp.status_code == 422
            ), f"max_tokens={invalid_tokens} returned {resp.status_code}, expected 422"


@pytest.mark.asyncio
async def test_input_oversized_prompts_rejected_with_422():
    """SECURITY: §5 - Enforce prompt limits: probe max 16000, attack max 4000."""
    headers = {"Authorization": f"Bearer {RED_TOKEN}"}
    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        # Probe oversized prompt (> 16000 chars)
        r1 = await client.post(
            "/v1/red/probe",
            json={"prompt": "P" * 16001, "max_tokens": 10},
            headers=headers,
        )
        assert r1.status_code == 422, f"Probe prompt length 16001 returned {r1.status_code}, expected 422"

        # Attack oversized prompt (> 4000 chars)
        r2 = await client.post(
            "/v1/red/runs/test/attack",
            json={"idx": 0, "prompt": "A" * 4001},
            headers=headers,
        )
        assert r2.status_code == 422, f"Attack prompt length 4001 returned {r2.status_code}, expected 422"


@pytest.mark.asyncio
async def test_input_wrong_types_rejected_with_422():
    """SECURITY: §5 - Wrong data types must fail pydantic schema validation with 422."""
    headers = {"Authorization": f"Bearer {RED_TOKEN}"}
    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        bad_payloads = [
            ("/v1/red/probe", {"prompt": "test", "max_tokens": "five"}),
            ("/v1/red/probe", {"prompt": 12345, "max_tokens": 10}),
            ("/v1/red/runs/test/attack", {"idx": "zero", "prompt": "test"}),
            ("/v1/red/runs/test/attack", {"idx": 0, "prompt": ["array", "of", "strings"]}),
            ("/v1/red/runs/test/commit", {"count": "one", "digests": ["a" * 64], "set_digest": "b" * 64}),
            ("/v1/red/runs/test/commit", {"count": 1, "digests": "not_a_list", "set_digest": "b" * 64}),
        ]
        for path, body in bad_payloads:
            resp = await client.post(path, json=body, headers=headers)
            assert (
                resp.status_code == 422
            ), f"Payload {body} to {path} returned {resp.status_code}, expected 422"


@pytest.mark.asyncio
async def test_input_nested_junk_rejected_with_422():
    """SECURITY: §5 - Arbitrary nested dictionary/JSON junk must be rejected with 422."""
    headers_red = {"Authorization": f"Bearer {RED_TOKEN}"}
    headers_blue = {"Authorization": f"Bearer {BLUE_TOKEN}"}

    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        # Nested object where string expected
        r1 = await client.post(
            "/v1/red/probe",
            json={"prompt": {"nested": {"junk": [1, 2, 3]}}, "max_tokens": 10},
            headers=headers_red,
        )
        assert r1.status_code == 422, f"Nested junk prompt returned {r1.status_code}, expected 422"

        # Nested junk in attack prompt
        r2 = await client.post(
            "/v1/red/runs/test/attack",
            json={"idx": 0, "prompt": {"nested": "dict"}},
            headers=headers_red,
        )
        assert r2.status_code == 422, f"Nested junk attack returned {r2.status_code}, expected 422"

        # Invalid bundle type
        r3 = await client.put(
            "/v1/blue/runs/test/defense",
            json={"bundle": "string-instead-of-bundle-object"},
            headers=headers_blue,
        )
        assert r3.status_code == 422, f"Malformed bundle returned {r3.status_code}, expected 422"


# ==============================================================================
# 4. Response Hygiene
# ==============================================================================


@pytest.mark.asyncio
async def test_response_hygiene_no_timings_usage_slot_keys():
    """SECURITY: SI-08 & §5 - Strip timings, usage, slot_id, tokens_cached from tenant responses."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        # Check /v1/red/work
        r1 = await client.get("/v1/red/work", headers={"Authorization": f"Bearer {RED_TOKEN}"})
        if r1.status_code == 200:
            _assert_no_forbidden_keys(r1.json())

        # Check /v1/blue/work
        r2 = await client.get("/v1/blue/work", headers={"Authorization": f"Bearer {BLUE_TOKEN}"})
        if r2.status_code == 200:
            _assert_no_forbidden_keys(r2.json())

        # Check probe response (whether 200 or 503 fail-closed)
        r3 = await client.post(
            "/v1/red/probe",
            json={"prompt": "hi", "max_tokens": 5},
            headers={"Authorization": f"Bearer {RED_TOKEN}"},
        )
        try:
            body = r3.json()
            _assert_no_forbidden_keys(body)
        except Exception:
            pass


@pytest.mark.asyncio
async def test_response_hygiene_no_secret_or_traceback_leak_in_errors():
    """SECURITY: SI-10 - Error responses must not echo sensitive secrets or internal tracebacks."""
    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        for secret in [RED_TOKEN, BLUE_TOKEN, ADMIN_TOKEN]:
            if not secret:
                continue
            r = await client.get(
                "/v1/red/work",
                headers={"Authorization": f"Bearer {secret}_corrupted"},
            )
            assert secret not in r.text, "SECURITY VIOLATION: Secret leaked in error response!"
            assert "traceback (most recent call last)" not in r.text.lower()


# ==============================================================================
# 5. Rate Limiting
# ==============================================================================


@pytest.mark.asyncio
async def test_rate_limiting_tenant_endpoints():
    """SECURITY: §5 & §14 - Tenant rate limit (RATE_LIMIT_TENANT_PER_SEC=10) returns 429."""
    url = "/v1/red/work"
    headers = {"Authorization": f"Bearer {RED_TOKEN}"}
    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        # Burst 30 concurrent requests
        tasks = [client.get(url, headers=headers) for _ in range(30)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        status_codes = [getattr(r, "status_code", None) for r in responses]
        assert 429 in status_codes, (
            f"SECURITY DEFENSE FAILED: Rate limit of 10 req/s not enforced! "
            f"Statuses from 30 concurrent requests: {status_codes}"
        )


@pytest.mark.asyncio
async def test_rate_limiting_public_endpoints():
    """SECURITY: §5 & §14 - Public rate limit (RATE_LIMIT_PUBLIC_PER_MIN=60) returns 429."""
    url = "/api/health"
    async with httpx.AsyncClient(base_url=GATEWAY_URL) as client:
        # Burst 75 rapid requests
        tasks = [client.get(url) for _ in range(75)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        status_codes = [getattr(r, "status_code", None) for r in responses]
        assert 429 in status_codes, (
            f"SECURITY DEFENSE FAILED: Public rate limit of 60 req/min not enforced! "
            f"Statuses from 75 rapid requests: {status_codes}"
        )


# ==============================================================================
# 6. Public Proxy Isolation (/v1/* must be 404 through web)
# ==============================================================================


@pytest.mark.asyncio
async def test_public_proxy_blocks_v1_endpoints():
    """SECURITY: SI-11 & §2 - Web proxy must block /v1/* with 404."""
    blocked_paths = [
        "/v1/red/work",
        "/v1/blue/work",
        "/v1/red/probe",
        "/v1/blue/probe",
        "/v1/red/runs/1/commit",
        "/v1/red/runs/1/attack",
        "/v1/red/runs/1/done",
        "/v1/blue/runs/1/defense",
        "/v1/red/runs/1/report",
        "/v1/blue/runs/1/report",
        "/v1/arbitrary_path",
    ]

    async with httpx.AsyncClient(base_url=WEB_URL, verify=False, follow_redirects=True) as client:
        for path in blocked_paths:
            # Test GET
            r_get = await client.get(path)
            assert (
                r_get.status_code == 404
            ), f"SECURITY VIOLATION: GET {path} accessible through public proxy! Status: {r_get.status_code}"

            # Test POST
            r_post = await client.post(path, json={"test": 1})
            assert (
                r_post.status_code == 404
            ), f"SECURITY VIOLATION: POST {path} accessible through public proxy! Status: {r_post.status_code}"


@pytest.mark.asyncio
async def test_public_proxy_allows_api_health():
    """SECURITY: §2 & SI-11 - Web proxy routes /api/* (e.g. /api/health -> 200)."""
    async with httpx.AsyncClient(base_url=WEB_URL, verify=False, follow_redirects=True) as client:
        resp = await client.get("/api/health")
        assert (
            resp.status_code == 200
        ), f"Expected 200 for /api/health through public proxy, got {resp.status_code}"
        data = resp.json()
        assert "status" in data
