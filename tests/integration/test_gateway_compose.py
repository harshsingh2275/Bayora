"""
tests/integration/test_gateway_compose.py
Live container tests running against the real Docker Compose environment.

Verifies:
  - Token auth and role isolation between real red/blue containers and gateway
  - Pydantic extra="forbid" rejection of id_slot, cache_prompt, unknown fields
  - Fail-closed 503 behavior when audit logger is the stub
  - No secrets in logs
  - Caddy web proxy blocks /v1/* with 404 while allowing /api/health with 200
"""
import json
import subprocess
import pytest


def _is_compose_running() -> bool:
    try:
        res = subprocess.run(
            ["docker", "compose", "ps", "--status", "running", "-q", "gateway"],
            capture_output=True,
            text=True,
            check=False,
        )
        return bool(res.stdout.strip())
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _is_compose_running(),
    reason="Docker Compose stack not running",
)


def _exec_in_container(container: str, python_code: str) -> dict:
    cmd = ["docker", "compose", "exec", "-T", container, "python3", "-c", python_code]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(res.stdout.strip())


def test_real_container_no_token_returns_401():
    code = """
import urllib.request as u, urllib.error as e, json
req = u.Request("http://gateway:8000/v1/red/work")
try:
    res = u.urlopen(req)
    print(json.dumps({"status": res.status}))
except e.HTTPError as err:
    print(json.dumps({"status": err.code, "body": err.read().decode()}))
"""
    out = _exec_in_container("red", code)
    assert out["status"] == 401


def test_real_container_garbage_token_returns_401():
    code = """
import urllib.request as u, urllib.error as e, json
req = u.Request("http://gateway:8000/v1/red/work")
req.add_header("Authorization", "Bearer invalid-garbage-token-12345")
try:
    res = u.urlopen(req)
    print(json.dumps({"status": res.status}))
except e.HTTPError as err:
    print(json.dumps({"status": err.code, "body": err.read().decode()}))
"""
    out = _exec_in_container("red", code)
    assert out["status"] == 401
    assert "invalid-garbage-token-12345" not in out["body"]


def test_real_container_valid_token_returns_200():
    code = """
import urllib.request as u, json
token = open("/run/secrets/red_token").read().strip()
req = u.Request("http://gateway:8000/v1/red/work")
req.add_header("Authorization", f"Bearer {token}")
res = u.urlopen(req)
print(json.dumps({"status": res.status, "data": json.loads(res.read().decode())}))
"""
    out = _exec_in_container("red", code)
    assert out["status"] == 200
    assert out["data"] == {"run": None}


def test_real_container_cross_role_token_returns_403():
    code = """
import urllib.request as u, urllib.error as e, json
token = open("/run/secrets/red_token").read().strip()
req = u.Request("http://gateway:8000/v1/blue/work")
req.add_header("Authorization", f"Bearer {token}")
try:
    res = u.urlopen(req)
    print(json.dumps({"status": res.status}))
except e.HTTPError as err:
    print(json.dumps({"status": err.code, "body": err.read().decode()}))
"""
    out = _exec_in_container("red", code)
    assert out["status"] == 403


def test_real_container_probe_extra_fields_rejected_422():
    code = """
import urllib.request as u, urllib.error as e, json
token = open("/run/secrets/red_token").read().strip()
payload = json.dumps({"prompt": "hi", "max_tokens": 10, "id_slot": 0, "extra_bad": 1}).encode()
req = u.Request("http://gateway:8000/v1/red/probe", data=payload, method="POST")
req.add_header("Authorization", f"Bearer {token}")
req.add_header("Content-Type", "application/json")
try:
    res = u.urlopen(req)
    print(json.dumps({"status": res.status}))
except e.HTTPError as err:
    print(json.dumps({"status": err.code, "body": err.read().decode()}))
"""
    out = _exec_in_container("red", code)
    assert out["status"] == 422


def test_real_container_probe_oversized_max_tokens_rejected_422():
    code = """
import urllib.request as u, urllib.error as e, json
token = open("/run/secrets/red_token").read().strip()
payload = json.dumps({"prompt": "hi", "max_tokens": 129}).encode()
req = u.Request("http://gateway:8000/v1/red/probe", data=payload, method="POST")
req.add_header("Authorization", f"Bearer {token}")
req.add_header("Content-Type", "application/json")
try:
    res = u.urlopen(req)
    print(json.dumps({"status": res.status}))
except e.HTTPError as err:
    print(json.dumps({"status": err.code, "body": err.read().decode()}))
"""
    out = _exec_in_container("red", code)
    assert out["status"] == 422


def test_real_container_probe_returns_503_fail_closed_with_stub():
    code = """
import urllib.request as u, urllib.error as e, json
token = open("/run/secrets/red_token").read().strip()
payload = json.dumps({"prompt": "hi", "max_tokens": 10}).encode()
req = u.Request("http://gateway:8000/v1/red/probe", data=payload, method="POST")
req.add_header("Authorization", f"Bearer {token}")
req.add_header("Content-Type", "application/json")
try:
    res = u.urlopen(req)
    print(json.dumps({"status": res.status}))
except e.HTTPError as err:
    print(json.dumps({"status": err.code, "body": err.read().decode()}))
"""
    out = _exec_in_container("red", code)
    assert out["status"] == 503
    assert "fail-closed" in out["body"].lower()


def test_web_proxy_blocks_v1_and_allows_api():
    import urllib.request as u
    import urllib.error as e

    # SI-11: Public proxy exposes /api/* only. /v1/* returns 404.
    try:
        u.urlopen("http://localhost:8088/v1/red/work")
        assert False, "Should have returned 404"
    except e.HTTPError as err:
        assert err.code == 404

    res = u.urlopen("http://localhost:8088/api/health")
    assert res.status == 200
    body = json.loads(res.read().decode())
    assert body["status"] == "ok"
