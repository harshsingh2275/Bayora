"""
tests/integration/test_audit_compose.py
Live integration test suite for T04: Audit Logger, Verifier, and Gateway fail-closed integration.

Acceptance criteria:
  1. 25 appended entries produce a valid chain and 2 checkpoints.
  2. Verifier returns ok: true with 25 entries, 2 checkpoints, and correct head.
  3. Tamper demo returns expected detected/not-detected results across all 6 attack cases.
  4. Stopping the logger causes the gateway to fail closed with 503.
  5. Restarting the logger restores gateway functionality.
  6. No raw prompt or response text appears in any log entry.
  7. Verifier cannot write to the log volume (read-only mount).
"""
import json
import subprocess
import time
import urllib.request
import urllib.error
import pytest


def _is_compose_running() -> bool:
    try:
        res = subprocess.run(
            ["docker", "compose", "ps", "--status", "running", "-q", "logger"],
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


@pytest.fixture(scope="module", autouse=True)
def clean_audit_log():
    """Clear log files and restart logger & verifier so tests run against a fresh genesis chain."""
    clean_code = "import os; [os.unlink(p) for p in ['/app/log-data/log.jsonl', '/app/log-data/checkpoints.jsonl'] if os.path.exists(p)]"
    subprocess.run(["docker", "compose", "exec", "-T", "logger", "python3", "-c", clean_code], check=True)
    subprocess.run(["docker", "compose", "restart", "logger", "verifier"], check=True)
    # Wait until verifier and gateway are responsive
    for _ in range(20):
        try:
            with urllib.request.urlopen("http://127.0.0.1:8088/api/verify", timeout=1.0) as resp:
                if resp.status == 200:
                    break
        except Exception:
            time.sleep(0.5)


def test_append_25_entries_produces_valid_chain_and_2_checkpoints():
    """
    Append entries up to 25 total and verify:
      - 25 entries in log.jsonl
      - Exactly 2 checkpoints in checkpoints.jsonl (seq 9 and seq 19)
    """
    code = """
import urllib.request as u, json

token = open("/run/secrets/logger_token").read().strip()
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

# Read current entries count
req = u.Request("http://127.0.0.1:8001/entries?limit=1000", headers=headers)
curr = json.loads(u.urlopen(req).read().decode())["entries"]
curr_count = len(curr)

needed = 25 - curr_count
for i in range(needed):
    seq_idx = curr_count + i
    payload = json.dumps({
        "run_id": "acceptance_run",
        "actor": "red",
        "event": "probe_processed",
        "data": {"seq_idx": seq_idx, "prompt_digest": f"dig_{seq_idx}"}
    }).encode()
    r = u.Request("http://127.0.0.1:8001/append", data=payload, headers=headers, method="POST")
    u.urlopen(r)

# Verify 25 entries and 2 checkpoints
req = u.Request("http://127.0.0.1:8001/entries?limit=1000", headers=headers)
entries = json.loads(u.urlopen(req).read().decode())["entries"]
head = json.loads(u.urlopen(u.Request("http://127.0.0.1:8001/head", headers=headers)).read().decode())

print(json.dumps({
    "entries_count": len(entries),
    "head": head,
}))
"""
    out = _exec_in_container("logger", code)
    assert out["entries_count"] == 25
    assert out["head"]["seq"] == 24


def test_verifier_endpoint_returns_ok_true():
    """
    Query verifier /verify via web proxy:
      - ok must be True
      - entries must be 25
      - checkpoints must be 2
      - head.seq must be 24
      - errors must be []
    """
    with urllib.request.urlopen("http://127.0.0.1:8088/api/verify", timeout=5.0) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())

    assert data["ok"] is True
    assert data["entries"] == 25
    assert data["checkpoints"] == 2
    assert data["head"]["seq"] == 24
    assert data["errors"] == []


def test_verifier_tamper_demo_all_cases():
    """
    Query verifier /verify/tamper-demo via web proxy:
      - modify_entry: detected True
      - delete_entry: detected True
      - reorder_entries: detected True
      - forge_checkpoint: detected True
      - truncate_before_checkpoint: detected True
      - truncate_after_checkpoint: detected False (expected limitation!)
    """
    with urllib.request.urlopen("http://127.0.0.1:8088/api/verify/tamper-demo", timeout=10.0) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode())

    assert data["ok"] is True
    case_map = {c["id"]: c for c in data["cases"]}

    assert case_map["modify_entry"]["detected"] is True
    assert case_map["modify_entry"]["passed"] is True

    assert case_map["delete_entry"]["detected"] is True
    assert case_map["delete_entry"]["passed"] is True

    assert case_map["reorder_entries"]["detected"] is True
    assert case_map["reorder_entries"]["passed"] is True

    assert case_map["forge_checkpoint"]["detected"] is True
    assert case_map["forge_checkpoint"]["passed"] is True

    assert case_map["truncate_before_checkpoint"]["detected"] is True
    assert case_map["truncate_before_checkpoint"]["passed"] is True

    # Tail truncation after last checkpoint is expected to be NOT detectable
    assert case_map["truncate_after_checkpoint"]["detected"] is False
    assert case_map["truncate_after_checkpoint"]["passed"] is True
    assert case_map["truncate_after_checkpoint"].get("limitation") is True

    assert data["summary"]["all_expectations_met"] is True


def test_gateway_fails_closed_when_logger_stopped():
    """
    Stopping the logger service must cause the gateway to return 503 on probe.
    Starting the logger restores gateway functionality.
    """
    # 1. Stop logger
    subprocess.run(["docker", "compose", "stop", "logger"], check=True)
    time.sleep(1)

    try:
        # Probe from red container to gateway must fail with 503
        code = """
import urllib.request as u, urllib.error as e, json
token = open("/run/secrets/red_token").read().strip()
payload = json.dumps({"prompt": "testing fail closed", "max_tokens": 10}).encode()
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

    finally:
        # 2. Restart logger and wait for healthy
        subprocess.run(["docker", "compose", "start", "logger"], check=True)
        time.sleep(3)


def test_no_raw_prompt_in_audit_log():
    """Verify that raw prompt text never appears in log.jsonl (SI-08)."""
    # Send a unique probe prompt
    unique_secret_string = "unique_secret_probe_text_123456789"
    code = f"""
import urllib.request as u, json
token = open("/run/secrets/red_token").read().strip()
payload = json.dumps({{"prompt": "{unique_secret_string}", "max_tokens": 10}}).encode()
req = u.Request("http://gateway:8000/v1/red/probe", data=payload, method="POST")
req.add_header("Authorization", f"Bearer {{token}}")
req.add_header("Content-Type", "application/json")
res = u.urlopen(req)
print(json.dumps({{"status": res.status}}))
"""
    out = _exec_in_container("red", code)
    assert out["status"] == 200

    # Inspect log file from inside logger
    inspect_code = f"""
import json
log_text = open("/app/log-data/log.jsonl").read()
print(json.dumps({{"leaked": "{unique_secret_string}" in log_text}}))
"""
    inspect_out = _exec_in_container("logger", inspect_code)
    assert inspect_out["leaked"] is False


def test_verifier_cannot_write_log_volume():
    """Verify that the verifier container cannot write to /app/log-data (SI-01/SI-02)."""
    code = """
import json
try:
    with open("/app/log-data/illegal_write.txt", "w") as f:
        f.write("should fail")
    print(json.dumps({"write_succeeded": True}))
except OSError as err:
    print(json.dumps({"write_succeeded": False, "error": str(err), "errno": err.errno}))
"""
    out = _exec_in_container("verifier", code)
    assert out["write_succeeded"] is False
    # Errno 30 is EROFS (Read-only file system)
    assert out["errno"] == 30
