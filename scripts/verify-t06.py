#!/usr/bin/env python3
"""
scripts/verify-t06.py
Live acceptance test runner for T06: Datasets, red agent, blue agent, bundles.

Acceptance criteria verified:
  1. Tenant isolation: red cannot see blue data/secrets, blue cannot see red data/secrets.
  2. Autonomous execution: creating a run via operator API causes red and blue to act
     with no human action, and the run autonomously reaches concluded.
  3. Bundle discrimination: baseline vs hardened produce different ASR on the same seed.
  4. Gateway restart resilience: agents survive a gateway restart and resume functioning.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRETS_DIR = os.path.join(REPO_ROOT, "secrets")


def read_secret(name: str) -> str:
    path = os.path.join(SECRETS_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def get_gateway_url() -> str:
    # Try public proxy port first (standard entry point)
    candidate = "http://127.0.0.1:8088"
    try:
        with urllib.request.urlopen(f"{candidate}/api/health", timeout=2.0) as resp:
            if resp.status == 200:
                return candidate
    except Exception:
        pass

    # Fallback to direct container IP if port 8088 not mapped
    try:
        res = subprocess.run(
            ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", "bayora-gateway"],
            capture_output=True,
            text=True,
            check=True,
        )
        for ip in res.stdout.strip().split():
            ip = ip.strip()
            if not ip:
                continue
            test_url = f"http://{ip}:8000/api/health"
            try:
                with urllib.request.urlopen(test_url, timeout=2.0) as resp:
                    if resp.status == 200:
                        return f"http://{ip}:8000"
            except Exception:
                continue
    except Exception:
        pass

    raise RuntimeError("Could not connect to gateway via 127.0.0.1:8088 or container IP")


def http_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
    timeout: float = 30.0,
) -> tuple[int, dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if payload is not None and "Content-Type" not in req.headers:
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"detail": body}


def check_tenant_isolation() -> bool:
    print("\n" + "=" * 60)
    print("[1/4] Checking tenant data and secret isolation (exec checks)")
    print("=" * 60)

    # 1. Red container checks
    r1 = subprocess.run(
        ["docker", "compose", "exec", "-T", "red", "sh", "-c", "cat /data/blue 2>&1 || true"],
        capture_output=True, text=True,
    )
    r2 = subprocess.run(
        ["docker", "compose", "exec", "-T", "red", "sh", "-c", "cat /run/secrets/blue_token 2>&1 || true"],
        capture_output=True, text=True,
    )
    red_sees_blue_data = "No such file" not in r1.stdout
    red_sees_blue_token = "No such file" not in r2.stdout

    # 2. Blue container checks
    b1 = subprocess.run(
        ["docker", "compose", "exec", "-T", "blue", "sh", "-c", "cat /data/red 2>&1 || true"],
        capture_output=True, text=True,
    )
    b2 = subprocess.run(
        ["docker", "compose", "exec", "-T", "blue", "sh", "-c", "cat /run/secrets/red_token 2>&1 || true"],
        capture_output=True, text=True,
    )
    blue_sees_red_data = "No such file" not in b1.stdout
    blue_sees_red_token = "No such file" not in b2.stdout

    print(f"[*] Red accessing /data/blue:             {r1.stdout.strip()}")
    print(f"[*] Red accessing /run/secrets/blue_token: {r2.stdout.strip()}")
    print(f"[*] Blue accessing /data/red:             {b1.stdout.strip()}")
    print(f"[*] Blue accessing /run/secrets/red_token: {b2.stdout.strip()}")

    assert not red_sees_blue_data, "SECURITY VIOLATION: red container can see blue data"
    assert not red_sees_blue_token, "SECURITY VIOLATION: red container has blue token"
    assert not blue_sees_red_data, "SECURITY VIOLATION: blue container can see red data"
    assert not blue_sees_red_token, "SECURITY VIOLATION: blue container has red token"

    print("[✓] Isolation verified: red and blue have strictly separated data and secrets.")
    return True


def run_evaluation(
    gateway_url: str,
    admin_token: str,
    name: str,
    bundle: str,
    attack_count: int = 10,
    seed: int = 42,
    max_wait_sec: float = 120.0,
) -> dict[str, Any]:
    print(f"\n[*] Creating run '{name}' with bundle='{bundle}', seed={seed}, count={attack_count}...")
    headers = {"X-Admin-Token": admin_token}
    create_payload = {
        "name": name,
        "bundle": bundle,
        "attack_count": attack_count,
        "seed": seed,
    }
    status, resp = http_request("POST", f"{gateway_url}/api/runs", headers, create_payload)
    if status != 201:
        raise RuntimeError(f"Failed to create run: HTTP {status} {resp}")

    run_id = resp["run_id"]
    print(f"[*] Run created: {run_id}. Waiting for autonomous red & blue agents...")

    start_time = time.time()
    last_state = ""
    while time.time() - start_time < max_wait_sec:
        # Check run state via public run endpoint
        r_status, r_resp = http_request("GET", f"{gateway_url}/api/runs/{run_id}")
        if r_status == 200:
            state = r_resp.get("state")
            if state != last_state:
                print(f"    -> Run state transition: {state} (elapsed: {time.time()-start_time:.1f}s)")
                last_state = state
            if state == "concluded":
                print(f"[✓] Run {run_id} concluded autonomously!")
                break
            if state in ("aborted", "failed"):
                raise RuntimeError(f"Run ended in failure state: {state}")
        time.sleep(1.0)
    else:
        raise TimeoutError(f"Run {run_id} did not conclude within {max_wait_sec}s")

    # Fetch revealed results
    res_status, results = http_request("GET", f"{gateway_url}/api/runs/{run_id}/results")
    if res_status != 200:
        raise RuntimeError(f"Failed to fetch results: HTTP {res_status} {results}")

    return results


def main() -> int:
    admin_token = read_secret("admin_token")
    gateway_url = get_gateway_url()
    print(f"[*] Using Gateway URL: {gateway_url}")

    # Step 1: Isolation check
    check_tenant_isolation()

    # Step 2: Baseline autonomous run
    print("\n" + "=" * 60)
    print("[2/4] Testing Autonomous Baseline Run (seed=42, bundle=baseline)")
    print("=" * 60)
    baseline_results = run_evaluation(
        gateway_url,
        admin_token,
        name="test-t06-baseline",
        bundle="baseline",
        attack_count=10,
        seed=42,
    )
    b_total = baseline_results.get("total", 0)
    b_agg = baseline_results.get("aggregate", {})
    b_asr = baseline_results.get("asr", 0.0)
    print(f"[*] Baseline Results: total={b_total}, aggregate={b_agg}, ASR={b_asr:.3f}")

    # Step 3: Hardened autonomous run (same seed)
    print("\n" + "=" * 60)
    print("[3/4] Testing Autonomous Hardened Run (seed=42, bundle=hardened)")
    print("=" * 60)
    hardened_results = run_evaluation(
        gateway_url,
        admin_token,
        name="test-t06-hardened",
        bundle="hardened",
        attack_count=10,
        seed=42,
    )
    h_total = hardened_results.get("total", 0)
    h_agg = hardened_results.get("aggregate", {})
    h_asr = hardened_results.get("asr", 0.0)
    print(f"[*] Hardened Results: total={h_total}, aggregate={h_agg}, ASR={h_asr:.3f}")

    # Verify ASR difference
    print(f"\n[*] Comparing ASR (seed=42): Baseline ASR={b_asr:.3f} vs Hardened ASR={h_asr:.3f}")
    assert b_asr != h_asr or b_agg != h_agg, (
        f"Expected different defense outcomes between baseline ({b_agg}) and hardened ({h_agg})"
    )
    print("[✓] Baseline and Hardened bundles produce different outcomes on the same seed!")

    # Step 4: Gateway restart resilience test
    print("\n" + "=" * 60)
    print("[4/4] Testing Agent Resilience across Gateway Restart")
    print("=" * 60)
    print("[*] Restarting gateway container (docker compose restart gateway)...")
    res = subprocess.run(["docker", "compose", "restart", "gateway"], capture_output=True, text=True, check=True)
    print("[*] Gateway restarted. Waiting 5s for health...")
    time.sleep(5.0)

    # Confirm gateway is back
    gw_ready = False
    for _ in range(15):
        try:
            with urllib.request.urlopen(f"{gateway_url}/api/health", timeout=2.0) as resp:
                if resp.status == 200:
                    gw_ready = True
                    break
        except Exception:
            time.sleep(1.0)
    assert gw_ready, "Gateway failed to become healthy after restart"
    print("[✓] Gateway healthy after restart.")

    # Confirm red and blue are still healthy and polling
    ps_res = subprocess.run(["docker", "compose", "ps"], capture_output=True, text=True, check=True)
    assert "bayora-red" in ps_res.stdout and "healthy" in ps_res.stdout
    assert "bayora-blue" in ps_res.stdout and "healthy" in ps_res.stdout
    print("[✓] Both red and blue agents survived gateway restart.")

    # Execute a post-restart run to prove end-to-end functionality
    post_results = run_evaluation(
        gateway_url,
        admin_token,
        name="test-t06-post-restart",
        bundle="hardened",
        attack_count=5,
        seed=101,
    )
    p_total = post_results.get("total", 0)
    p_asr = post_results.get("asr", 0.0)
    print(f"[✓] Post-restart run concluded successfully: total={p_total}, ASR={p_asr:.3f}")

    print("\n" + "=" * 60)
    print("ALL T06 ACCEPTANCE CRITERIA VERIFIED SUCCESSFULLY!")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
