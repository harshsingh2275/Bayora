#!/usr/bin/env bash
# scripts/seed-real-run.sh: Seed real evaluation runs (baseline and hardened) through the operator API
# Architecture references: §5, §6, §7
# Task reference: T12 (Production deployment)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Usage information
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --url URL           Target API base URL (default: auto-detected)"
    echo "  --token TOKEN       Operator admin token (default: read from secrets/admin_token)"
    echo "  --count COUNT       Number of attacks per run (default: 5)"
    echo "  --seed SEED         Random seed for deterministic attack sampling (default: 42)"
    echo "  --timeout SECONDS   Maximum wait time per run in seconds (default: 180)"
    echo "  -h, --help          Show this help message"
    exit 0
fi

export REPO_ROOT

# Run via python inline for portable HTTP, SSL, and JSON processing
exec python3 - "$@" << 'EOF'
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Any

REPO_ROOT = os.getenv("REPO_ROOT", os.getcwd())
SECRETS_DIR = os.path.join(REPO_ROOT, "secrets")

# Parse CLI arguments
cli_args = sys.argv[1:]
target_url = None
admin_token = None
attack_count = 5
seed_val = 42
timeout_sec = 180.0

i = 0
while i < len(cli_args):
    arg = cli_args[i]
    if arg == "--url" and i + 1 < len(cli_args):
        target_url = cli_args[i + 1]
        i += 2
    elif arg == "--token" and i + 1 < len(cli_args):
        admin_token = cli_args[i + 1]
        i += 2
    elif arg == "--count" and i + 1 < len(cli_args):
        attack_count = int(cli_args[i + 1])
        i += 2
    elif arg == "--seed" and i + 1 < len(cli_args):
        seed_val = int(cli_args[i + 1])
        i += 2
    elif arg == "--timeout" and i + 1 < len(cli_args):
        timeout_sec = float(cli_args[i + 1])
        i += 2
    else:
        i += 1

# Load admin token if not passed
if not admin_token:
    admin_token_file = os.path.join(SECRETS_DIR, "admin_token")
    if os.path.isfile(admin_token_file):
        with open(admin_token_file, "r", encoding="utf-8") as f:
            admin_token = f.read().strip()
    elif os.getenv("ADMIN_TOKEN"):
        admin_token = os.getenv("ADMIN_TOKEN", "").strip()

if not admin_token:
    print("ERROR: Admin token not found in secrets/admin_token or ADMIN_TOKEN env var.", file=sys.stderr)
    sys.exit(1)

# Insecure SSL context for local/self-signed testing against localhost
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE


def probe_health(url: str) -> bool:
    try:
        req = urllib.request.Request(f"{url.rstrip('/')}/api/health", method="GET")
        with urllib.request.urlopen(req, timeout=3.0, context=ssl_ctx) as resp:
            return resp.status == 200
    except Exception:
        return False


# Determine base URL
if not target_url:
    env_domain = os.getenv("DOMAIN")
    candidates = []
    if env_domain:
        candidates.append(f"https://{env_domain}")
        candidates.append(f"http://{env_domain}")
    candidates.extend([
        "https://localhost",
        "http://localhost",
        "http://127.0.0.1:8088",
        "http://127.0.0.1:8000",
    ])
    for c in candidates:
        if probe_health(c):
            target_url = c
            break

if not target_url:
    print("ERROR: Could not connect to Bayora API on any candidate URL.", file=sys.stderr)
    print("Ensure the stack is running (`make prod-up` or `make up`).", file=sys.stderr)
    sys.exit(1)

base_url = target_url.rstrip("/")
print("=" * 70)
print("Bayora Evaluation Seeder (T12 Production)")
print(f"Target API:    {base_url}")
print(f"Attack Count:  {attack_count}")
print(f"Random Seed:   {seed_val}")
print(f"Max Timeout:   {timeout_sec}s")
print("=" * 70)


def http_call(method: str, path: str, headers: dict[str, str] | None = None, payload: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    url = f"{base_url}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if payload is not None and "Content-Type" not in req.headers:
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=timeout_sec, context=ssl_ctx) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"detail": body}


def run_bundle(name: str, bundle: str, count: int, seed: int) -> dict[str, Any]:
    print(f"\n[+] Seeding run: '{name}' (bundle={bundle}, attacks={count}, seed={seed})")

    # Check for active run
    status, runs_data = http_call("GET", "/api/runs")
    if status == 200:
        active = [r for r in runs_data.get("runs", []) if r.get("state") not in ("concluded", "aborted", "failed")]
        if active:
            active_id = active[0].get("run_id")
            print(f"    [!] Prior active run detected ({active_id}). Waiting for completion...")
            start_wait = time.time()
            while time.time() - start_wait < 60:
                s, d = http_call("GET", f"/api/runs/{active_id}")
                if s == 200 and d.get("state") in ("concluded", "aborted", "failed"):
                    print(f"    [✓] Prior run completed with state: {d.get('state')}")
                    break
                time.sleep(2)

    # 1. Create run through operator API
    create_headers = {"X-Admin-Token": admin_token}
    create_body = {
        "name": name,
        "bundle": bundle,
        "attack_count": count,
        "seed": seed,
    }
    status, resp = http_call("POST", "/api/runs", headers=create_headers, payload=create_body)
    if status != 201:
        raise RuntimeError(f"Run creation failed (HTTP {status}): {resp}")

    run_id = resp["run_id"]
    print(f"    Run created: {run_id}")
    print("    Waiting for autonomous red and blue agents to execute...")

    start_time = time.time()
    last_state = ""
    while time.time() - start_time < timeout_sec:
        status, detail = http_call("GET", f"/api/runs/{run_id}")
        if status == 200:
            state = detail.get("state")
            if state != last_state:
                elapsed = time.time() - start_time
                print(f"    -> State transition: {state} (+{elapsed:.1f}s)")
                last_state = state
            if state == "concluded":
                elapsed = time.time() - start_time
                print(f"    [✓] Run concluded successfully in {elapsed:.1f}s")
                break
            if state in ("aborted", "failed"):
                raise RuntimeError(f"Run ended in failure state: {state}")
        time.sleep(1.5)
    else:
        raise TimeoutError(f"Run {run_id} did not conclude within {timeout_sec}s")

    # Fetch revealed results
    status, results = http_call("GET", f"/api/runs/{run_id}/results")
    if status == 200:
        agg = results.get("aggregate", {})
        total = results.get("total", count)
        asr = results.get("asr", 0.0)
        complied = agg.get("complied", 0)
        blocked_in = agg.get("blocked_input", 0)
        blocked_out = agg.get("blocked_output", 0)
        refused = agg.get("refused", 0)
        print(f"    Results: Total={total}, Complied={complied}, Blocked(In)={blocked_in}, "
              f"Blocked(Out)={blocked_out}, Refused={refused}, ASR={asr:.1%}")
        return {"run_id": run_id, "total": total, "aggregate": agg, "asr": asr}
    else:
        return {"run_id": run_id, "detail": detail}


# 1. Run baseline
res_baseline = run_bundle(
    name=f"prod-baseline-seed-{int(time.time())}",
    bundle="baseline",
    count=attack_count,
    seed=seed_val,
)

# Small cooldown between runs
time.sleep(2)

# 2. Run hardened
res_hardened = run_bundle(
    name=f"prod-hardened-seed-{int(time.time())}",
    bundle="hardened",
    count=attack_count,
    seed=seed_val,
)

print("\n" + "=" * 70)
print("Seeding Complete: Summary of Real Runs")
print("=" * 70)
b_asr = res_baseline.get("asr", "N/A")
h_asr = res_hardened.get("asr", "N/A")
print(f"Baseline Run:  ID={res_baseline.get('run_id')} | ASR={b_asr if isinstance(b_asr, str) else f'{b_asr:.1%}'}")
print(f"Hardened Run:  ID={res_hardened.get('run_id')} | ASR={h_asr if isinstance(h_asr, str) else f'{h_asr:.1%}'}")
print("=" * 70)
EOF
