"""
blue/agent.py
Autonomous Blue-Team Agent for Bayora.

Architecture references: §5, §6, §7, §2, §4
Task reference: T06 (prompt P-06)

SECURITY INVARIANTS ENFORCED:
  SI-01..SI-03: Runs unprivileged (10001:10001), read-only rootfs, internal blue-net only.
  SI-04: Only talks to the gateway at http://gateway:8000; never to model, logger, or internet.
  SI-05/SI-10: Reads token from /run/secrets/blue_token; never logs or prints tokens.
  SI-09: Defense bundles are purely declarative JSON data; never executed.
  SI-10: Reads defense bundles from /data/bundles (mounted read-only).
"""
from __future__ import annotations

import http.server
import json
import logging
import os
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","name":"%(name)s","level":"%(levelname)s","message":%(message)s}',
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("blue.agent")

# Configuration via environment and secrets
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://gateway:8000").rstrip("/")
SECRETS_DIR = os.getenv("SECRETS_DIR", "/run/secrets")
SERVICE_PORT = int(os.getenv("SERVICE_PORT", "8000"))
POLL_INTERVAL_SEC = float(os.getenv("POLL_INTERVAL_SEC", "1.5"))

BUNDLE_SEARCH_DIRS = [
    "/data/bundles",
    "/data/blue/bundles",
    "/data",
    os.path.join(os.path.dirname(__file__), "..", "data", "blue", "bundles"),
]


def load_token() -> str:
    """Read blue tenant token from secrets or env."""
    token_file = os.path.join(SECRETS_DIR, "blue_token")
    if os.path.isfile(token_file):
        with open(token_file, "r", encoding="utf-8") as f:
            return f.read().strip()
    env_token = os.getenv("BLUE_TOKEN")
    if env_token:
        return env_token.strip()
    raise RuntimeError("Blue token not found in /run/secrets/blue_token or BLUE_TOKEN env")


def load_bundle(bundle_name: str) -> dict[str, Any]:
    """
    Load named defense bundle JSON from read-only mount (§4, §7).
    SECURITY SI-09: Loaded as plain JSON data, never evaluated or executed.
    """
    # Normalize name (e.g. baseline or hardened)
    filename = f"{bundle_name}.json" if not bundle_name.endswith(".json") else bundle_name

    for base_dir in BUNDLE_SEARCH_DIRS:
        candidate = os.path.join(base_dir, filename)
        if os.path.isfile(candidate):
            with open(candidate, "r", encoding="utf-8") as f:
                data = json.load(f)
                log.info(json.dumps({"event": "bundle_loaded", "name": bundle_name, "path": candidate}))
                return data

    raise FileNotFoundError(f"Defense bundle '{bundle_name}' not found in search dirs: {BUNDLE_SEARCH_DIRS}")


# ── Health server for container healthchecks ──────────────────────────────────
class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path in ("/health", "/"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = {"status": "ok", "service": "blue"}
            self.wfile.write(json.dumps(payload).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        pass


def start_health_server(port: int) -> http.server.ThreadingHTTPServer:
    """Start HTTP health check endpoint on background thread."""
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ── Gateway HTTP helper ───────────────────────────────────────────────────────
def gateway_request(
    method: str,
    path: str,
    token: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 30.0,
) -> tuple[int, dict[str, Any] | None]:
    """
    Execute HTTP request to gateway.
    SECURITY SI-04: Only talks to the gateway; never to any other host.
    """
    url = f"{GATEWAY_URL}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    # SECURITY SI-05: Authenticate using Bearer token
    req.add_header("Authorization", f"Bearer {token}")
    if payload is not None:
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"detail": body}
        return e.code, parsed
    except Exception as exc:
        log.warning(json.dumps({"event": "gateway_connection_error", "path": path, "error": str(exc)}))
        return 0, None


# ── Main agent polling loop ───────────────────────────────────────────────────
def run_agent() -> None:
    token = load_token()

    # Track per-run lifecycle state in memory
    runs_state: dict[str, dict[str, Any]] = {}
    running = True

    def handle_signal(sig: int, frame: Any) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    log.info(json.dumps({"event": "blue_agent_started", "gateway": GATEWAY_URL}))

    while running:
        try:
            status, resp = gateway_request("GET", "/v1/blue/work", token)
            if status == 200 and resp and resp.get("run"):
                run_data = resp["run"]
                run_id = run_data["run_id"]
                state = run_data["state"]
                params = run_data.get("params", {})

                if run_id not in runs_state:
                    runs_state[run_id] = {
                        "defense_uploaded": False,
                        "report_fetched": False,
                    }

                b_state = runs_state[run_id]

                # Step 1: Upload defense bundle if created/committing and not yet uploaded
                if state in ("created", "committing") and not b_state["defense_uploaded"]:
                    bundle_name = params.get("bundle", "baseline")
                    try:
                        bundle_data = load_bundle(bundle_name)
                        put_status, put_resp = gateway_request(
                            "PUT",
                            f"/v1/blue/runs/{run_id}/defense",
                            token,
                            {"bundle": bundle_data},
                        )
                        if put_status in (200, 201):
                            b_state["defense_uploaded"] = True
                            bundle_digest = put_resp.get("bundle_digest") if put_resp else "unknown"
                            log.info(json.dumps({
                                "event": "blue_defense_uploaded",
                                "run_id": run_id,
                                "bundle": bundle_name,
                                "digest": bundle_digest,
                            }))
                        elif put_status == 409:
                            # Already committed
                            b_state["defense_uploaded"] = True
                        else:
                            log.warning(json.dumps({
                                "event": "defense_upload_failed",
                                "run_id": run_id,
                                "status": put_status,
                                "detail": put_resp,
                            }))
                    except Exception as err:
                        log.error(json.dumps({
                            "event": "bundle_load_error",
                            "run_id": run_id,
                            "bundle": bundle_name,
                            "error": str(err),
                        }))

                # Step 2: Fetch blue report when run concludes (§5)
                elif state == "concluded" and not b_state["report_fetched"]:
                    r_status, r_resp = gateway_request(
                        "GET",
                        f"/v1/blue/runs/{run_id}/report",
                        token,
                    )
                    if r_status == 200:
                        b_state["report_fetched"] = True
                        log.info(json.dumps({
                            "event": "blue_report_fetched",
                            "run_id": run_id,
                            "attacks_count": len(r_resp.get("attacks", [])) if r_resp else 0,
                        }))

        except Exception as exc:
            log.warning(json.dumps({"event": "polling_loop_error", "error": str(exc)}))

        time.sleep(POLL_INTERVAL_SEC)

    log.info(json.dumps({"event": "blue_agent_stopped"}))


def main() -> None:
    # Start container healthcheck server on background thread
    start_health_server(SERVICE_PORT)
    # Run the long-running agent polling loop
    run_agent()


if __name__ == "__main__":
    main()
