"""
experiments/timing/run.py
Timing side-channel evaluation of LLM prompt KV-cache reuse across tenants.

Source of Truth:
  - docs/architecture.md (§9, §12)
  - AGENTS.md (§3, §4)
  - docs/verified-notes.md (§3, §4, §5)

Hypothesis & Threat Model (§9):
  In `shared` mode (deliberately weak baseline), both tenants are routed to the
  same model instance (model-red), enabling cross-tenant prompt KV-cache reuse.
  When an attacker prompt shares a prefix with a recent victim prompt, the attacker
  can infer victim prompt contents via faster response latency.
  In `isolated` mode (Bayora default, §9 fallback), the gateway routes red to model-red
  (on internal model-red-net) and blue to model-blue (on internal model-blue-net),
  physically isolating KV-cache across tenants on separate instances and networks.

Protocol (§9):
  1. Warm-up requests; discard.
  2. For each mode in ['shared', 'isolated'] (switched via operator endpoint):
     - For N trials per condition (default N=40 HIT, 40 MISS):
       - Fresh random prefix P_i (~900 words) from seeded RNG, distinct per trial.
       - Victim (blue) sends P_i + " Question A" through /v1/blue/probe (max_tokens=1).
       - Attacker (red) sends through /v1/red/probe (max_tokens=1, temp=0):
         - HIT: P_i + " Question B" (shares victim prefix)
         - MISS: different random prefix P_i' of same length + " Question B"
       - Record client-side wall time (time.perf_counter) of the attacker call.
       - Trial order (HIT vs MISS) is shuffled with a fixed seed.
  3. Per mode compute: n, medians, Mann-Whitney U, p-value, AUC (U / (n1 * n2)),
     median difference.
  4. Pre-registered verdict rule:
     - LEAK DETECTED if p < 0.01 and AUC > 0.8
     - NO LEAK DETECTED otherwise
     Rule is pre-registered and never altered post-hoc.
  5. Post the report (raw samples, stats, environment info, verdicts) to
     POST /api/experiments/timing/report.
"""
from __future__ import annotations

import argparse
import datetime
import json
import logging
import math
import os
import random
import statistics
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.request

# SECURITY: AGENTS.md §4 allows scipy inside experiments/
try:
    from scipy.stats import mannwhitneyu
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("timing_experiment")

# ── Vocabulary for generating natural ~900-word random prefixes ───────────────
_WORD_POOL: list[str] = [
    "algorithm", "analysis", "anomaly", "architecture", "adversary", "artifact",
    "assessment", "asymmetric", "attacker", "attribute", "audit", "authentication",
    "authorization", "availability", "baseline", "behavior", "benchmark", "boundary",
    "buffer", "bundle", "capability", "certificate", "channel", "checkpoint",
    "classification", "client", "cluster", "commitment", "compliance", "compression",
    "computation", "concurrency", "condition", "configuration", "consensus", "constraint",
    "container", "contention", "context", "control", "cryptography", "dataset",
    "defense", "degradation", "delivery", "dependency", "deployment", "detection",
    "deterministic", "device", "differential", "digest", "dimension", "discovery",
    "distribution", "document", "domain", "dynamic", "efficiency", "elevation",
    "encryption", "endpoint", "engineering", "entropy", "environment", "epoch",
    "error", "escalation", "evaluation", "evidence", "execution", "experiment",
    "failure", "feedback", "filesystem", "filtering", "firewall", "framework",
    "frequency", "function", "gateway", "generation", "gradient", "graph",
    "hardware", "harness", "hash", "header", "heuristic", "hierarchy",
    "host", "hybrid", "hypothesis", "identity", "immutable", "implementation",
    "inference", "infrastructure", "injection", "input", "inspection", "instance",
    "instruction", "integrity", "interface", "invariant", "isolation", "iteration",
    "judgment", "kernel", "latency", "layer", "learning", "lifecycle",
    "limit", "linear", "linkage", "locality", "lock", "logger",
    "logging", "loop", "maintenance", "malicious", "management", "manifest",
    "matrix", "measurement", "mechanism", "memory", "message", "metadata",
    "methodology", "metric", "mitigation", "model", "module", "monitor",
    "mutation", "namespace", "network", "neural", "node", "normalization",
    "observation", "operation", "operator", "optimization", "orchestration", "output",
    "packet", "parallel", "parameter", "partition", "payload", "performance",
    "permission", "persistence", "pipeline", "platform", "policy", "prefix",
    "probability", "probe", "process", "prompt", "protocol", "proxy",
    "quantization", "random", "ranking", "rate", "record", "recovery",
    "recurrent", "redirection", "refusal", "regex", "regression", "reliability",
    "reproducibility", "request", "residual", "resilience", "resolution", "resource",
    "response", "restriction", "review", "robustness", "role", "routing",
    "sandbox", "sample", "scale", "scenario", "scheduler", "schema",
    "score", "seccomp", "secret", "security", "segment", "selection",
    "sequence", "server", "session", "shield", "sidechannel", "signature",
    "simulation", "slot", "snapshot", "socket", "software", "source",
    "specification", "stability", "standard", "statistical", "storage", "strategy",
    "structure", "summary", "surface", "surveillance", "system", "table",
    "tamper", "target", "task", "template", "temporal", "tenant",
    "terminal", "testing", "texture", "threshold", "throughput", "timestamp",
    "timing", "token", "tolerance", "topology", "trace", "traffic",
    "transformation", "transition", "transmission", "trigger", "truncate", "trust",
    "unauthorized", "unified", "unprivileged", "validation", "variance", "vector",
    "verdict", "verification", "verifier", "version", "victim", "view",
    "virtual", "volume", "vulnerability", "warmup", "weight", "whitelist",
]


def load_secret(name: str, repo_root: str) -> str:
    """Read a token from environment variable or repo secrets/ directory."""
    env_name = name.upper()
    if os.environ.get(env_name):
        return os.environ[env_name].strip()
    path = os.path.join(repo_root, "secrets", name)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    return ""


def discover_gateway_url(repo_root: str) -> str:
    """
    Find the routable gateway container URL for tenant /v1/* endpoints.
    Priority:
      1. GATEWAY_URL env var
      2. Direct docker inspect on bayora-gateway across its attached networks
      3. Fallback http://127.0.0.1:8000
    """
    if os.environ.get("GATEWAY_URL"):
        return os.environ["GATEWAY_URL"].rstrip("/")

    try:
        res = subprocess.run(
            ["docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", "bayora-gateway"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
        if res.returncode == 0 and res.stdout.strip():
            nets = json.loads(res.stdout.strip())
            # Prioritize front-net if available
            ordered_keys = sorted(nets.keys(), key=lambda k: 0 if "front" in k else 1)
            for net_name in ordered_keys:
                ip = nets[net_name].get("IPAddress")
                if not ip:
                    continue
                test_url = f"http://{ip}:8000/api/health"
                try:
                    req = urllib.request.Request(test_url)
                    with urllib.request.urlopen(req, timeout=1.0) as resp:
                        if resp.status == 200:
                            return f"http://{ip}:8000"
                except Exception:
                    continue
    except Exception as exc:
        log.debug(f"Docker inspect discovery failed: {exc}")

    return "http://127.0.0.1:8000"


def generate_prefix(rng: random.Random, word_count: int = 900) -> str:
    """Generate a distinct pseudo-random text prefix of ~word_count words."""
    words = rng.choices(_WORD_POOL, k=word_count)
    return " ".join(words)


def http_request_json(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    payload: Optional[Dict[str, Any]] = None,
    timeout: float = 60.0,
) -> Tuple[int, Dict[str, Any]]:
    """Send an HTTP request and return (status_code, response_json)."""
    hdrs = dict(headers or {})
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        hdrs["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8")
        try:
            return err.code, json.loads(body) if body else {}
        except Exception:
            return err.code, {"error": body}


def set_gateway_cache_mode(
    base_url: str,
    mode: str,
    admin_token: str,
) -> bool:
    """Switch cache mode (isolated | shared) via the operator endpoint."""
    url = f"{base_url}/api/admin/cache-mode"
    headers = {"X-Admin-Token": admin_token}
    status, body = http_request_json(
        url,
        method="POST",
        headers=headers,
        payload={"mode": mode},
        timeout=10.0,
    )
    if status == 200 and body.get("mode") == mode:
        log.info(f"Gateway cache mode switched to: {mode}")
        return True
    log.error(f"Failed to set cache mode to {mode}: HTTP {status} {body}")
    return False


def get_gateway_cache_mode(base_url: str) -> str:
    """Get current cache mode from the public API."""
    url = f"{base_url}/api/cache-mode"
    status, body = http_request_json(url, method="GET", timeout=5.0)
    if status == 200:
        return body.get("mode", "")
    return ""


def send_probe(
    gateway_url: str,
    role: str,
    token: str,
    prompt: str,
    max_tokens: int = 1,
    timeout: float = 90.0,
) -> Tuple[float, int, str]:
    """
    Send probe request to /v1/{role}/probe and measure client-side wall time.
    Returns (latency_ms, status_code, text).
    """
    url = f"{gateway_url}/v1/{role}/probe"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {
        "prompt": prompt,
        "max_tokens": max_tokens,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            t1 = time.perf_counter()
            latency_ms = (t1 - t0) * 1000.0
            parsed = json.loads(raw)
            return latency_ms, resp.status, parsed.get("text", "")
    except urllib.error.HTTPError as err:
        t1 = time.perf_counter()
        latency_ms = (t1 - t0) * 1000.0
        return latency_ms, err.code, ""
    except Exception as exc:
        t1 = time.perf_counter()
        latency_ms = (t1 - t0) * 1000.0
        log.warning(f"Probe error on {role}: {exc}")
        return latency_ms, 0, ""


def _pure_python_mannwhitneyu(
    x_samples: list[float],
    y_samples: list[float],
) -> Tuple[float, float, float]:
    """
    Exact pure-Python Mann-Whitney U test with asymptotic normal approximation
    and AUC computation.
    Used as reliable fallback when scipy is not installed.
    Tests if x > y (i.e. MISS latencies tend to exceed HIT latencies).
    """
    n1 = len(x_samples)
    n2 = len(y_samples)
    if n1 == 0 or n2 == 0:
        return 0.0, 1.0, 0.5

    # Count pairs where x > y (+ 0.5 for ties)
    u1 = 0.0
    for x in x_samples:
        for y in y_samples:
            if x > y:
                u1 += 1.0
            elif x == y:
                u1 += 0.5

    auc = u1 / (n1 * n2)

    # Normal approximation with continuity correction
    mu_u = (n1 * n2) / 2.0
    sigma_u = math.sqrt((n1 * n2 * (n1 + n2 + 1)) / 12.0)
    if sigma_u > 0:
        z = (abs(u1 - mu_u) - 0.5) / sigma_u
        # Standard normal two-tailed p-value via math.erf
        p_val = math.erfc(z / math.sqrt(2.0))
    else:
        p_val = 1.0

    return u1, max(0.0, min(1.0, p_val)), auc


def compute_statistics(
    hit_samples: list[float],
    miss_samples: list[float],
) -> dict[str, Any]:
    """
    Compute distribution metrics, Mann-Whitney U p-value, AUC, and verdict.
    Pre-registered verdict rule (architecture §9):
      LEAK DETECTED if p < 0.01 and AUC > 0.8; otherwise NO LEAK DETECTED.
    """
    n_hit = len(hit_samples)
    n_miss = len(miss_samples)
    if n_hit == 0 or n_miss == 0:
        return {
            "n_hit": n_hit,
            "n_miss": n_miss,
            "error": "insufficient samples",
            "verdict": "inconclusive",
        }

    med_hit = float(statistics.median(hit_samples))
    med_miss = float(statistics.median(miss_samples))
    # Positive diff = HIT is faster than MISS (expected cache hit advantage)
    med_diff = float(med_miss - med_hit)
    mean_hit = float(statistics.mean(hit_samples))
    mean_miss = float(statistics.mean(miss_samples))

    if HAS_SCIPY:
        # SciPy mannwhitneyu: x=miss, y=hit.
        # When miss > hit, rank sum of miss is large, so statistic U = sum(miss > hit).
        res = mannwhitneyu(miss_samples, hit_samples, alternative="two-sided")
        u_stat = float(res.statistic)
        p_val = float(res.pvalue)
        auc = float(u_stat / (n_miss * n_hit))
    else:
        u_stat, p_val, auc = _pure_python_mannwhitneyu(miss_samples, hit_samples)

    # Pre-registered verdict rule: §9
    is_leak = (p_val < 0.01) and (auc > 0.8)
    verdict = "leak_detected" if is_leak else "no_leak_detected"

    return {
        "n_hit": n_hit,
        "n_miss": n_miss,
        "median_hit_ms": round(med_hit, 3),
        "median_miss_ms": round(med_miss, 3),
        "median_diff_ms": round(med_diff, 3),
        "mean_hit_ms": round(mean_hit, 3),
        "mean_miss_ms": round(mean_miss, 3),
        "mann_whitney_u": round(u_stat, 3),
        "p_value": float(f"{p_val:.6e}"),
        "auc": round(auc, 4),
        "verdict": verdict,
    }


def collect_environment_info(repo_root: str) -> dict[str, Any]:
    """Collect host and model runtime environment information."""
    env_info: dict[str, Any] = {
        "cpu_count": os.cpu_count() or 1,
        "platform": sys.platform,
        "python_version": sys.version.split()[0],
        "model_file": os.environ.get("MODEL_FILE", "qwen2.5-0.5b-instruct-q4_k_m.gguf"),
        "llamacpp_version": "ghcr.io/ggml-org/llama.cpp:server-b11382",
        "model_architecture": "dual-instance (model-red on model-red-net, model-blue on model-blue-net; §9 fallback)",
    }
    # Read model from .env if present
    env_path = os.path.join(repo_root, ".env")
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("MODEL_FILE="):
                        env_info["model_file"] = line.split("=", 1)[1].strip()
                    elif line.startswith("MODEL_THREADS="):
                        env_info["model_threads"] = line.split("=", 1)[1].strip()
                    elif line.startswith("MODEL_PARALLEL="):
                        env_info["model_parallel"] = line.split("=", 1)[1].strip()
        except Exception:
            pass
    return env_info


def get_git_commit(repo_root: str) -> str:
    """Retrieve current git commit SHA."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=2.0,
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return "unknown"


def run_trials_for_mode(
    *,
    mode: str,
    gateway_url: str,
    web_url: str,
    red_token: str,
    blue_token: str,
    admin_token: str,
    n_trials: int,
    word_count: int,
    rng: random.Random,
    order_rng: random.Random,
    warmup_count: int = 3,
) -> Tuple[list[float], list[float]]:
    """
    Run the trial protocol for one cache mode.
    Returns (hit_samples, miss_samples).
    """
    log.info(f"=== Starting trials for mode: {mode} (N={n_trials} per condition) ===")

    # 1. Switch mode via operator API (erases KV slots upon switch)
    op_url = web_url if web_url else gateway_url
    switched = set_gateway_cache_mode(op_url, mode, admin_token)
    if not switched and gateway_url != op_url:
        switched = set_gateway_cache_mode(gateway_url, mode, admin_token)

    current_mode = get_gateway_cache_mode(op_url)
    log.info(f"Verified active cache mode: {current_mode}")

    # 2. Warm-up requests
    log.info(f"Running {warmup_count} warm-up probes...")
    for w in range(warmup_count):
        wp = f"Warmup probe {w}: " + generate_prefix(rng, 50)
        send_probe(gateway_url, "blue", blue_token, wp, max_tokens=1)
        send_probe(gateway_url, "red", red_token, wp, max_tokens=1)

    # 3. Create shuffled condition schedule
    # Fixed seed for trial ordering
    conditions: list[str] = ["HIT"] * n_trials + ["MISS"] * n_trials
    order_rng.shuffle(conditions)

    hit_samples: list[float] = []
    miss_samples: list[float] = []

    total_trials = len(conditions)
    log.info(f"Executing {total_trials} shuffled trials ({n_trials} HIT, {n_trials} MISS)...")

    for idx, cond in enumerate(conditions, 1):
        # Distinct prefix P_i for this trial
        prefix_i = generate_prefix(rng, word_count)

        # Victim (blue) probe: P_i + " Question A"
        victim_prompt = prefix_i + " Question A"
        v_lat, v_status, _ = send_probe(gateway_url, "blue", blue_token, victim_prompt, max_tokens=1)
        if v_status != 200:
            log.warning(f"Trial {idx}/{total_trials}: victim probe status {v_status}")

        # Attacker (red) probe:
        # HIT: P_i + " Question B"
        # MISS: fresh random prefix of same length + " Question B"
        if cond == "HIT":
            attacker_prompt = prefix_i + " Question B"
        else:
            prefix_miss = generate_prefix(rng, word_count)
            attacker_prompt = prefix_miss + " Question B"

        a_lat, a_status, _ = send_probe(gateway_url, "red", red_token, attacker_prompt, max_tokens=1)
        if a_status != 200:
            log.warning(f"Trial {idx}/{total_trials}: attacker probe status {a_status}")

        if cond == "HIT":
            hit_samples.append(a_lat)
        else:
            miss_samples.append(a_lat)

        if idx % 10 == 0 or idx == total_trials:
            curr_h_med = statistics.median(hit_samples) if hit_samples else 0.0
            curr_m_med = statistics.median(miss_samples) if miss_samples else 0.0
            log.info(
                f"[{mode.upper()}] Progress: {idx}/{total_trials} | "
                f"HIT n={len(hit_samples)} (med={curr_h_med:.1f}ms) | "
                f"MISS n={len(miss_samples)} (med={curr_m_med:.1f}ms) | "
                f"Diff={curr_m_med - curr_h_med:.1f}ms"
            )

    return hit_samples, miss_samples


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bayora Timing Side-Channel Evaluation Protocol (Architecture §9)"
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=40,
        help="Number of trials per condition (HIT and MISS). Default: 40 (architecture §9).",
    )
    parser.add_argument(
        "--words",
        type=int,
        default=900,
        help="Prefix word count. Default: 900 (~900 words per architecture §9).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Fixed seed for random prefix generation and trial shuffling. Default: 42.",
    )
    parser.add_argument(
        "--modes",
        nargs="+",
        default=["shared", "isolated"],
        choices=["shared", "isolated"],
        help="Modes to evaluate. Default: shared isolated.",
    )
    parser.add_argument(
        "--gateway-url",
        type=str,
        default="",
        help="Direct gateway URL for /v1/* probes (auto-discovered if empty).",
    )
    parser.add_argument(
        "--web-url",
        type=str,
        default="http://127.0.0.1:8088",
        help="Web proxy / operator URL for /api/* endpoints. Default: http://127.0.0.1:8088.",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=3,
        help="Warmup requests per mode. Default: 3.",
    )
    parser.add_argument(
        "--no-post",
        action="store_true",
        help="Do not post report to gateway API.",
    )
    parser.add_argument(
        "--out",
        type=str,
        default="experiments/timing/latest_report.json",
        help="Path to save report JSON locally.",
    )
    args = parser.parse_args()

    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    # Read secrets
    red_token = load_secret("red_token", repo_root)
    blue_token = load_secret("blue_token", repo_root)
    admin_token = load_secret("admin_token", repo_root)

    if not red_token or not blue_token or not admin_token:
        log.error("Missing required tokens (red_token, blue_token, admin_token in secrets/)")
        return 1

    gateway_url = args.gateway_url or discover_gateway_url(repo_root)
    web_url = args.web_url.rstrip("/")
    log.info(f"Target Gateway URL (tenant probes): {gateway_url}")
    log.info(f"Target Web URL (operator / public API): {web_url}")

    # Limitations as specified in architecture §9
    limitations: list[str] = [
        "Measured from the host through localhost; shared CPU contention itself is a timing channel (blue's load slows red's requests) and is not mitigated.",
        "Client-side wall-clock measurements (time.perf_counter) include gateway HTTP parsing, auth verification, and TCP network transit overhead.",
        "Operating system thread scheduling and host load variations may introduce noise into individual latency samples.",
        "Prompt KV-cache behavior is specific to the pinned llama.cpp server version and quantization format.",
    ]

    verdict_rule_desc = (
        "leak_detected only if p < 0.01 and AUC > 0.8; otherwise no_leak_detected (pre-registered, architecture §9)"
    )

    env_info = collect_environment_info(repo_root)
    git_commit = get_git_commit(repo_root)
    generated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    modes_results: dict[str, Any] = {}
    raw_samples: dict[str, Any] = {}
    verdicts: dict[str, str] = {}

    rng = random.Random(args.seed)
    order_rng = random.Random(args.seed + 1000)

    for mode in args.modes:
        hit_samples, miss_samples = run_trials_for_mode(
            mode=mode,
            gateway_url=gateway_url,
            web_url=web_url,
            red_token=red_token,
            blue_token=blue_token,
            admin_token=admin_token,
            n_trials=args.trials,
            word_count=args.words,
            rng=rng,
            order_rng=order_rng,
            warmup_count=args.warmup,
        )

        stats = compute_statistics(hit_samples, miss_samples)
        modes_results[mode] = stats
        raw_samples[mode] = {
            "hit": [round(x, 3) for x in hit_samples],
            "miss": [round(x, 3) for x in miss_samples],
        }
        verdicts[mode] = stats.get("verdict", "inconclusive")

    # Restore default isolated mode upon experiment completion (architecture §9)
    log.info("Restoring gateway to default isolated mode...")
    set_gateway_cache_mode(web_url, "isolated", admin_token)

    # Build summary
    summary: dict[str, Any] = {
        "trials_per_condition": args.trials,
        "prefix_words": args.words,
        "seed": args.seed,
    }
    for mode, stats in modes_results.items():
        summary[f"{mode}_auc"] = stats.get("auc")
        summary[f"{mode}_p_value"] = stats.get("p_value")
        summary[f"{mode}_verdict"] = stats.get("verdict")
        summary[f"{mode}_median_diff_ms"] = stats.get("median_diff_ms")

    report: dict[str, Any] = {
        "generated_at": generated_at,
        "git_commit": git_commit,
        "environment": env_info,
        "protocol": {
            "n_trials_per_condition": args.trials,
            "prefix_words": args.words,
            "seed": args.seed,
            "attacker_max_tokens": 1,
            "victim_max_tokens": 1,
            "warmup_count": args.warmup,
            "timing_method": "client-side time.perf_counter wall-clock latency (ms)",
        },
        "verdict_rule": verdict_rule_desc,
        "modes": modes_results,
        "verdict": {
            "rule": verdict_rule_desc,
            **verdicts,
        },
        "raw_samples": raw_samples,
        "summary": summary,
        "limitations": limitations,
    }

    # Print summary table
    print("\n" + "=" * 90)
    print("BAYORA TIMING SIDE-CHANNEL EXPERIMENT REPORT (Architecture §9)")
    print("=" * 90)
    print(f"Generated At: {generated_at} | Git Commit: {git_commit}")
    print(f"Environment: CPU count={env_info['cpu_count']}, Model={env_info['model_file']}, llama.cpp={env_info['llamacpp_version']}")
    print(f"Pre-Registered Verdict Rule: {verdict_rule_desc}")
    print("-" * 90)
    print(f"{'Mode':<10} | {'N(hit)':<6} | {'N(miss)':<7} | {'Med(Hit) ms':<12} | {'Med(Miss) ms':<13} | {'Diff ms':<10} | {'U Stat':<10} | {'p-value':<12} | {'AUC':<7} | {'Verdict'}")
    print("-" * 90)
    for mode, st in modes_results.items():
        print(
            f"{mode:<10} | {st['n_hit']:<6} | {st['n_miss']:<7} | "
            f"{st['median_hit_ms']:<12.2f} | {st['median_miss_ms']:<13.2f} | "
            f"{st['median_diff_ms']:<10.2f} | {st['mann_whitney_u']:<10.1f} | "
            f"{st['p_value']:<12.3e} | {st['auc']:<7.4f} | {st['verdict']}"
        )
    print("=" * 90)

    print("\nLimitations (§9):")
    for lim in limitations:
        print(f"  * {lim}")

    # Save to local file
    out_path = os.path.join(repo_root, args.out)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    log.info(f"Report saved locally to: {out_path}")

    # Post to gateway API if requested
    if not args.no_post:
        post_target = web_url if web_url else gateway_url
        post_url = f"{post_target}/api/experiments/timing/report"
        log.info(f"Posting timing report to: {post_url}")
        status, body = http_request_json(
            post_url,
            method="POST",
            headers={"X-Admin-Token": admin_token},
            payload=report,
            timeout=15.0,
        )
        if status in (200, 201):
            log.info(f"Report successfully posted to gateway (status={status}): {body}")
        else:
            log.warning(f"Failed to post report to {post_url}: HTTP {status} {body}")
            # Try posting directly to gateway if web proxy failed
            if post_target != gateway_url:
                alt_url = f"{gateway_url}/api/experiments/timing/report"
                log.info(f"Retrying report post directly to gateway: {alt_url}")
                status2, body2 = http_request_json(
                    alt_url,
                    method="POST",
                    headers={"X-Admin-Token": admin_token},
                    payload=report,
                    timeout=15.0,
                )
                if status2 in (200, 201):
                    log.info(f"Direct report post succeeded: {body2}")
                else:
                    log.error(f"Direct report post failed: HTTP {status2} {body2}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
