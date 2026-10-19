"""
tests/security/test_audit_log.py
Security adversary test suite for Bayora Audit Logger and Verifier.

Source of Truth:
  - docs/architecture.md (§8, §4, §5, §10)
  - AGENTS.md (§3)

Security Invariants tested:
  - SI-02: Verifier container cannot write to log volume (read-only mount).
  - SI-07: Fail closed. If the audit logger is unreachable, gateway rejects with 503.
  - SI-08: No raw prompts or responses in audit log; only SHA-256 digests.
  - Tamper detection: All log modifications, deletions, reorderings, checkpoint
    forgeries, and pre-checkpoint truncations must be detected.
  - Known limitation: Truncation after last checkpoint is undetectable by chain alone.
"""
import asyncio
import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.request
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import httpx
import pytest

# Paths
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SECRETS_DIR = os.path.join(REPO_ROOT, "secrets")
PUBKEY_PATH = os.path.join(REPO_ROOT, "verifier", "trusted_pubkey.pem")
TESTS_TMP_DIR = os.path.join(REPO_ROOT, "tests", ".audit_log_adversary_scratch")


def _read_secret(name: str) -> str:
    path = os.path.join(SECRETS_DIR, name)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    return ""


RED_TOKEN = _read_secret("red_token")
BLUE_TOKEN = _read_secret("blue_token")
ADMIN_TOKEN = _read_secret("admin_token")


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
            stdin=subprocess.DEVNULL,
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
    return "http://127.0.0.1:8088"


GATEWAY_URL = _discover_gateway_url()


# ==============================================================================
# Independent Verification Implementation (Derived Strictly from §8)
# ==============================================================================


def canonical_json_bytes(entry_dict: Dict[str, Any]) -> bytes:
    """Canonical JSON per §8: keys sorted, separators (',', ':'), UTF-8, ensure_ascii=False."""
    # SECURITY: Strip hash field before computing canonical digest per §8
    entry_without_hash = {k: v for k, v in entry_dict.items() if k != "hash"}
    return json.dumps(entry_without_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_entry_hash(entry_dict: Dict[str, Any]) -> str:
    """Compute SHA-256 digest of canonical entry representation."""
    return hashlib.sha256(canonical_json_bytes(entry_dict)).hexdigest()


def independent_verify_log(log_dir: str, pubkey_path: str = PUBKEY_PATH) -> Dict[str, Any]:
    """
    Independent re-implementation of audit log verification written strictly
    from docs/architecture.md §8 and AGENTS.md.
    """
    errors: List[Dict[str, Any]] = []
    log_file = os.path.join(log_dir, "log.jsonl")
    cp_file = os.path.join(log_dir, "checkpoints.jsonl")

    entries: List[Dict[str, Any]] = []
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except Exception as e:
                    errors.append({"seq": idx, "kind": f"json_syntax_error: {e}"})

    checkpoints: List[Dict[str, Any]] = []
    if os.path.exists(cp_file):
        with open(cp_file, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    checkpoints.append(json.loads(line))
                except Exception as e:
                    errors.append({"seq": idx, "kind": f"checkpoint_syntax_error: {e}"})

    # Sequence continuity and hash linkage checks
    if entries:
        # SECURITY: Genesis prev must be 64 zeros and seq must be 0 per §8
        e0 = entries[0]
        if e0.get("seq") != 0:
            errors.append({"seq": e0.get("seq"), "kind": "genesis_seq_not_zero"})
        if e0.get("prev") != "0" * 64:
            errors.append({"seq": 0, "kind": "genesis_prev_not_zeros"})
        if compute_entry_hash(e0) != e0.get("hash"):
            errors.append({"seq": 0, "kind": "hash_mismatch"})

        for i in range(1, len(entries)):
            prev_e = entries[i - 1]
            curr_e = entries[i]
            curr_seq = curr_e.get("seq")
            expected_seq = prev_e.get("seq", -1) + 1
            if curr_seq != expected_seq:
                errors.append({"seq": curr_seq, "kind": f"sequence_discontinuity: expected {expected_seq}"})
            # SECURITY: Linkage invariant - each entry's prev must equal predecessor's hash
            if curr_e.get("prev") != prev_e.get("hash"):
                errors.append({"seq": curr_seq, "kind": "prev_linkage_mismatch"})
            # SECURITY: Tamper detection - entry hash must match recomputed canonical hash
            if compute_entry_hash(curr_e) != curr_e.get("hash"):
                errors.append({"seq": curr_seq, "kind": "hash_mismatch"})

    # Checkpoint verification
    trusted_key = None
    if os.path.exists(pubkey_path):
        with open(pubkey_path, "rb") as f:
            trusted_key = load_pem_public_key(f.read())

    entries_by_seq = {e.get("seq"): e for e in entries if "seq" in e}

    for cp in checkpoints:
        cp_seq = cp.get("seq")
        cp_hash = cp.get("hash")
        cp_sig = cp.get("sig")

        # SECURITY: Checkpoint must reference an existing entry in the chain
        if cp_seq not in entries_by_seq:
            errors.append({"seq": cp_seq, "kind": "checkpoint_entry_missing"})
            continue

        # SECURITY: Checkpoint hash must equal entry hash at seq
        if entries_by_seq[cp_seq].get("hash") != cp_hash:
            errors.append({"seq": cp_seq, "kind": "checkpoint_hash_mismatch"})

        # SECURITY: Signature verification over ASCII "{seq}:{hash}"
        if trusted_key and cp_sig:
            msg = f"{cp_seq}:{cp_hash}".encode("ascii")
            try:
                sig_bytes = base64.b64decode(cp_sig)
                trusted_key.verify(sig_bytes, msg)
            except Exception as e:
                errors.append({"seq": cp_seq, "kind": f"checkpoint_sig_invalid: {e}"})

    head = None
    if entries:
        head = {"seq": entries[-1].get("seq"), "hash": entries[-1].get("hash")}

    return {
        "ok": len(errors) == 0,
        "entries": len(entries),
        "checkpoints": len(checkpoints),
        "head": head,
        "errors": errors,
    }


def real_verifier_endpoint_verify(log_dir: str, pubkey_path: str = PUBKEY_PATH) -> Dict[str, Any]:
    """
    Execute verification via the real verifier container through a temporary read-only mount.
    SECURITY: Mounts log directory strictly read-only (:ro) matching §4.
    """
    # Ensure readable by container user 10001
    os.chmod(log_dir, 0o755)
    for root, dirs, files in os.walk(log_dir):
        for d in dirs:
            os.chmod(os.path.join(root, d), 0o755)
        for f in files:
            os.chmod(os.path.join(root, f), 0o644)

    abs_log_dir = os.path.abspath(log_dir)
    abs_pubkey = os.path.abspath(pubkey_path)

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{abs_log_dir}:/app/log-data:ro",
        "-v",
        f"{abs_pubkey}:/run/secrets/trusted_pubkey.pem:ro",
        "bayora-verifier",
        "python3",
        "-c",
        (
            "import asyncio, json; "
            "from app.main import app; "
            "route = next(r for r in app.routes if getattr(r, 'path', None) == '/verify'); "
            "print('VERIFY_RESULT:' + json.dumps(asyncio.run(route.endpoint())))"
        ),
    ]

    res = subprocess.run(cmd, capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL)
    for line in res.stdout.splitlines():
        if line.startswith("VERIFY_RESULT:"):
            return json.loads(line[len("VERIFY_RESULT:") :])

    raise RuntimeError(f"Real verifier did not return VERIFY_RESULT: {res.stdout}\nSTDERR: {res.stderr}")


# ==============================================================================
# Helper Functions: Log Production & Copying
# ==============================================================================


def produce_gateway_log_entries(count: int = 12) -> None:
    """Send probe requests through the gateway to generate real audit log entries."""
    if not RED_TOKEN:
        return
    for i in range(count):
        req = urllib.request.Request(
            f"{GATEWAY_URL}/v1/red/probe",
            headers={"Authorization": f"Bearer {RED_TOKEN}", "Content-Type": "application/json"},
            data=json.dumps({"prompt": f"Audit adversary seed probe {i} - {uuid.uuid4().hex[:8]}", "max_tokens": 1}).encode("utf-8"),
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                resp.read()
        except Exception:
            pass


def create_log_copy(target_dir: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Copy current audit log files from container into a target directory."""
    os.makedirs(target_dir, exist_ok=True)
    subprocess.run(["docker", "cp", "bayora-verifier:/app/log-data/.", target_dir + "/"], check=True, stdin=subprocess.DEVNULL)
    os.chmod(target_dir, 0o755)

    entries = []
    with open(os.path.join(target_dir, "log.jsonl"), "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                entries.append(json.loads(line.strip()))

    checkpoints = []
    with open(os.path.join(target_dir, "checkpoints.jsonl"), "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                checkpoints.append(json.loads(line.strip()))

    return entries, checkpoints


def write_log_copy(target_dir: str, entries: List[Dict[str, Any]], checkpoints: List[Dict[str, Any]]) -> None:
    """Write modified entries and checkpoints to target directory and set permissions."""
    os.makedirs(target_dir, exist_ok=True)
    with open(os.path.join(target_dir, "log.jsonl"), "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    with open(os.path.join(target_dir, "checkpoints.jsonl"), "w", encoding="utf-8") as f:
        for cp in checkpoints:
            f.write(json.dumps(cp, ensure_ascii=False) + "\n")

    os.chmod(target_dir, 0o755)
    os.chmod(os.path.join(target_dir, "log.jsonl"), 0o644)
    os.chmod(os.path.join(target_dir, "checkpoints.jsonl"), 0o644)


@pytest.fixture(scope="module")
def base_log_data():
    """Ensure entries exist in the log, then snapshot to scratch directory."""
    produce_gateway_log_entries(count=5)
    os.makedirs(TESTS_TMP_DIR, exist_ok=True)
    base_dir = os.path.join(TESTS_TMP_DIR, "baseline")
    if os.path.exists(base_dir):
        shutil.rmtree(base_dir, ignore_errors=True)
    entries, checkpoints = create_log_copy(base_dir)
    # Ensure we have at least 1 checkpoint and entries before and after it
    if len(checkpoints) == 0:
        produce_gateway_log_entries(count=12)
        entries, checkpoints = create_log_copy(base_dir)
    yield base_dir, entries, checkpoints
    shutil.rmtree(TESTS_TMP_DIR, ignore_errors=True)


# ==============================================================================
# Tamper Attacks (10 Scenarios on Log Copy)
# ==============================================================================


def test_attack_01_edit_field(base_log_data):
    """ATTACK 1: Edit a field inside an entry without modifying the hash."""
    base_dir, entries, checkpoints = base_log_data
    tamper_dir = os.path.join(TESTS_TMP_DIR, "attack_01")
    tampered_entries = copy.deepcopy(entries)
    # SECURITY: Modify content of entry 3 leaving hash untouched
    tampered_entries[3]["actor"] = "adversary"
    write_log_copy(tamper_dir, tampered_entries, checkpoints)

    res_ind = independent_verify_log(tamper_dir)
    res_real = real_verifier_endpoint_verify(tamper_dir)

    assert not res_ind["ok"], "Independent verifier failed to detect edited field!"
    assert not res_real["ok"], "Real verifier failed to detect edited field!"


def test_attack_02_change_hash_without_rechaining(base_log_data):
    """ATTACK 2: Change an entry hash to match its content, but leave next entry prev unchanged."""
    base_dir, entries, checkpoints = base_log_data
    tamper_dir = os.path.join(TESTS_TMP_DIR, "attack_02")
    tampered_entries = copy.deepcopy(entries)
    # Modify entry 3 and recompute its hash consistently
    tampered_entries[3]["actor"] = "adversary"
    tampered_entries[3]["hash"] = compute_entry_hash(tampered_entries[3])
    # SECURITY: Do NOT update entry 4's prev pointer -> breaks chain linkage
    write_log_copy(tamper_dir, tampered_entries, checkpoints)

    res_ind = independent_verify_log(tamper_dir)
    res_real = real_verifier_endpoint_verify(tamper_dir)

    assert not res_ind["ok"], "Independent verifier failed to detect broken prev linkage!"
    assert not res_real["ok"], "Real verifier failed to detect broken prev linkage!"


def test_attack_03_delete_entry(base_log_data):
    """ATTACK 3: Delete an entry from the middle of the log."""
    base_dir, entries, checkpoints = base_log_data
    tamper_dir = os.path.join(TESTS_TMP_DIR, "attack_03")
    tampered_entries = copy.deepcopy(entries)
    # SECURITY: Delete entry at index 3 -> breaks sequence continuity and prev pointer
    del tampered_entries[3]
    write_log_copy(tamper_dir, tampered_entries, checkpoints)

    res_ind = independent_verify_log(tamper_dir)
    res_real = real_verifier_endpoint_verify(tamper_dir)

    assert not res_ind["ok"], "Independent verifier failed to detect deleted entry!"
    assert not res_real["ok"], "Real verifier failed to detect deleted entry!"


def test_attack_04_duplicate_entry(base_log_data):
    """ATTACK 4: Duplicate an entry in the log."""
    base_dir, entries, checkpoints = base_log_data
    tamper_dir = os.path.join(TESTS_TMP_DIR, "attack_04")
    tampered_entries = copy.deepcopy(entries)
    # SECURITY: Insert duplicate copy of entry 3 -> breaks seq monotonicity and linkage
    tampered_entries.insert(4, copy.deepcopy(tampered_entries[3]))
    write_log_copy(tamper_dir, tampered_entries, checkpoints)

    res_ind = independent_verify_log(tamper_dir)
    res_real = real_verifier_endpoint_verify(tamper_dir)

    assert not res_ind["ok"], "Independent verifier failed to detect duplicated entry!"
    assert not res_real["ok"], "Real verifier failed to detect duplicated entry!"


def test_attack_05_reorder_entries(base_log_data):
    """ATTACK 5: Reorder two adjacent entries in the log."""
    base_dir, entries, checkpoints = base_log_data
    tamper_dir = os.path.join(TESTS_TMP_DIR, "attack_05")
    tampered_entries = copy.deepcopy(entries)
    # SECURITY: Swap entries 3 and 4 -> violates sequence ordering and hash chaining
    tampered_entries[3], tampered_entries[4] = tampered_entries[4], tampered_entries[3]
    write_log_copy(tamper_dir, tampered_entries, checkpoints)

    res_ind = independent_verify_log(tamper_dir)
    res_real = real_verifier_endpoint_verify(tamper_dir)

    assert not res_ind["ok"], "Independent verifier failed to detect reordered entries!"
    assert not res_real["ok"], "Real verifier failed to detect reordered entries!"


def test_attack_06_replace_checkpoint_signature(base_log_data):
    """ATTACK 6: Replace checkpoint signature with corrupted signature bytes."""
    base_dir, entries, checkpoints = base_log_data
    assert len(checkpoints) > 0, "Requires at least one checkpoint"
    tamper_dir = os.path.join(TESTS_TMP_DIR, "attack_06")
    tampered_cp = copy.deepcopy(checkpoints)
    # SECURITY: Mutate the base64 signature of the first checkpoint
    orig_sig = base64.b64decode(tampered_cp[0]["sig"])
    corrupted_sig = bytes([b ^ 0xFF for b in orig_sig])
    tampered_cp[0]["sig"] = base64.b64encode(corrupted_sig).decode("ascii")
    write_log_copy(tamper_dir, entries, tampered_cp)

    res_ind = independent_verify_log(tamper_dir)
    res_real = real_verifier_endpoint_verify(tamper_dir)

    assert not res_ind["ok"], "Independent verifier failed to detect corrupted signature!"
    assert not res_real["ok"], "Real verifier failed to detect corrupted signature!"


def test_attack_07_replace_checkpoint_wrong_key(base_log_data):
    """ATTACK 7: Replace checkpoint signature with one signed by an attacker Ed25519 key."""
    base_dir, entries, checkpoints = base_log_data
    assert len(checkpoints) > 0, "Requires at least one checkpoint"
    tamper_dir = os.path.join(TESTS_TMP_DIR, "attack_07")
    tampered_cp = copy.deepcopy(checkpoints)
    # SECURITY: Attacker generates a fresh Ed25519 keypair and signs the checkpoint
    attacker_key = Ed25519PrivateKey.generate()
    cp = tampered_cp[0]
    msg = f"{cp['seq']}:{cp['hash']}".encode("ascii")
    forged_sig = attacker_key.sign(msg)
    tampered_cp[0]["sig"] = base64.b64encode(forged_sig).decode("ascii")
    write_log_copy(tamper_dir, entries, tampered_cp)

    res_ind = independent_verify_log(tamper_dir)
    res_real = real_verifier_endpoint_verify(tamper_dir)

    assert not res_ind["ok"], "Independent verifier failed to detect wrong signing key!"
    assert not res_real["ok"], "Real verifier failed to detect wrong signing key!"


def test_attack_08_truncate_before_last_checkpoint(base_log_data):
    """ATTACK 8: Truncate log entries to a point before the last checkpoint."""
    base_dir, entries, checkpoints = base_log_data
    assert len(checkpoints) > 0, "Requires at least one checkpoint"
    tamper_dir = os.path.join(TESTS_TMP_DIR, "attack_08")
    last_cp_seq = checkpoints[-1]["seq"]
    # Truncate entries so that the checkpoint seq no longer exists
    trunc_cutoff = max(1, last_cp_seq - 2)
    truncated_entries = copy.deepcopy(entries[:trunc_cutoff])
    # SECURITY: Checkpoint at last_cp_seq now references a missing entry
    write_log_copy(tamper_dir, truncated_entries, checkpoints)

    res_ind = independent_verify_log(tamper_dir)
    res_real = real_verifier_endpoint_verify(tamper_dir)

    assert not res_ind["ok"], "Independent verifier failed to detect pre-checkpoint truncation!"
    assert not res_real["ok"], "Real verifier failed to detect pre-checkpoint truncation!"


def test_attack_09_truncate_after_last_checkpoint(base_log_data):
    """
    ATTACK 9: Truncate log entries strictly after the last checkpoint.
    KNOWN LIMITATION (architecture §8, §10): Undetectable by hash-chain and verifier alone.
    Expected outcome: UNDETECTABLE (ok == True).
    """
    base_dir, entries, checkpoints = base_log_data
    assert len(checkpoints) > 0, "Requires at least one checkpoint"
    last_cp_seq = checkpoints[-1]["seq"]
    if len(entries) <= last_cp_seq + 1:
        produce_gateway_log_entries(count=5)
        entries, checkpoints = create_log_copy(base_dir)

    tamper_dir = os.path.join(TESTS_TMP_DIR, "attack_09")
    # SECURITY: Truncate tail entries after the checkpoint (e.g. keep up to checkpoint + 1)
    tampered_entries = copy.deepcopy(entries[: last_cp_seq + 2])
    write_log_copy(tamper_dir, tampered_entries, checkpoints)

    res_ind = independent_verify_log(tamper_dir)
    res_real = real_verifier_endpoint_verify(tamper_dir)

    # Documented property: tail truncation cannot be caught by verifier without external anchoring
    assert res_ind["ok"] is True, "Tail truncation should be undetectable by chain alone (architecture §8)"
    assert res_real["ok"] is True, "Real verifier should report tail truncation as undetectable by design"


def test_attack_10_insert_forged_entry_with_recomputed_hash_chain(base_log_data):
    """ATTACK 10: Insert forged entry and recompute the entire subsequent hash chain."""
    base_dir, entries, checkpoints = base_log_data
    assert len(checkpoints) > 0, "Requires at least one checkpoint"
    tamper_dir = os.path.join(TESTS_TMP_DIR, "attack_10")
    tampered_entries = copy.deepcopy(entries)

    # SECURITY: Adversary modifies entry 2 and re-chains every entry up to the end
    tampered_entries[2]["actor"] = "forged_actor"
    tampered_entries[2]["hash"] = compute_entry_hash(tampered_entries[2])
    for i in range(3, len(tampered_entries)):
        tampered_entries[i]["prev"] = tampered_entries[i - 1]["hash"]
        tampered_entries[i]["hash"] = compute_entry_hash(tampered_entries[i])

    # Hash chain is internally valid, but checkpoints at seq >= 2 will have mismatching hashes!
    write_log_copy(tamper_dir, tampered_entries, checkpoints)

    res_ind = independent_verify_log(tamper_dir)
    res_real = real_verifier_endpoint_verify(tamper_dir)

    assert not res_ind["ok"], "Independent verifier failed to detect forged entry with recomputed chain!"
    assert not res_real["ok"], "Real verifier failed to detect forged entry with recomputed chain!"


# ==============================================================================
# Additional Security Invariant Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_fail_closed_logger_stopped_gateway_returns_503():
    """SECURITY: SI-07 & §8 - Stopping logger makes gateway fail closed with 503."""
    if not RED_TOKEN:
        pytest.skip("RED_TOKEN not available")

    # Stop logger container
    subprocess.run(["docker", "compose", "stop", "logger"], check=True, stdin=subprocess.DEVNULL)
    try:
        async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=5.0) as client:
            # SECURITY: Gateway must reject requests requiring audit log when logger is down
            resp = await client.post(
                "/v1/red/probe",
                headers={"Authorization": f"Bearer {RED_TOKEN}"},
                json={"prompt": "fail closed probe", "max_tokens": 1},
            )
            assert resp.status_code == 503, f"Expected 503 Service Unavailable, got {resp.status_code}"
    finally:
        # Restore logger container
        subprocess.run(["docker", "compose", "start", "logger"], check=True, stdin=subprocess.DEVNULL)
        # Wait until logger container healthcheck reports healthy
        for _ in range(30):
            time.sleep(0.5)
            health_res = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Health.Status}}", "bayora-logger"],
                capture_output=True,
                text=True,
                check=False,
                stdin=subprocess.DEVNULL,
            )
            if health_res.stdout.strip() == "healthy":
                break
        time.sleep(1.0)


@pytest.mark.asyncio
async def test_no_raw_prompts_or_responses_in_audit_log():
    """SECURITY: SI-08 & §8 - No raw prompt or response text appears in any entry."""
    canary_prompt = f"CANARY_SECRET_PROMPT_{uuid.uuid4().hex}"
    canary_response_text = ""

    # Send probe through gateway (retrying briefly if logger connection is warming up)
    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=10.0) as client:
        resp = None
        for _ in range(10):
            resp = await client.post(
                "/v1/red/probe",
                headers={"Authorization": f"Bearer {RED_TOKEN}"},
                json={"prompt": canary_prompt, "max_tokens": 10},
            )
            if resp.status_code == 200:
                break
            await asyncio.sleep(1.0)

        assert resp is not None and resp.status_code == 200, f"Expected probe 200, got {getattr(resp, 'status_code', None)}"
        canary_response_text = resp.json().get("text", "").strip()

    # Read all log lines from container
    res = subprocess.run(
        ["docker", "compose", "exec", "-T", "verifier", "cat", "/app/log-data/log.jsonl"],
        capture_output=True,
        text=True,
        check=True,
        stdin=subprocess.DEVNULL,
    )
    raw_log = res.stdout

    # SECURITY: Raw prompt string must never appear in audit log
    assert canary_prompt not in raw_log, "SECURITY VIOLATION: raw prompt leaked into audit log!"
    if canary_response_text and len(canary_response_text) > 8:
        # SECURITY: Raw response string must never appear in audit log
        assert canary_response_text not in raw_log, "SECURITY VIOLATION: raw response leaked into audit log!"


def test_verifier_cannot_write_to_log_volume():
    """SECURITY: SI-02 & §4 - Verifier container cannot write to the log volume (read-only mount)."""
    probe_file = "/app/log-data/unauthorized_write.txt"
    # Attempt to write inside the verifier container
    res = subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "verifier",
            "python3",
            "-c",
            (
                "try:\n"
                f"    with open('{probe_file}', 'w') as f:\n"
                "        f.write('tamper')\n"
                "    print('UNEXPECTED_WRITE_SUCCESS')\n"
                "except Exception as e:\n"
                "    print('CAUGHT_EXCEPTION:' + type(e).__name__)\n"
            ),
        ],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    assert "CAUGHT_EXCEPTION" in res.stdout, f"SECURITY VIOLATION: Verifier did not raise exception on write: {res.stdout}"
    assert "UNEXPECTED_WRITE_SUCCESS" not in res.stdout, "SECURITY VIOLATION: Verifier wrote to read-only log volume!"


# ==============================================================================
# Standalone CLI Summary Report
# ==============================================================================


if __name__ == "__main__":
    print("\n" + "=" * 88)
    print(" BAYORA AUDIT LOG ADVERSARY TEST SUITE ")
    print("=" * 88 + "\n")

    os.makedirs(TESTS_TMP_DIR, exist_ok=True)
    produce_gateway_log_entries(count=5)
    base_dir = os.path.join(TESTS_TMP_DIR, "standalone_base")
    if os.path.exists(base_dir):
        shutil.rmtree(base_dir, ignore_errors=True)
    entries, checkpoints = create_log_copy(base_dir)
    if len(checkpoints) == 0:
        produce_gateway_log_entries(count=12)
        entries, checkpoints = create_log_copy(base_dir)

    base_fixture = (base_dir, entries, checkpoints)

    attacks = [
        ("1. Edit a field", test_attack_01_edit_field, "Detected", True),
        ("2. Change hash consistently without re-chaining", test_attack_02_change_hash_without_rechaining, "Detected", True),
        ("3. Delete an entry", test_attack_03_delete_entry, "Detected", True),
        ("4. Duplicate an entry", test_attack_04_duplicate_entry, "Detected", True),
        ("5. Reorder entries", test_attack_05_reorder_entries, "Detected", True),
        ("6. Corrupt checkpoint signature", test_attack_06_replace_checkpoint_signature, "Detected", True),
        ("7. Replace checkpoint signed by different key", test_attack_07_replace_checkpoint_wrong_key, "Detected", True),
        ("8. Truncate before last checkpoint", test_attack_08_truncate_before_last_checkpoint, "Detected", True),
        ("9. Truncate after last checkpoint (tail)", test_attack_09_truncate_after_last_checkpoint, "Undetectable (documented)", True),
        ("10. Insert forged entry with recomputed chain", test_attack_10_insert_forged_entry_with_recomputed_hash_chain, "Detected", True),
    ]

    print(f"{'Attack # / Description':<48} | {'Expected':<26} | {'Status'}")
    print("-" * 88)

    all_passed = True
    for desc, func, expected_behavior, expect_pass in attacks:
        try:
            func(base_fixture)
            status = "PASS"
        except Exception as e:
            status = f"FAIL ({e})"
            all_passed = False
        print(f"{desc:<48} | {expected_behavior:<26} | {status}")

    print("-" * 88)

    # Invariant checks
    print("\n[Invariant Checks]")
    try:
        test_verifier_cannot_write_to_log_volume()
        print("  - Verifier volume read-only enforcement: PASS")
    except Exception as e:
        print(f"  - Verifier volume read-only enforcement: FAIL ({e})")
        all_passed = False

    try:
        asyncio.run(test_no_raw_prompts_or_responses_in_audit_log())
        print("  - No raw prompt / response in audit log: PASS")
    except Exception as e:
        print(f"  - No raw prompt / response in audit log: FAIL ({e})")
        all_passed = False

    try:
        asyncio.run(test_fail_closed_logger_stopped_gateway_returns_503())
        print("  - Gateway fail closed (503) when logger stopped: PASS")
    except Exception as e:
        print(f"  - Gateway fail closed (503) when logger stopped: FAIL ({e})")
        all_passed = False

    shutil.rmtree(TESTS_TMP_DIR, ignore_errors=True)
    print("\n" + "=" * 88)
    print(f" OVERALL AUDIT LOG ADVERSARY TEST RESULT: {'PASS' if all_passed else 'FAIL'}")
    print("=" * 88 + "\n")
