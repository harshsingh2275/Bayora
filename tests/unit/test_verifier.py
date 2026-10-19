"""
tests/unit/test_verifier.py
Unit tests for the independent Verifier service and in-memory tamper demo.

Architecture §8:
  - Independent code path (never imports logger code)
  - Full chain verification
  - 6 tamper demo attack cases evaluated in memory
  - Honest reporting of tail truncation limitation
"""
import copy
from pathlib import Path
from cryptography.hazmat.primitives import serialization

from verifier.app.verifier import (
    GENESIS_PREV,
    canonical_json_bytes,
    compute_entry_hash,
    run_tamper_demo,
    verify_log_chain,
)


def _generate_valid_in_memory_chain(count: int = 25):
    """Generate in-memory valid entries and checkpoints using test signing key."""
    privkey_bytes = Path("secrets/log_signing_key").read_bytes()
    privkey = serialization.load_pem_private_key(privkey_bytes, password=None)
    pubkey_bytes = Path("verifier/trusted_pubkey.pem").read_bytes()
    pubkey = serialization.load_pem_public_key(pubkey_bytes)

    entries = []
    checkpoints = []
    prev_hash = GENESIS_PREV

    import base64

    for i in range(count):
        entry = {
            "seq": i,
            "ts": f"2026-11-18T10:00:{i:02d}.000Z",
            "run_id": "r1",
            "actor": "red",
            "event": "probe_processed",
            "data": {"digest": f"dig_{i}"},
            "prev": prev_hash,
        }
        h = compute_entry_hash(entry)
        entry["hash"] = h
        entries.append(entry)
        prev_hash = h

        if (i + 1) % 10 == 0:
            msg = f"{i}:{h}".encode("ascii")
            sig = base64.b64encode(privkey.sign(msg)).decode("ascii")
            checkpoints.append({
                "seq": i,
                "hash": h,
                "ts": entry["ts"],
                "sig": sig,
            })

    return entries, checkpoints, pubkey


def test_independent_verifier_valid_chain():
    """Verify that a valid 25-entry chain with 2 checkpoints passes verification."""
    entries, checkpoints, pubkey = _generate_valid_in_memory_chain(25)
    result = verify_log_chain(entries, checkpoints, pubkey)
    assert result["ok"] is True
    assert result["entries"] == 25
    assert result["checkpoints"] == 2
    assert result["head"] == {"seq": 24, "hash": entries[-1]["hash"]}
    assert result["errors"] == []


def test_independent_verifier_detects_hash_mismatch():
    """Verify that modifying an entry's data breaks hash verification."""
    entries, checkpoints, pubkey = _generate_valid_in_memory_chain(25)
    entries[5]["data"]["digest"] = "tampered_digest"

    result = verify_log_chain(entries, checkpoints, pubkey)
    assert result["ok"] is False
    assert any("Hash mismatch at seq 5" in e["kind"] for e in result["errors"])


def test_independent_verifier_detects_prev_link_break():
    """Verify that breaking the prev link is detected."""
    entries, checkpoints, pubkey = _generate_valid_in_memory_chain(25)
    entries[4]["prev"] = "f" * 64

    result = verify_log_chain(entries, checkpoints, pubkey)
    assert result["ok"] is False
    assert any("Broken prev hash link at seq 4" in e["kind"] for e in result["errors"])


def test_independent_verifier_detects_invalid_checkpoint_signature():
    """Verify that an altered checkpoint signature is rejected."""
    entries, checkpoints, pubkey = _generate_valid_in_memory_chain(25)
    checkpoints[0]["sig"] = "A" * len(checkpoints[0]["sig"])

    result = verify_log_chain(entries, checkpoints, pubkey)
    assert result["ok"] is False
    assert any("Invalid signature on checkpoint at seq 9" in e["kind"] for e in result["errors"])


def test_tamper_demo_all_cases():
    """
    Test the 6 cases of the in-memory tamper demo:
      1. modify an entry -> detected: True
      2. delete an entry -> detected: True
      3. reorder two entries -> detected: True
      4. forge a checkpoint -> detected: True
      5. truncate before last checkpoint -> detected: True
      6. truncate after last checkpoint -> detected: False (expected limitation!)
    """
    entries, checkpoints, pubkey = _generate_valid_in_memory_chain(25)
    report = run_tamper_demo(entries, checkpoints, pubkey)

    assert report["ok"] is True
    cases = report["cases"]
    assert len(cases) == 6

    # Verify each case by ID
    case_map = {c["id"]: c for c in cases}

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

    # Tail truncation: NOT detectable (honest limitation)
    assert case_map["truncate_after_checkpoint"]["detected"] is False
    assert case_map["truncate_after_checkpoint"]["passed"] is True
    assert case_map["truncate_after_checkpoint"].get("limitation") is True

    assert report["summary"]["all_expectations_met"] is True
