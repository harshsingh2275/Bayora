"""
verifier/app/verifier.py
Independent verification of the Bayora audit log and in-memory tamper demonstration.

Architecture §8:
  - SEPARATE code (never imports logger code)
  - Checks seq continuity, prev linkage, recomputed hashes, checkpoint Ed25519 signatures,
    and checkpoint alignment with log entries.
  - Tamper demo works on an in-memory copy only and evaluates:
    modify entry, delete entry, reorder entries, forge checkpoint,
    truncate before last checkpoint, truncate after last checkpoint.
  - Tail truncation after last checkpoint is honestly reported as NOT detectable (expected limitation).
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

GENESIS_PREV: str = "0" * 64


def canonical_json_bytes(obj: dict[str, Any]) -> bytes:
    """
    Independent implementation of canonical JSON serialization.
    Keys sorted, separators (',', ':'), UTF-8 encoded, ensure_ascii=False.
    """
    # SECURITY: Independent canonical serialization for cross-verification
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_entry_hash(entry: dict[str, Any]) -> str:
    """
    Compute SHA-256 hash of entry without the 'hash' field.
    """
    # SECURITY: Recompute hash from source fields without trusting stored hash
    entry_without_hash = {k: v for k, v in entry.items() if k != "hash"}
    raw_bytes = canonical_json_bytes(entry_without_hash)
    return hashlib.sha256(raw_bytes).hexdigest()


def verify_log_chain(
    entries: list[dict[str, Any]],
    checkpoints: list[dict[str, Any]],
    pubkey: ed25519.Ed25519PublicKey,
) -> dict[str, Any]:
    """
    Verify complete audit log chain and all signed checkpoints.
    Returns: {"ok": bool, "entries": int, "checkpoints": int, "head": head, "errors": errors}
    """
    errors: list[dict[str, Any]] = []

    # 1. Empty log verification
    if not entries:
        if checkpoints:
            errors.append({
                "seq": None,
                "kind": "Checkpoints exist but log entries are empty",
            })
        return {
            "ok": len(errors) == 0,
            "entries": 0,
            "checkpoints": len(checkpoints),
            "head": None,
            "errors": errors,
        }

    # 2. Sequential continuity and prev-hash linkage
    expected_prev = GENESIS_PREV
    expected_seq = 0

    entry_by_seq: dict[int, dict[str, Any]] = {}

    for i, entry in enumerate(entries):
        seq = entry.get("seq")
        prev = entry.get("prev")
        stored_hash = entry.get("hash")

        # Check sequence continuity
        if seq != expected_seq:
            errors.append({
                "seq": seq,
                "kind": f"Sequence discontinuity at index {i}: expected seq {expected_seq}, got {seq}",
            })

        # Check prev hash linkage
        if prev != expected_prev:
            errors.append({
                "seq": seq,
                "kind": f"Broken prev hash link at seq {seq}: expected {expected_prev}, got {prev}",
            })

        # Check recomputed hash
        computed_hash = compute_entry_hash(entry)
        if computed_hash != stored_hash:
            errors.append({
                "seq": seq,
                "kind": f"Hash mismatch at seq {seq}: stored {stored_hash}, computed {computed_hash}",
            })

        if seq is not None and isinstance(seq, int):
            entry_by_seq[seq] = entry

        expected_prev = stored_hash
        expected_seq = (seq + 1) if seq is not None else (expected_seq + 1)

    # 3. Checkpoint verification
    for cp in checkpoints:
        cp_seq = cp.get("seq")
        cp_hash = cp.get("hash")
        cp_sig_b64 = cp.get("sig")

        if cp_seq is None or cp_hash is None or not cp_sig_b64:
            errors.append({"seq": cp_seq, "kind": "Malformed checkpoint missing seq, hash, or sig"})
            continue

        # SECURITY: Verify Ed25519 signature over ASCII "{seq}:{hash}"
        msg = f"{cp_seq}:{cp_hash}".encode("ascii")
        try:
            sig_bytes = base64.b64decode(cp_sig_b64)
            pubkey.verify(sig_bytes, msg)
        except (InvalidSignature, ValueError, Exception) as err:
            errors.append({
                "seq": cp_seq,
                "kind": f"Invalid signature on checkpoint at seq {cp_seq}: {err}",
            })
            continue

        # Check checkpoint alignment with log entries
        matching_entry = entry_by_seq.get(cp_seq)
        if matching_entry is None:
            errors.append({
                "seq": cp_seq,
                "kind": f"Checkpoint at seq {cp_seq} references non-existent entry (truncation before checkpoint)",
            })
        elif matching_entry.get("hash") != cp_hash:
            errors.append({
                "seq": cp_seq,
                "kind": f"Checkpoint hash mismatch at seq {cp_seq}: checkpoint has {cp_hash}, entry has {matching_entry.get('hash')}",
            })

    head = {"seq": entries[-1]["seq"], "hash": entries[-1]["hash"]} if entries else None

    return {
        "ok": len(errors) == 0,
        "entries": len(entries),
        "checkpoints": len(checkpoints),
        "head": head,
        "errors": errors,
    }


def run_tamper_demo(
    entries: list[dict[str, Any]],
    checkpoints: list[dict[str, Any]],
    pubkey: ed25519.Ed25519PublicKey,
) -> dict[str, Any]:
    """
    Run in-memory tamper demonstration against a copy of the audit log.
    Tests 6 tamper cases per architecture §8:
      1. modify an entry
      2. delete an entry
      3. reorder two entries
      4. forge a checkpoint
      5. truncate before the last checkpoint
      6. truncate after the last checkpoint (expected limitation: not detectable)
    """
    cases: list[dict[str, Any]] = []

    # Case 1: Modify an entry
    e_copy = copy.deepcopy(entries)
    cp_copy = copy.deepcopy(checkpoints)
    target_idx = min(1, len(e_copy) - 1)
    if "data" in e_copy[target_idx] and isinstance(e_copy[target_idx]["data"], dict):
        e_copy[target_idx]["data"]["tampered"] = True
    else:
        e_copy[target_idx]["event"] = "tampered_event"
    res1 = verify_log_chain(e_copy, cp_copy, pubkey)
    detected1 = not res1["ok"]
    cases.append({
        "id": "modify_entry",
        "description": "Modify data in an existing entry",
        "detected": detected1,
        "expected_detection": True,
        "passed": detected1 is True,
        "details": res1["errors"][0]["kind"] if res1["errors"] else "Detected",
    })

    # Case 2: Delete an entry
    e_copy = copy.deepcopy(entries)
    cp_copy = copy.deepcopy(checkpoints)
    del_idx = min(2, len(e_copy) - 1)
    e_copy.pop(del_idx)
    res2 = verify_log_chain(e_copy, cp_copy, pubkey)
    detected2 = not res2["ok"]
    cases.append({
        "id": "delete_entry",
        "description": "Delete an entry from the middle of the chain",
        "detected": detected2,
        "expected_detection": True,
        "passed": detected2 is True,
        "details": res2["errors"][0]["kind"] if res2["errors"] else "Detected",
    })

    # Case 3: Reorder two entries
    e_copy = copy.deepcopy(entries)
    cp_copy = copy.deepcopy(checkpoints)
    swap_idx = 1 if len(e_copy) > 2 else 0
    e_copy[swap_idx], e_copy[swap_idx + 1] = e_copy[swap_idx + 1], e_copy[swap_idx]
    res3 = verify_log_chain(e_copy, cp_copy, pubkey)
    detected3 = not res3["ok"]
    cases.append({
        "id": "reorder_entries",
        "description": "Reorder two adjacent entries",
        "detected": detected3,
        "expected_detection": True,
        "passed": detected3 is True,
        "details": res3["errors"][0]["kind"] if res3["errors"] else "Detected",
    })

    # Case 4: Forge a checkpoint
    e_copy = copy.deepcopy(entries)
    cp_copy = copy.deepcopy(checkpoints)
    # Corrupt the signature of the first checkpoint
    orig_sig = cp_copy[0]["sig"]
    corrupted_sig = "A" * len(orig_sig)
    cp_copy[0]["sig"] = corrupted_sig
    res4 = verify_log_chain(e_copy, cp_copy, pubkey)
    detected4 = not res4["ok"]
    cases.append({
        "id": "forge_checkpoint",
        "description": "Forge or corrupt a checkpoint signature",
        "detected": detected4,
        "expected_detection": True,
        "passed": detected4 is True,
        "details": res4["errors"][0]["kind"] if res4["errors"] else "Detected",
    })

    # Case 5: Truncate before the last checkpoint
    e_copy = copy.deepcopy(entries)
    cp_copy = copy.deepcopy(checkpoints)
    last_cp_seq = cp_copy[-1]["seq"]
    # Drop entries so that log ends before the last checkpoint's sequence
    e_copy = [e for e in e_copy if e.get("seq", 0) < last_cp_seq]
    res5 = verify_log_chain(e_copy, cp_copy, pubkey)
    detected5 = not res5["ok"]
    cases.append({
        "id": "truncate_before_checkpoint",
        "description": "Truncate entries before the latest checkpoint",
        "detected": detected5,
        "expected_detection": True,
        "passed": detected5 is True,
        "details": res5["errors"][0]["kind"] if res5["errors"] else "Detected",
    })

    # Case 6: Truncate after the last checkpoint (tail truncation)
    # SECURITY: This is an expected limitation honestly reported as NOT detectable
    e_copy = copy.deepcopy(entries)
    cp_copy = copy.deepcopy(checkpoints)
    last_cp_seq = cp_copy[-1]["seq"]
    # Drop entries after the last checkpoint
    e_copy = [e for e in e_copy if e.get("seq", 0) <= last_cp_seq]
    res6 = verify_log_chain(e_copy, cp_copy, pubkey)
    detected6 = not res6["ok"]
    cases.append({
        "id": "truncate_after_checkpoint",
        "description": "Truncate entries after the latest checkpoint (tail truncation)",
        "detected": detected6,
        "expected_detection": False,
        "passed": detected6 is False,
        "limitation": True,
        "details": "Expected limitation: chain valid up to latest checkpoint; external head anchoring required",
    })

    all_passed = all(c["passed"] for c in cases)
    return {
        "ok": True,
        "cases": cases,
        "summary": {
            "total": len(cases),
            "passed": sum(1 for c in cases if c["passed"]),
            "limitations_acknowledged": 1,
            "all_expectations_met": all_passed,
        },
    }
