"""
tests/unit/test_logger_chain.py
Unit tests for AuditChain, canonical JSON serialization, and Ed25519 signed checkpoints.

Architecture §8:
  - Canonical JSON: keys sorted, separators (",", ":"), UTF-8, ensure_ascii=False.
  - Hash chain: 64-zero genesis, contiguous seq, prev = previous hash.
  - Checkpoints: every 10 entries and on demand, Ed25519 signature over ASCII "{seq}:{hash}".
  - Refuses to append if the on-disk chain is inconsistent.
"""
import base64
import json
import pytest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from logger.app.canonical import GENESIS_PREV, canonical_json_bytes, compute_entry_hash
from logger.app.chain import AuditChain


def test_canonical_json_bytes():
    """Verify key sorting, exact separators, UTF-8, and ensure_ascii=False."""
    d = {"z": 1, "a": "hello", "b": [3, 2, 1], "unicode": "こんにちは"}
    raw = canonical_json_bytes(d)
    expected = b'{"a":"hello","b":[3,2,1],"unicode":"\xe3\x81\x93\xe3\x82\x93\xe3\x81\xab\xe3\x81\xa1\xe3\x81\xaf","z":1}'
    assert raw == expected


def test_compute_entry_hash_excludes_hash_field():
    """Verify that compute_entry_hash strips the 'hash' field before hashing."""
    entry = {
        "seq": 0,
        "ts": "2026-11-18T10:00:00.000Z",
        "run_id": None,
        "actor": "gateway",
        "event": "gateway_started",
        "data": {},
        "prev": GENESIS_PREV,
    }
    h1 = compute_entry_hash(entry)

    entry_with_hash = dict(entry)
    entry_with_hash["hash"] = "some_dummy_hash"
    h2 = compute_entry_hash(entry_with_hash)

    assert h1 == h2
    assert len(h1) == 64


@pytest.mark.asyncio
async def test_chain_appends_and_checkpoints(tmp_path: Path):
    """
    Append 25 entries and verify:
      - Genesis prev is 64 zeros.
      - Sequence is contiguous 0..24.
      - Each prev equals previous hash.
      - Exactly 2 checkpoints produced (seq 9 and seq 19).
      - Checkpoint signatures verify with public key.
    """
    chain = AuditChain(log_dir=tmp_path)
    chain.verify_on_disk_chain()

    for i in range(25):
        entry = await chain.append(
            run_id="test_run",
            actor="red",
            event="probe_processed",
            data={"idx": i, "digest": f"digest_{i}"},
        )
        assert entry["seq"] == i

    assert chain.entry_count == 25
    assert chain.last_seq == 24

    # Read log.jsonl
    log_lines = [json.loads(line) for line in (tmp_path / "log.jsonl").read_text().strip().split("\n")]
    assert len(log_lines) == 25

    assert log_lines[0]["prev"] == GENESIS_PREV
    for i in range(1, 25):
        assert log_lines[i]["seq"] == i
        assert log_lines[i]["prev"] == log_lines[i - 1]["hash"]
        assert compute_entry_hash(log_lines[i]) == log_lines[i]["hash"]

    # Read checkpoints.jsonl
    cp_lines = [json.loads(line) for line in (tmp_path / "checkpoints.jsonl").read_text().strip().split("\n")]
    assert len(cp_lines) == 2
    assert cp_lines[0]["seq"] == 9
    assert cp_lines[0]["hash"] == log_lines[9]["hash"]
    assert cp_lines[1]["seq"] == 19
    assert cp_lines[1]["hash"] == log_lines[19]["hash"]

    # Verify Ed25519 signatures
    pubkey_path = Path("verifier/trusted_pubkey.pem")
    pubkey = serialization.load_pem_public_key(pubkey_path.read_bytes())
    for cp in cp_lines:
        msg = f"{cp['seq']}:{cp['hash']}".encode("ascii")
        sig_bytes = base64.b64decode(cp["sig"])
        pubkey.verify(sig_bytes, msg)


@pytest.mark.asyncio
async def test_chain_refuses_append_when_on_disk_corrupt(tmp_path: Path):
    """Verify that an inconsistent chain on disk causes the logger to refuse appends."""
    chain = AuditChain(log_dir=tmp_path)
    await chain.append(run_id=None, actor="gateway", event="event_0", data={})
    await chain.append(run_id=None, actor="gateway", event="event_1", data={})

    # Tamper with the log file on disk
    log_file = tmp_path / "log.jsonl"
    lines = log_file.read_text().strip().split("\n")
    corrupt_entry = json.loads(lines[1])
    corrupt_entry["event"] = "tampered_event"
    lines[1] = json.dumps(corrupt_entry)
    log_file.write_text("\n".join(lines) + "\n")

    # New chain instance verifying the corrupted on-disk state
    chain2 = AuditChain(log_dir=tmp_path)
    chain2.verify_on_disk_chain()
    assert chain2.is_consistent is False

    with pytest.raises(RuntimeError, match="inconsistent"):
        await chain2.append(run_id=None, actor="gateway", event="event_2", data={})
