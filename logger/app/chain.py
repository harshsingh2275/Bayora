"""
logger/app/chain.py
Audit log chain manager with Ed25519 checkpoints and fsync durability.

Architecture §8:
  - Single writer behind an asyncio lock.
  - fsync after each append to log.jsonl and checkpoints.jsonl.
  - Refuses to append if the on-disk chain is inconsistent.
  - Checkpoints every 10 entries and on demand (Ed25519 signature over ASCII "{seq}:{hash}").
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canonical import GENESIS_PREV, canonical_json_bytes, compute_entry_hash
from .config import LOG_DIR, load_signing_key

log = logging.getLogger("logger.chain")


class AuditChain:
    """Manages appending to log.jsonl and checkpoints.jsonl with strict consistency checks."""

    def __init__(self, log_dir: Path | None = None) -> None:
        self.log_dir = log_dir or LOG_DIR
        self.log_file = self.log_dir / "log.jsonl"
        self.checkpoints_file = self.log_dir / "checkpoints.jsonl"

        self._lock = asyncio.Lock()
        self.last_seq: int | None = None
        self.last_hash: str | None = None
        self.entry_count: int = 0
        self.is_consistent: bool = True
        self.inconsistency_error: str | None = None

        self._signing_key = None

    def _get_signing_key(self):
        if self._signing_key is None:
            self._signing_key = load_signing_key()
        return self._signing_key

    def verify_on_disk_chain(self) -> None:
        """
        Scan existing log.jsonl on disk and verify continuity, linkage, and hashes.
        Refuses to append if any corruption or inconsistency is found.
        """
        self.log_dir.mkdir(parents=True, exist_ok=True)
        if not self.log_file.exists():
            self.last_seq = None
            self.last_hash = None
            self.entry_count = 0
            self.is_consistent = True
            self.inconsistency_error = None
            return

        entries: list[dict[str, Any]] = []
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except Exception as err:
                        self.is_consistent = False
                        self.inconsistency_error = f"Malformed JSON at line {line_num}: {err}"
                        log.error(self.inconsistency_error)
                        return
                    entries.append(entry)
        except Exception as err:
            self.is_consistent = False
            self.inconsistency_error = f"Failed to read log file: {err}"
            log.error(self.inconsistency_error)
            return

        if not entries:
            self.last_seq = None
            self.last_hash = None
            self.entry_count = 0
            self.is_consistent = True
            self.inconsistency_error = None
            return

        prev_hash = GENESIS_PREV
        expected_seq = 0

        for i, entry in enumerate(entries):
            seq = entry.get("seq")
            prev = entry.get("prev")
            stored_hash = entry.get("hash")

            if seq != expected_seq:
                self.is_consistent = False
                self.inconsistency_error = (
                    f"Non-contiguous sequence at index {i}: expected {expected_seq}, got {seq}"
                )
                log.error(self.inconsistency_error)
                return

            if prev != prev_hash:
                self.is_consistent = False
                self.inconsistency_error = (
                    f"Broken prev hash link at seq {seq}: expected {prev_hash}, got {prev}"
                )
                log.error(self.inconsistency_error)
                return

            computed = compute_entry_hash(entry)
            if computed != stored_hash:
                self.is_consistent = False
                self.inconsistency_error = (
                    f"Hash mismatch at seq {seq}: stored {stored_hash}, computed {computed}"
                )
                log.error(self.inconsistency_error)
                return

            prev_hash = stored_hash
            expected_seq += 1

        self.last_seq = entries[-1]["seq"]
        self.last_hash = entries[-1]["hash"]
        self.entry_count = len(entries)
        self.is_consistent = True
        self.inconsistency_error = None
        log.info({"event": "chain_verified", "entries": self.entry_count, "head_seq": self.last_seq})

    async def append(
        self,
        *,
        run_id: str | None,
        actor: str,
        event: str,
        data: dict[str, Any],
        checkpoint: bool = False,
    ) -> dict[str, Any]:
        """
        Append an entry to the audit log under an asyncio lock.
        SECURITY: fsync ensures physical write before returning.
        Refuses to append if the chain is inconsistent.
        """
        async with self._lock:
            # SECURITY SI-07: Refuse append if on-disk chain is inconsistent
            if not self.is_consistent:
                raise RuntimeError(
                    f"On-disk audit chain is inconsistent: {self.inconsistency_error}"
                )

            seq = 0 if self.last_seq is None else self.last_seq + 1
            prev = GENESIS_PREV if self.last_hash is None else self.last_hash
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

            entry: dict[str, Any] = {
                "seq": seq,
                "ts": ts,
                "run_id": run_id,
                "actor": actor,
                "event": event,
                "data": data,
                "prev": prev,
            }
            entry_hash = compute_entry_hash(entry)
            entry["hash"] = entry_hash

            # SECURITY: Canonical JSON formatting
            line_bytes = canonical_json_bytes(entry) + b"\n"

            # Write and fsync log.jsonl
            with open(self.log_file, "ab") as f:
                f.write(line_bytes)
                f.flush()
                # SECURITY: fsync per append guarantees durability
                os.fsync(f.fileno())

            self.last_seq = seq
            self.last_hash = entry_hash
            self.entry_count += 1

            # Checkpoint trigger: every 10 entries, on run_concluded, or on-demand
            should_checkpoint = (
                ((seq + 1) % 10 == 0)
                or (event == "run_concluded")
                or checkpoint
            )
            if should_checkpoint:
                self._write_checkpoint_sync(seq=seq, entry_hash=entry_hash, ts=ts)

            return entry

    def _write_checkpoint_sync(self, *, seq: int, entry_hash: str, ts: str) -> dict[str, Any]:
        """Sign and append a checkpoint to checkpoints.jsonl with fsync."""
        key = self._get_signing_key()
        # SECURITY: Sign ASCII string "{seq}:{hash}"
        msg = f"{seq}:{entry_hash}".encode("ascii")
        sig_bytes = key.sign(msg)
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

        checkpoint = {
            "seq": seq,
            "hash": entry_hash,
            "ts": ts,
            "sig": sig_b64,
        }
        cp_bytes = canonical_json_bytes(checkpoint) + b"\n"

        with open(self.checkpoints_file, "ab") as f:
            f.write(cp_bytes)
            f.flush()
            # SECURITY: fsync ensures signed checkpoint is durable
            os.fsync(f.fileno())

        log.info({"event": "checkpoint_written", "seq": seq})
        return checkpoint

    async def create_checkpoint_on_demand(self) -> dict[str, Any]:
        """Create a signed checkpoint for current head on demand."""
        async with self._lock:
            if not self.is_consistent:
                raise RuntimeError("Cannot checkpoint inconsistent chain")
            if self.last_seq is None or self.last_hash is None:
                raise ValueError("Cannot checkpoint empty log")
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            return self._write_checkpoint_sync(
                seq=self.last_seq,
                entry_hash=self.last_hash,
                ts=ts,
            )

    def get_head(self) -> dict[str, Any]:
        """Return head sequence and hash."""
        return {"seq": self.last_seq, "hash": self.last_hash}

    def get_entries(self, after: int | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Read entries with optional pagination."""
        if not self.log_file.exists():
            return []
        results: list[dict[str, Any]] = []
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                seq = entry.get("seq", -1)
                if after is not None and seq <= after:
                    continue
                results.append(entry)
                if len(results) >= limit:
                    break
        return results
