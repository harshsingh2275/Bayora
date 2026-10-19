"""
logger/app/canonical.py
Canonical JSON formatting and hash computation for the audit log chain.

Architecture §8:
  - Canonical JSON: keys sorted, separators (",", ":"), UTF-8, ensure_ascii=False.
  - hash = SHA-256 of canonical JSON of entry without the "hash" field.
  - Genesis prev = 64 zeros.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS_PREV: str = "0" * 64


def canonical_json_bytes(obj: dict[str, Any]) -> bytes:
    """
    Serialize dictionary to canonical JSON bytes per architecture §8.
    Keys are sorted, minimal separators (',', ':'), UTF-8 encoded, ensure_ascii=False.
    """
    # SECURITY: Deterministic serialization ensures hash reproducibility
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_entry_hash(entry: dict[str, Any]) -> str:
    """
    Compute SHA-256 hash of an entry's canonical JSON excluding the 'hash' key.
    """
    # SECURITY: entry without 'hash' field is hashed to form the chain link
    entry_without_hash = {k: v for k, v in entry.items() if k != "hash"}
    raw_bytes = canonical_json_bytes(entry_without_hash)
    return hashlib.sha256(raw_bytes).hexdigest()
