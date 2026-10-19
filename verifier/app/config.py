"""
verifier/app/config.py
Configuration and key loading for the Verifier Service.

SECURITY: Verifier has read-only access to log volume and trusted public key.
SECURITY: Verifier does not possess any signing keys.
"""
from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Directory where log.jsonl and checkpoints.jsonl reside (mounted read-only)
LOG_DIR = Path(os.environ.get("LOG_DIR", "/app/log-data"))

# Pinned trusted public key path
PUBKEY_CANDIDATES = [
    Path(os.environ.get("TRUSTED_PUBKEY_FILE", "/run/secrets/trusted_pubkey.pem")),
    Path("/app/trusted_pubkey.pem"),
    Path("verifier/trusted_pubkey.pem"),
]


def load_trusted_pubkey() -> ed25519.Ed25519PublicKey:
    """Load the pinned Ed25519 public key for checkpoint signature verification."""
    # SECURITY: Trusted public key is pinned and mounted read-only
    for p in PUBKEY_CANDIDATES:
        if p.is_file():
            key_bytes = p.read_bytes()
            pubkey = serialization.load_pem_public_key(key_bytes)
            if not isinstance(pubkey, ed25519.Ed25519PublicKey):
                raise ValueError(f"Key in {p} is not an Ed25519 public key")
            return pubkey
    raise FileNotFoundError(f"Trusted public key not found among candidates: {PUBKEY_CANDIDATES}")
