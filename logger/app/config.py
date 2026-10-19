"""
logger/app/config.py
Configuration and secret loading for the Audit Logger Service.

SECURITY SI-05: Tokens and signing keys are read strictly from secret mounts.
SECURITY SI-10: Secrets are never logged or exposed in responses.
"""
from __future__ import annotations

import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Directory where log.jsonl and checkpoints.jsonl reside
LOG_DIR = Path(os.environ.get("LOG_DIR", "/app/log-data"))

# Secret paths (Docker secrets default; local fallback for tests)
LOGGER_TOKEN_FILE = Path(os.environ.get("LOGGER_TOKEN_FILE", "/run/secrets/logger_token"))
LOCAL_TOKEN_FILE = Path("secrets/logger_token")

LOG_SIGNING_KEY_FILE = Path(os.environ.get("LOG_SIGNING_KEY_FILE", "/run/secrets/log_signing_key"))
LOCAL_SIGNING_KEY_FILE = Path("secrets/log_signing_key")


def load_logger_token() -> str:
    """Load the logger shared secret token."""
    # SECURITY: Read file secret without echoing to logs
    for p in [LOGGER_TOKEN_FILE, LOCAL_TOKEN_FILE]:
        if p.is_file():
            return p.read_text().strip()
    return ""


def load_signing_key() -> ed25519.Ed25519PrivateKey:
    """Load the Ed25519 private signing key for log checkpoints."""
    # SECURITY: Read private key from secret mount
    for p in [LOG_SIGNING_KEY_FILE, LOCAL_SIGNING_KEY_FILE]:
        if p.is_file():
            key_bytes = p.read_bytes()
            key = serialization.load_pem_private_key(key_bytes, password=None)
            if not isinstance(key, ed25519.Ed25519PrivateKey):
                raise ValueError(f"Key in {p} is not an Ed25519 private key")
            return key
    raise FileNotFoundError(
        f"Signing key not found at {LOG_SIGNING_KEY_FILE} or {LOCAL_SIGNING_KEY_FILE}"
    )
