"""
gateway/app/config.py
Environment-variable configuration for the gateway.
All secrets come from file-mounts, never from env vars (SI-10).
"""
import os
from pathlib import Path


# ── Secret file paths (compose mounts /run/secrets/<name>) ─────────────────
SECRETS_DIR = Path(os.getenv("SECRETS_DIR", "/run/secrets"))

def _read_secret(name: str) -> str:
    """Read a secret from the Docker secrets mount.  Returns '' if missing."""
    p = SECRETS_DIR / name
    try:
        # SECURITY: strip trailing whitespace; never log the value
        return p.read_text().strip()
    except FileNotFoundError:
        return ""


# ── Token hashes (gateway never holds plain tokens, only SHA-256 hashes) ───
# SECURITY SI-05: only hashes are loaded; plain tokens are not mounted here
RED_TOKEN_SHA256: str   = _read_secret("red_token_sha256")
BLUE_TOKEN_SHA256: str  = _read_secret("blue_token_sha256")
ADMIN_TOKEN_SHA256: str = _read_secret("admin_token_sha256")
LOGGER_TOKEN: str       = _read_secret("logger_token")

# ── Model service ───────────────────────────────────────────────────────────
MODEL_URL: str = os.getenv("MODEL_URL", "http://model:8080")

# ── Logger service ──────────────────────────────────────────────────────────
LOGGER_URL: str = os.getenv("LOGGER_URL", "http://logger:8001")

# ── SQLite database path (inside gateway-data named volume) ─────────────────
DB_PATH: str = os.getenv("DB_PATH", "/app/data/gateway.db")

# ── Run & probe caps ────────────────────────────────────────────────────────
DEFAULT_CACHE_MODE: str = os.getenv("DEFAULT_CACHE_MODE", "isolated")
MAX_ATTACKS: int        = int(os.getenv("MAX_ATTACKS", "100"))
ATTACK_MAX_TOKENS: int  = int(os.getenv("ATTACK_MAX_TOKENS", "96"))
RUN_TIMEOUT_SECONDS: int = int(os.getenv("RUN_TIMEOUT_SECONDS", "600"))

# Probe max_tokens is always capped at 128 (architecture §5)
PROBE_MAX_TOKENS_CAP: int = 128

# Fixed model request parameters (architecture §7) — tenants cannot override these
MODEL_SYSTEM_PROMPT: str   = "You are a helpful assistant."
MODEL_TEMPERATURE: float   = 0.0

# ── Rate limiting ────────────────────────────────────────────────────────────
RATE_LIMIT_PUBLIC_PER_MIN: int  = int(os.getenv("RATE_LIMIT_PUBLIC_PER_MIN", "60"))
RATE_LIMIT_TENANT_PER_SEC: float = float(os.getenv("RATE_LIMIT_TENANT_PER_SEC", "10"))
