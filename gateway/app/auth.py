"""
gateway/app/auth.py
Token authentication and role-based access control.

SECURITY invariants:
  SI-05 – Tokens are stored as SHA-256 hashes. Comparison uses hmac.compare_digest
           to prevent timing-oracle attacks.  Plain tokens are never loaded or logged.
  SI-10 – Auth failures are logged as structured JSON without the supplied token value.
"""
import hashlib
import hmac
import logging
from typing import Literal

from fastapi import Header, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import config as cfg  # access at call time so tests can monkeypatch cfg attributes

log = logging.getLogger("gateway.auth")

Role = Literal["red", "blue"]

_bearer = HTTPBearer(auto_error=False)




def _sha256_hex(token: str) -> str:
    """Return the lowercase hex SHA-256 of a plain token string."""
    return hashlib.sha256(token.encode()).hexdigest()


def _constant_compare(a: str, b: str) -> bool:
    """SECURITY SI-05: timing-safe comparison using hmac.compare_digest."""
    # Both sides must be the same type; encode to bytes for hmac.compare_digest
    return hmac.compare_digest(a.encode(), b.encode())


def _verify_tenant_token(raw_token: str) -> Role:
    """Hash the supplied token and compare against stored hashes.

    Returns the role string if valid; raises HTTPException 401 otherwise.
    SECURITY: never log raw_token.
    """
    candidate_hash = _sha256_hex(raw_token)

    # SECURITY SI-05: read hashes from cfg at call time so tests can monkeypatch
    if cfg.RED_TOKEN_SHA256 and _constant_compare(candidate_hash, cfg.RED_TOKEN_SHA256):
        return "red"
    if cfg.BLUE_TOKEN_SHA256 and _constant_compare(candidate_hash, cfg.BLUE_TOKEN_SHA256):
        return "blue"

    # SECURITY SI-10: log the failure, never the token value
    log.warning({"event": "auth_failed", "reason": "bad_token"})
    raise HTTPException(status_code=401, detail="Invalid or missing token")


def _verify_admin_token(raw_token: str) -> None:
    """Hash and compare against admin hash.  Raises 401 if invalid."""
    if not cfg.ADMIN_TOKEN_SHA256:
        log.error({"event": "auth_failed", "reason": "admin_hash_not_configured"})
        raise HTTPException(status_code=503, detail="Admin auth not configured")
    candidate_hash = _sha256_hex(raw_token)
    # SECURITY SI-05: constant-time comparison
    if not _constant_compare(candidate_hash, cfg.ADMIN_TOKEN_SHA256):
        log.warning({"event": "auth_failed", "reason": "bad_admin_token"})
        raise HTTPException(status_code=401, detail="Invalid admin token")


# ── FastAPI dependency functions ────────────────────────────────────────────

async def require_tenant(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> Role:
    """FastAPI dependency: authenticate a tenant Bearer token, return their role."""
    if credentials is None:
        # SECURITY SI-10: 401 with no token value in response or log
        log.warning({"event": "auth_failed", "reason": "missing_token"})
        raise HTTPException(status_code=401, detail="Authorization header required")
    return _verify_tenant_token(credentials.credentials)


async def require_red(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> None:
    """FastAPI dependency: authenticate and assert role == 'red'."""
    role = await require_tenant(credentials)
    if role != "red":
        # SECURITY SI-05: 403 on cross-role attempt
        log.warning({"event": "authz_failed", "reason": "wrong_role", "role": role, "required": "red"})
        raise HTTPException(status_code=403, detail="Red role required")


async def require_blue(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> None:
    """FastAPI dependency: authenticate and assert role == 'blue'."""
    role = await require_tenant(credentials)
    if role != "blue":
        log.warning({"event": "authz_failed", "reason": "wrong_role", "role": role, "required": "blue"})
        raise HTTPException(status_code=403, detail="Blue role required")


async def require_admin(
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
) -> None:
    """FastAPI dependency: authenticate operator X-Admin-Token header."""
    if x_admin_token is None:
        log.warning({"event": "auth_failed", "reason": "missing_admin_token"})
        raise HTTPException(status_code=401, detail="X-Admin-Token header required")
    # SECURITY SI-10: never pass raw token to any log
    _verify_admin_token(x_admin_token)
