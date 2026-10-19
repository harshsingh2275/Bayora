"""
gateway/app/rate_limit.py
In-memory per-tenant rate limiting (token bucket, configurable via env).

Architecture §5: 429 on rate limit exceeded.
Architecture §14: RATE_LIMIT_TENANT_PER_SEC controls the sustained rate.

SECURITY: Rate limiting is in-memory only (no shared state between gateway
          replicas); sufficient for single-instance hackathon use.
          Public endpoint rate limiting is a separate counter keyed by IP.
"""
import asyncio
import logging
import time
from collections import defaultdict

from fastapi import HTTPException, Request

from .config import RATE_LIMIT_PUBLIC_PER_MIN, RATE_LIMIT_TENANT_PER_SEC

log = logging.getLogger("gateway.rate_limit")


class TokenBucket:
    """Simple token-bucket rate limiter for a single tenant or IP."""

    def __init__(self, rate: float, capacity: float) -> None:
        self._rate = rate          # tokens per second
        self._capacity = capacity  # maximum tokens
        self._tokens = capacity
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def consume(self) -> bool:
        """Consume one token.  Returns True if allowed, False if rate-limited."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            # Refill tokens proportional to elapsed time
            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False


# ── Tenant buckets (keyed by role: 'red' | 'blue') ──────────────────────────
_tenant_buckets: dict[str, TokenBucket] = {}

def _get_tenant_bucket(role: str) -> TokenBucket:
    if role not in _tenant_buckets:
        _tenant_buckets[role] = TokenBucket(
            rate=RATE_LIMIT_TENANT_PER_SEC,
            capacity=RATE_LIMIT_TENANT_PER_SEC * 5,  # burst up to 5s worth
        )
    return _tenant_buckets[role]


async def check_tenant_rate(role: str) -> None:
    """Raise 429 if the tenant role is over the configured rate limit."""
    bucket = _get_tenant_bucket(role)
    if not await bucket.consume():
        log.warning({"event": "rate_limited", "role": role})
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


# ── Public (per-IP) buckets ──────────────────────────────────────────────────
_public_buckets: dict[str, TokenBucket] = {}

def _get_public_bucket(ip: str) -> TokenBucket:
    if ip not in _public_buckets:
        rate_per_sec = RATE_LIMIT_PUBLIC_PER_MIN / 60.0
        _public_buckets[ip] = TokenBucket(rate=rate_per_sec, capacity=rate_per_sec * 10)
    return _public_buckets[ip]


async def check_public_rate(request: Request) -> None:
    """Raise 429 if the requesting IP is over the public rate limit."""
    ip = request.client.host if request.client else "unknown"
    bucket = _get_public_bucket(ip)
    if not await bucket.consume():
        log.warning({"event": "public_rate_limited", "ip": ip})
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
