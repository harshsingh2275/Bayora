"""
gateway/app/logger_client.py
Logger client interface and fail-closed stub.

Architecture §8: The gateway MUST fail closed (503) when the audit logger is
unreachable.  This module defines the interface and a stub that always fails
closed so the gateway is safe before T04 wires in the real logger.

SECURITY SI-07: Fail closed — if the logger is unavailable, reject the action
                with 503 rather than proceeding without an audit trail.
SECURITY SI-08: This interface never accepts raw prompt or response text.
                All audit calls use digests only.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from fastapi import HTTPException

log = logging.getLogger("gateway.logger_client")


class LoggerClient(ABC):
    """Abstract logger client interface.  All implementations MUST fail closed."""

    @abstractmethod
    async def append(
        self,
        *,
        run_id: str | None,
        actor: str,
        event: str,
        data: dict[str, Any],
    ) -> None:
        """Append an audit entry.  Raises HTTPException(503) if unavailable."""
        ...


class FailClosedStub(LoggerClient):
    """
    Stub logger that ALWAYS fails closed with 503.

    Used during T03 before the real logger service (T04) is available.
    Every call raises 503 so no gateway action proceeds without an audit record.

    SECURITY SI-07: This is the correct safe default — the stub deliberately
    blocks all actions rather than silently allowing unaudited operations.
    """

    async def append(
        self,
        *,
        run_id: str | None,
        actor: str,
        event: str,
        data: dict[str, Any],
    ) -> None:
        # SECURITY SI-08: data dict must never contain raw prompt/response text.
        # Log the event name only (not data), to avoid leaking digests to stdout in tests.
        log.warning({"event": "logger_stub_blocked", "audit_event": event})
        raise HTTPException(
            status_code=503,
            detail="Audit logger unavailable — action rejected (fail-closed)",
        )


# ── Module-level singleton (replaced by real client in T04) ─────────────────
# SECURITY SI-07: Default is the fail-closed stub so the gateway is safe at startup.
_client: LoggerClient = FailClosedStub()


def get_logger_client() -> LoggerClient:
    """Return the active logger client (FastAPI dependency or direct call)."""
    return _client


def set_logger_client(client: LoggerClient) -> None:
    """Replace the active logger client (called during app startup in T04)."""
    global _client
    _client = client
