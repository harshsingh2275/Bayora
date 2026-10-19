"""
gateway/app/logger_client.py
Logger client interface and RealLoggerClient / FailClosedStub.

Architecture §8: The gateway MUST fail closed (503) when the audit logger is
unreachable.

SECURITY SI-07: Fail closed — if the logger is unavailable, reject the action
                with 503 rather than proceeding without an audit trail.
SECURITY SI-08: This interface never accepts raw prompt or response text.
                All audit calls use digests only.
"""
from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import httpx
from fastapi import HTTPException

log = logging.getLogger("gateway.logger_client")

LOGGER_TOKEN_FILE = Path(os.environ.get("LOGGER_TOKEN_FILE", "/run/secrets/logger_token"))
LOCAL_TOKEN_FILE = Path("secrets/logger_token")
DEFAULT_LOGGER_URL = os.environ.get("LOGGER_URL", "http://logger:8001")


def _read_logger_token() -> str:
    """Read the logger secret token."""
    for p in [LOGGER_TOKEN_FILE, LOCAL_TOKEN_FILE]:
        if p.is_file():
            return p.read_text().strip()
    return ""


class LoggerClient(ABC):
    """Abstract logger client interface. All implementations MUST fail closed."""

    @abstractmethod
    async def append(
        self,
        *,
        run_id: str | None,
        actor: str,
        event: str,
        data: dict[str, Any],
    ) -> None:
        """Append an audit entry. Raises HTTPException(503) if unavailable."""
        ...


class FailClosedStub(LoggerClient):
    """
    Stub logger that ALWAYS fails closed with 503.
    SECURITY SI-07: Default safe stub blocking all actions when real logger is unset.
    """

    async def append(
        self,
        *,
        run_id: str | None,
        actor: str,
        event: str,
        data: dict[str, Any],
    ) -> None:
        log.warning({"event": "logger_stub_blocked", "audit_event": event})
        raise HTTPException(
            status_code=503,
            detail="Audit logger unavailable — action rejected (fail-closed)",
        )


class RealLoggerClient(LoggerClient):
    """
    Production logger client connecting to the Logger service on log-net.
    SECURITY SI-07: Strictly fails closed (503) on network failure, timeout, or error.
    """

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        timeout: float = 3.0,
    ) -> None:
        self.base_url = (base_url or DEFAULT_LOGGER_URL).rstrip("/")
        self.token = token if token is not None else _read_logger_token()
        self.timeout = httpx.Timeout(connect=2.0, read=timeout, write=2.0, pool=5.0)

    async def append(
        self,
        *,
        run_id: str | None,
        actor: str,
        event: str,
        data: dict[str, Any],
    ) -> None:
        """
        POST audit record to the logger service.
        SECURITY SI-07: Any failure raises HTTPException(503).
        SECURITY SI-08: Data must contain only digests, never raw text.
        """
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        payload = {
            "run_id": run_id,
            "actor": actor,
            "event": event,
            "data": data,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/append",
                    headers=headers,
                    json=payload,
                )
                if resp.status_code not in (200, 201):
                    log.error({
                        "event": "logger_error_response",
                        "status": resp.status_code,
                        "audit_event": event,
                    })
                    raise HTTPException(
                        status_code=503,
                        detail="Audit logger unavailable — action rejected (fail-closed)",
                    )
        except HTTPException:
            raise
        except Exception as err:
            log.error({
                "event": "logger_connection_failed",
                "audit_event": event,
                "error": type(err).__name__,
            })
            # SECURITY SI-07: Fail closed on connection error or timeout
            raise HTTPException(
                status_code=503,
                detail="Audit logger unavailable — action rejected (fail-closed)",
            )


# ── Module-level singleton ───────────────────────────────────────────────────
_client: LoggerClient = FailClosedStub()


def get_logger_client() -> LoggerClient:
    """Return the active logger client."""
    return _client


def set_logger_client(client: LoggerClient) -> None:
    """Replace the active logger client."""
    global _client
    _client = client
