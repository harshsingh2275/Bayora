"""
gateway/app/deps.py
FastAPI dependency providers for shared application resources.

Uses app.state for objects initialised during lifespan (db, logger client).
This avoids circular imports between routes and main.py.
"""
import aiosqlite
from fastapi import Request

from .logger_client import LoggerClient


async def get_db(request: Request) -> aiosqlite.Connection:
    """FastAPI dependency: return the shared SQLite connection from app.state."""
    return request.app.state.db


async def get_logger(request: Request) -> LoggerClient:
    """FastAPI dependency: return the active logger client from app.state."""
    return request.app.state.logger_client
