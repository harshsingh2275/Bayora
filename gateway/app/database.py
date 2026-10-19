"""
gateway/app/database.py
SQLite schema and DB access via aiosqlite.

Migrations are idempotent CREATE TABLE IF NOT EXISTS (architecture T03).
No ORM; raw SQL keeps the schema readable for auditors.

SECURITY: SQLite file lives on the gateway-data named volume, not in /tmp.
          No foreign service can mount this volume (architecture §4).
"""
import aiosqlite
import logging

from .config import DB_PATH

log = logging.getLogger("gateway.db")

# ── Schema ─────────────────────────────────────────────────────────────────────
# One block of DDL, each CREATE is idempotent.

_SCHEMA = """
-- runs: one row per run
CREATE TABLE IF NOT EXISTS runs (
    run_id      TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT 'created',
    attack_count INTEGER NOT NULL,
    seed        INTEGER NOT NULL,
    bundle_name TEXT NOT NULL,
    created_at  TEXT NOT NULL,   -- ISO-8601 UTC
    updated_at  TEXT NOT NULL
);

-- commitments: red and blue commit records
CREATE TABLE IF NOT EXISTS commitments (
    run_id      TEXT NOT NULL REFERENCES runs(run_id),
    role        TEXT NOT NULL,   -- 'red' | 'blue'
    count       INTEGER,
    set_digest  TEXT,            -- SHA-256 hex of the joined digests
    bundle_digest TEXT,          -- SHA-256 hex of the sealed bundle JSON
    committed_at TEXT NOT NULL,
    PRIMARY KEY (run_id, role)
);

-- bundles: sealed defense bundle JSON (stored as text, never executed)
-- SECURITY SI-09: content is data; the gateway applies it via regex matching
CREATE TABLE IF NOT EXISTS bundles (
    run_id      TEXT PRIMARY KEY REFERENCES runs(run_id),
    bundle_json TEXT NOT NULL,   -- canonical serialized JSON
    bundle_digest TEXT NOT NULL
);

-- attacks: per-attack records (sealed until conclusion)
-- SECURITY SI-08: prompt_digest and response_digest only; no raw text
CREATE TABLE IF NOT EXISTS attacks (
    run_id          TEXT NOT NULL REFERENCES runs(run_id),
    idx             INTEGER NOT NULL,
    prompt_digest   TEXT NOT NULL,   -- SHA-256 hex
    response_digest TEXT,            -- SHA-256 hex (set on conclusion)
    outcome         TEXT,            -- blocked_input | blocked_output | refused | complied | error
    latency_ms      REAL,
    PRIMARY KEY (run_id, idx)
);

-- settings: key-value store for runtime configuration
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Seed default settings if not present
INSERT OR IGNORE INTO settings (key, value) VALUES ('cache_mode', 'isolated');
""";


async def init_db() -> aiosqlite.Connection:
    """Open/create the SQLite database and apply idempotent schema migrations."""
    conn = await aiosqlite.connect(DB_PATH)
    conn.row_factory = aiosqlite.Row
    # SECURITY: WAL mode improves concurrency without shared write access from outside
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA foreign_keys=ON")
    await conn.executescript(_SCHEMA)
    await conn.commit()
    log.info({"event": "db_initialized", "path": DB_PATH})
    return conn


async def get_setting(conn: aiosqlite.Connection, key: str) -> str | None:
    """Fetch a runtime setting by key."""
    async with conn.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cur:
        row = await cur.fetchone()
        return row["value"] if row else None


async def set_setting(conn: aiosqlite.Connection, key: str, value: str) -> None:
    """Upsert a runtime setting."""
    await conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )
    await conn.commit()
