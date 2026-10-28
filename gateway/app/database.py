"""
gateway/app/database.py
SQLite schema and DB access via aiosqlite.

Migrations are idempotent CREATE TABLE IF NOT EXISTS (architecture T03).
No ORM; raw SQL keeps the schema readable for auditors.

SECURITY: SQLite file lives on the gateway-data named volume, not in /tmp.
          No foreign service can mount this volume (architecture §4).
"""
import json
import logging

import aiosqlite

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
-- SECURITY SI-08: prompt_digest and response_digest only logged mid-run; raw text stored sealed
CREATE TABLE IF NOT EXISTS attacks (
    run_id          TEXT NOT NULL REFERENCES runs(run_id),
    idx             INTEGER NOT NULL,
    prompt_digest   TEXT NOT NULL,   -- SHA-256 hex
    response_digest TEXT,            -- SHA-256 hex
    outcome         TEXT,            -- blocked_input | blocked_output | refused | complied | error
    latency_ms      REAL,
    prompt          TEXT,            -- full prompt text (sealed)
    response_text   TEXT,            -- model response or refusal text (sealed)
    rule_id         TEXT,            -- rule id that triggered block, or NULL
    source          TEXT NOT NULL DEFAULT 'advbench',
    category        TEXT NOT NULL DEFAULT 'harmful_behavior',
    created_at      TEXT,
    PRIMARY KEY (run_id, idx)
);

-- red_committed_digests: individual prompt digests committed by red team
CREATE TABLE IF NOT EXISTS red_committed_digests (
    run_id   TEXT NOT NULL REFERENCES runs(run_id),
    idx      INTEGER NOT NULL,
    digest   TEXT NOT NULL,
    source   TEXT NOT NULL DEFAULT 'advbench',
    category TEXT NOT NULL DEFAULT 'harmful_behavior',
    PRIMARY KEY (run_id, idx)
);

-- run_results: sealed results revealed after run conclusion
CREATE TABLE IF NOT EXISTS run_results (
    run_id         TEXT PRIMARY KEY REFERENCES runs(run_id),
    results_json   TEXT NOT NULL,
    results_digest TEXT NOT NULL,
    total          INTEGER NOT NULL,
    asr            REAL NOT NULL,
    concluded_at   TEXT NOT NULL
);

-- settings: key-value store for runtime configuration
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- breakit_reports: stores posted break-it runner reports
CREATE TABLE IF NOT EXISTS breakit_reports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    report_json  TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

-- timing_reports: stores posted timing side-channel experiment reports
CREATE TABLE IF NOT EXISTS timing_reports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    report_json  TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

-- Seed default settings if not present
INSERT OR IGNORE INTO settings (key, value) VALUES ('cache_mode', 'isolated');
""";


async def init_db() -> aiosqlite.Connection:
    """Open/create the SQLite database and apply idempotent schema migrations."""
    from . import config as cfg
    import os

    db_file = cfg.DB_PATH
    dirname = os.path.dirname(db_file)
    if dirname:
        os.makedirs(dirname, exist_ok=True)

    conn = await aiosqlite.connect(db_file)
    conn.row_factory = aiosqlite.Row
    # SECURITY: WAL mode improves concurrency without shared write access from outside
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA foreign_keys=ON")
    await conn.executescript(_SCHEMA)
    # Ensure sealed and metadata columns exist on attacks if table was created previously
    for col, col_type, default_val in [
        ("prompt", "TEXT", None),
        ("response_text", "TEXT", None),
        ("rule_id", "TEXT", None),
        ("source", "TEXT", "'advbench'"),
        ("category", "TEXT", "'harmful_behavior'"),
        ("created_at", "TEXT", None),
    ]:
        try:
            default_clause = f" DEFAULT {default_val}" if default_val else ""
            await conn.execute(f"ALTER TABLE attacks ADD COLUMN {col} {col_type}{default_clause}")
        except Exception:
            pass

    for col, col_type, default_val in [
        ("source", "TEXT", "'advbench'"),
        ("category", "TEXT", "'harmful_behavior'"),
    ]:
        try:
            default_clause = f" DEFAULT {default_val}" if default_val else ""
            await conn.execute(f"ALTER TABLE red_committed_digests ADD COLUMN {col} {col_type}{default_clause}")
        except Exception:
            pass

    # Backfill any existing attacks that have NULL source or category
    try:
        await conn.execute("UPDATE attacks SET source = 'advbench' WHERE source IS NULL")
        await conn.execute("UPDATE attacks SET category = 'harmful_behavior' WHERE category IS NULL")
        await conn.execute("UPDATE red_committed_digests SET source = 'advbench' WHERE source IS NULL")
        await conn.execute("UPDATE red_committed_digests SET category = 'harmful_behavior' WHERE category IS NULL")
    except Exception:
        pass

    # Ensure run_results does not leak harmful prompt_preview in stored historical JSON
    try:
        async with conn.execute("SELECT run_id, results_json FROM run_results") as cur:
            rows = await cur.fetchall()
        for row in rows:
            r_id = row["run_id"]
            raw_json = row["results_json"]
            try:
                parsed = json.loads(raw_json)
                changed = False
                if "attacks" in parsed and isinstance(parsed["attacks"], list):
                    for a in parsed["attacks"]:
                        src = a.get("source") or "advbench"
                        cat = a.get("category") or "harmful_behavior"
                        a["source"] = src
                        a["category"] = cat
                        if (
                            src in (
                                "advbench",
                                "advbench+roleplay",
                                "advbench+ignore_instructions",
                                "advbench+academic_research",
                                "advbench+system_override",
                                "advbench+hypothetical",
                            )
                            or cat == "harmful_behavior"
                        ):
                            if a.get("prompt_preview") != "[PROMPT REDACTED FOR PUBLIC VIEW]":
                                a["prompt_preview"] = "[PROMPT REDACTED FOR PUBLIC VIEW]"
                                changed = True
                        elif "prompt_preview" not in a or not a["prompt_preview"]:
                            a["prompt_preview"] = "[PROMPT REDACTED FOR PUBLIC VIEW]"
                            changed = True
                if changed:
                    cleaned_json = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                    await conn.execute(
                        "UPDATE run_results SET results_json = ? WHERE run_id = ?",
                        (cleaned_json, r_id),
                    )
            except Exception:
                pass
    except Exception:
        pass

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


async def save_breakit_report(conn: aiosqlite.Connection, report_json: str, created_at: str) -> None:
    """Persist a break-it probe report."""
    await conn.execute(
        "INSERT INTO breakit_reports (report_json, created_at) VALUES (?, ?)",
        (report_json, created_at),
    )
    await conn.commit()


async def get_latest_breakit_report(conn: aiosqlite.Connection) -> str | None:
    """Fetch the most recent break-it report JSON string."""
    async with conn.execute(
        "SELECT report_json FROM breakit_reports ORDER BY id DESC LIMIT 1"
    ) as cur:
        row = await cur.fetchone()
        return row["report_json"] if row else None


async def save_timing_report(conn: aiosqlite.Connection, report_json: str, created_at: str) -> None:
    """Persist a timing side-channel experiment report."""
    await conn.execute(
        "INSERT INTO timing_reports (report_json, created_at) VALUES (?, ?)",
        (report_json, created_at),
    )
    await conn.commit()


async def get_latest_timing_report(conn: aiosqlite.Connection) -> str | None:
    """Fetch the most recent timing side-channel experiment report JSON string."""
    async with conn.execute(
        "SELECT report_json FROM timing_reports ORDER BY id DESC LIMIT 1"
    ) as cur:
        row = await cur.fetchone()
        return row["report_json"] if row else None
