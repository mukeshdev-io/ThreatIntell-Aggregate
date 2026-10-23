"""
database.py
───────────
SQLite persistence layer.

Schema
──────
lookups
    id          INTEGER  PRIMARY KEY AUTOINCREMENT
    indicator   TEXT     NOT NULL
    ioc_type    TEXT     NOT NULL
    vt_result   TEXT     (JSON blob from VirusTotal, nullable)
    otx_result  TEXT     (JSON blob from OTX, nullable)
    score       REAL     NOT NULL
    verdict     TEXT     NOT NULL
    created_at  TEXT     NOT NULL  (ISO-8601 UTC timestamp)

A result is considered "fresh" if its created_at is within CACHE_TTL_HOURS
of the current UTC time.
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from config import DB_PATH, CACHE_TTL_HOURS

logger = logging.getLogger(__name__)


# ── Public helpers ────────────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    """Open a database connection with row_factory set to Row."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the *lookups* table if it does not already exist."""
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS lookups (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator   TEXT    NOT NULL,
                ioc_type    TEXT    NOT NULL,
                vt_result   TEXT,
                otx_result  TEXT,
                score       REAL    NOT NULL,
                verdict     TEXT    NOT NULL,
                created_at  TEXT    NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_indicator ON lookups (indicator)"
        )
        conn.commit()
    logger.debug("Database initialised at %s", DB_PATH)


def get_cached(indicator: str) -> Optional[dict[str, Any]]:
    """
    Return a cached lookup row for *indicator* if one exists and is still fresh.

    A result is fresh when its ``created_at`` timestamp is within
    ``CACHE_TTL_HOURS`` of the current UTC time.

    Returns ``None`` if no fresh cache entry exists.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=CACHE_TTL_HOURS)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

    with _connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM lookups
            WHERE indicator = ? AND created_at >= ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (indicator.lower(), cutoff_str),
        ).fetchone()

    if row is None:
        return None

    result = dict(row)
    # Deserialise JSON blobs back into dicts.
    for key in ("vt_result", "otx_result"):
        if result[key]:
            try:
                result[key] = json.loads(result[key])
            except json.JSONDecodeError:
                result[key] = None
    logger.debug("Cache hit for %s", indicator)
    return result


def save_lookup(
    indicator: str,
    ioc_type: str,
    vt_result: Optional[dict[str, Any]],
    otx_result: Optional[dict[str, Any]],
    score: float,
    verdict: str,
) -> int:
    """
    Persist a completed lookup to the database.

    Parameters
    ----------
    indicator:
        Normalised IoC string.
    ioc_type:
        One of ``"ipv4"``, ``"domain"``, ``"md5"``, ``"sha1"``, ``"sha256"``.
    vt_result:
        Raw VirusTotal response dict (or ``None`` if the call failed).
    otx_result:
        Raw OTX response dict (or ``None`` if the call failed).
    score:
        Normalised 0-100 risk score.
    verdict:
        ``"Low"``, ``"Medium"``, or ``"High"``.

    Returns
    -------
    int
        The ``rowid`` of the newly inserted row.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO lookups
                (indicator, ioc_type, vt_result, otx_result, score, verdict, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                indicator.lower(),
                ioc_type,
                json.dumps(vt_result) if vt_result else None,
                json.dumps(otx_result) if otx_result else None,
                score,
                verdict,
                now,
            ),
        )
        conn.commit()
    logger.info("Saved lookup for %s (score=%.1f, verdict=%s)", indicator, score, verdict)
    return cur.lastrowid  # type: ignore[return-value]


def get_history(limit: int = 200) -> list[dict[str, Any]]:
    """
    Return the most recent *limit* lookup rows, newest first.

    JSON blobs are left as raw strings so the caller can decide how to render
    them.
    """
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, indicator, ioc_type, score, verdict, created_at
            FROM lookups
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_verdict_counts() -> dict[str, int]:
    """Return a mapping of verdict → count across all stored lookups."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT verdict, COUNT(*) AS cnt FROM lookups GROUP BY verdict"
        ).fetchall()
    return {row["verdict"]: row["cnt"] for row in rows}
