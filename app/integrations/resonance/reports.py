"""
Client-side load failures, reported back so an admin can see them.

When embed.js fails to load its script it logs once to the console and gives up
permanently — no bubble, no retry, nothing on screen. From the user's side the
feature simply does not exist, so it is never reported; from the admin's side
the Settings page says "enabled" and looks fine. The common causes are ordinary
and have nothing to do with resonance itself: an ad blocker eating third-party
script tags, a mistyped server address, resonance being down.

Rows are keyed by day + user + reason, so the table is bounded by users x
reasons x retained days rather than by how often a browser retries.
"""
from __future__ import annotations

import logging

import aiosqlite

log = logging.getLogger("pktcert.resonance.reports")

# Closed set: the reason is written by the browser, so it is untrusted input and
# never reaches the table unless it is one of these.
VALID_REASONS = frozenset({"script_error", "code_error", "frame_timeout"})

RETAIN_DAYS = 30


async def record(db: aiosqlite.Connection, username: str, reason: str) -> bool:
    """Count one failure. Returns False for an unrecognised reason."""
    if reason not in VALID_REASONS:
        return False
    await db.execute(
        """
        INSERT INTO resonance_load_failures (day, username, reason, count, last_seen)
        VALUES (date('now'), ?, ?, 1, datetime('now'))
        ON CONFLICT(day, username, reason) DO UPDATE SET
            count = resonance_load_failures.count + 1,
            last_seen = datetime('now')
        """,
        (username[:64], reason),
    )
    await db.commit()
    return True


async def summary(db: aiosqlite.Connection, days: int = 7) -> dict:
    """Totals for the Settings panel: how many users, how many events, why."""
    offset = f"-{max(1, int(days))} days"
    async with db.execute(
        """
        SELECT COUNT(DISTINCT username), COALESCE(SUM(count), 0)
        FROM resonance_load_failures WHERE day >= date('now', ?)
        """,
        (offset,),
    ) as cur:
        row = await cur.fetchone()
    users, events = (row[0] or 0, row[1] or 0) if row else (0, 0)

    async with db.execute(
        """
        SELECT reason, SUM(count) FROM resonance_load_failures
        WHERE day >= date('now', ?) GROUP BY reason ORDER BY SUM(count) DESC
        """,
        (offset,),
    ) as cur:
        by_reason = {r[0]: r[1] for r in await cur.fetchall()}

    return {"days": days, "users": users, "events": events, "by_reason": by_reason}


async def prune(db: aiosqlite.Connection) -> None:
    await db.execute(
        "DELETE FROM resonance_load_failures WHERE day < date('now', ?)",
        (f"-{RETAIN_DAYS} days",),
    )
    await db.commit()
