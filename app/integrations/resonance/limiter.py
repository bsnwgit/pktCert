"""
Rate limiter and circuit breaker for the resonance embed client.

Both live in SQLite rather than in process memory. These apps ship with one
worker by default, but the worker count is configurable and some run more than
one — an in-process counter silently multiplies its own limit once there is
more than one, which is the failure mode where a limiter looks present and
isn't.

The breaker matters more than the limiter here. Resonance applies a geometric
per-IP backoff to repeated failed key attempts, and a pkt app calls it from a
single IP, so a misconfigured key does not degrade one user's experience — it
takes the widget down for everyone and keeps the backoff growing. Config errors
therefore open the breaker after two failures, not six.
"""
from __future__ import annotations

import logging

import aiosqlite

from .errors import ResonanceBreakerOpen, ResonanceError, ResonanceRateLimited

log = logging.getLogger("pktcert.resonance.limiter")

# ── Rate limits ───────────────────────────────────────────────────────────────
# A widget costs one code on page load plus one per session renewal, so a normal
# user spends single digits per day. These are loop-and-abuse backstops, sized to
# leave ordinary reloading alone: 20 per 10 minutes is a reload every 30 seconds,
# sustained, before anyone notices.
USER_LIMIT = 20
USER_WINDOW_SECONDS = 600
GLOBAL_LIMIT = 600
GLOBAL_WINDOW_SECONDS = 600

# ── Breaker ───────────────────────────────────────────────────────────────────
CONFIG_FAILURE_THRESHOLD = 2      # bad key, disabled key, wrong port — retrying cannot help
CONFIG_COOLDOWN_SECONDS = 300
TRANSIENT_FAILURE_THRESHOLD = 6   # timeouts and connection errors — usually self-clearing
TRANSIENT_COOLDOWN_SECONDS = 30


async def consume(db: aiosqlite.Connection, bucket: str, limit: int, window_seconds: int) -> None:
    """Count one request against a fixed window. Raises ResonanceRateLimited when over.

    Increment-then-compare, so the request that trips the limit is the one
    refused. Slightly racy under concurrency by design: this is a backstop, and
    paying for strict serialisation on every page load would cost more than the
    handful of requests the raciness could let through.
    """
    offset = f"-{int(window_seconds)} seconds"
    await db.execute(
        """
        INSERT INTO resonance_rate (bucket, window_start, count)
        VALUES (?, datetime('now'), 1)
        ON CONFLICT(bucket) DO UPDATE SET
            window_start = CASE
                WHEN resonance_rate.window_start <= datetime('now', ?)
                THEN datetime('now') ELSE resonance_rate.window_start END,
            count = CASE
                WHEN resonance_rate.window_start <= datetime('now', ?)
                THEN 1 ELSE resonance_rate.count + 1 END
        """,
        (bucket, offset, offset),
    )
    await db.commit()

    async with db.execute("SELECT count FROM resonance_rate WHERE bucket = ?", (bucket,)) as cur:
        row = await cur.fetchone()
    count = row[0] if row else 0
    if count > limit:
        log.warning("resonance rate limit hit for %s (%d > %d)", bucket, count, limit)
        raise ResonanceRateLimited(f"{bucket}: {count}/{limit}")


async def consume_for_user(db: aiosqlite.Connection, username: str) -> None:
    """Per-user limit first, then the global one, so one looping browser is
    refused before it can spend the whole install's allowance."""
    await consume(db, f"u:{username}", USER_LIMIT, USER_WINDOW_SECONDS)
    await consume(db, "global", GLOBAL_LIMIT, GLOBAL_WINDOW_SECONDS)


async def assert_closed(db: aiosqlite.Connection) -> None:
    """Raise if the breaker is open, without calling resonance."""
    st = await state(db)
    if st["open"]:
        raise ResonanceBreakerOpen(f"retry in {st['retry_in_seconds']}s")


async def state(db: aiosqlite.Connection) -> dict:
    """Breaker state for the Settings panel. A paused integration should say so,
    not look like a feature that quietly does nothing."""
    async with db.execute(
        """
        SELECT consecutive_failures,
               open_until,
               last_error,
               last_failure_at,
               CASE WHEN open_until IS NOT NULL AND open_until > datetime('now')
                    THEN CAST((julianday(open_until) - julianday('now')) * 86400 AS INTEGER)
                    ELSE 0 END
        FROM resonance_breaker WHERE id = 1
        """
    ) as cur:
        row = await cur.fetchone()

    if not row:
        return {"open": False, "failures": 0, "retry_in_seconds": 0, "last_error": "", "last_failure_at": None}

    failures, open_until, last_error, last_failure_at, retry_in = row
    return {
        "open": bool(open_until) and (retry_in or 0) > 0,
        "failures": failures or 0,
        "retry_in_seconds": max(0, retry_in or 0),
        "last_error": last_error or "",
        "last_failure_at": last_failure_at,
    }


async def record_success(db: aiosqlite.Connection) -> None:
    await db.execute(
        "UPDATE resonance_breaker SET consecutive_failures = 0, open_until = NULL, "
        "last_error = '' WHERE id = 1"
    )
    await db.commit()


async def record_failure(db: aiosqlite.Connection, err: ResonanceError) -> None:
    """Count a failure and open the breaker once the relevant threshold is met."""
    threshold = CONFIG_FAILURE_THRESHOLD if err.config_error else TRANSIENT_FAILURE_THRESHOLD
    cooldown = CONFIG_COOLDOWN_SECONDS if err.config_error else TRANSIENT_COOLDOWN_SECONDS

    async with db.execute(
        "SELECT consecutive_failures FROM resonance_breaker WHERE id = 1"
    ) as cur:
        row = await cur.fetchone()
    failures = (row[0] if row else 0) + 1

    if failures >= threshold:
        await db.execute(
            "UPDATE resonance_breaker SET consecutive_failures = ?, "
            "open_until = datetime('now', ?), last_error = ?, "
            "last_failure_at = datetime('now') WHERE id = 1",
            (failures, f"+{int(cooldown)} seconds", err.admin_message),
        )
        log.warning(
            "resonance breaker open for %ds after %d failures: %s",
            cooldown, failures, err.admin_message,
        )
    else:
        await db.execute(
            "UPDATE resonance_breaker SET consecutive_failures = ?, last_error = ?, "
            "last_failure_at = datetime('now') WHERE id = 1",
            (failures, err.admin_message),
        )
    await db.commit()
