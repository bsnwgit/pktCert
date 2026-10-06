"""
Per-address throttle on failed sign-ins.

The account lockout (app/auth/lockout.py) stops one account being guessed at.
It does nothing against one address trying many usernames, or a few passwords
across many accounts. This counts failed credential checks by the address they
came from, whatever username was tried, and blocks the address for a while once
it has made too many.

Three settings, all editable under Settings -> Security -> Auth:

  address_max_failed_attempts       failures allowed from one address (default 10)
  address_failure_window_minutes    how long a failure counts           (default 15)
  address_block_minutes             how long the address is then blocked (default 15)

What counts: a username that does not exist or is disabled, a wrong password,
and a wrong current password at the change-password form. A successful sign-in
does not reset the count, so a valid account cannot be used to dodge the limit.
A request for a locked account is not counted: it is refused before any
password is checked.

The address is the one the connection came from. Behind a proxy on another
host that is the proxy's address, so every user behind it shares one count; a
deployment like that should raise the limit, or throttle at the proxy. This
code does not read X-Forwarded-For (any client can send it); uvicorn applies it
itself only for a proxy on the same machine.
"""
from __future__ import annotations

import logging

import aiosqlite
from fastapi import HTTPException, Request, status

from app.auth.lockout import int_setting

log = logging.getLogger("pktcert.auth")

DEFAULT_MAX_FAILURES = 10
DEFAULT_WINDOW_MINUTES = 15
DEFAULT_BLOCK_MINUTES = 15
_MAX_FAILURES_CEILING = 10_000
_MINUTES_CEILING = 1440

# Failures older than this are of no use whatever the window is set to.
_KEEP = "-1 day"


def client_address(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def blocked_seconds(db: aiosqlite.Connection, address: str) -> int | None:
    """Seconds left on the block, or None when the address is not blocked."""
    async with db.execute(
        "SELECT CAST((julianday(blocked_until) - julianday('now')) * 86400 AS INTEGER) "
        "FROM address_blocks WHERE address = ? AND blocked_until > datetime('now')",
        (address,),
    ) as cur:
        row = await cur.fetchone()
    return max(int(row[0]), 1) if row else None


async def record_failure(db: aiosqlite.Connection, address: str) -> int | None:
    """Count one failed credential check from `address`. Returns the seconds the
    address is now blocked for if this failure reached the limit, else None."""
    limit = await int_setting(db, "address_max_failed_attempts", DEFAULT_MAX_FAILURES, _MAX_FAILURES_CEILING)
    window = await int_setting(db, "address_failure_window_minutes", DEFAULT_WINDOW_MINUTES, _MINUTES_CEILING)
    block = await int_setting(db, "address_block_minutes", DEFAULT_BLOCK_MINUTES, _MINUTES_CEILING)

    await db.execute("DELETE FROM address_failures WHERE ts < datetime('now', ?)", (_KEEP,))
    await db.execute("DELETE FROM address_blocks WHERE blocked_until <= datetime('now')")
    await db.execute("INSERT INTO address_failures (address) VALUES (?)", (address,))
    async with db.execute(
        "SELECT COUNT(*) FROM address_failures WHERE address = ? AND ts > datetime('now', ?)",
        (address, f"-{window} minutes"),
    ) as cur:
        count = (await cur.fetchone())[0]

    if count < limit:
        await db.commit()
        return None

    # The count starts again once the block ends.
    await db.execute("DELETE FROM address_failures WHERE address = ?", (address,))
    await db.execute(
        "INSERT INTO address_blocks (address, blocked_until) VALUES (?, datetime('now', ?)) "
        "ON CONFLICT(address) DO UPDATE SET blocked_until = excluded.blocked_until",
        (address, f"+{block} minutes"),
    )
    await db.commit()
    log.warning(f"Address {address} blocked for {block} minutes after {count} failed sign-ins in {window} minutes")
    return await blocked_seconds(db, address)


def blocked_exception(seconds: int) -> HTTPException:
    minutes = max((seconds + 59) // 60, 1)
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=f"Too many failed sign-in attempts from this address. Try again in about {minutes} minute{'s' if minutes != 1 else ''}.",
        headers={"Retry-After": str(seconds)},
    )
