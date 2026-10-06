"""
Failed-login lockout for local accounts.

Consecutive failed password attempts against an existing account count up to a
limit (the `login_max_failed_attempts` setting, default 3); they never expire,
only a successful login resets the count. Reaching the limit locks the account
for 30 minutes. After that lock ends, reaching the limit again
locks it permanently, until an admin unlocks it. A successful login clears both
the failure count and the record of earlier lockouts.

While an account is locked the password is not checked at all, so a locked
account cannot be guessed at.

The count covers every place a password is checked against an account: the
login, and the current password asked for when changing one, so a signed-in
session cannot be used to guess it.
"""
from __future__ import annotations

import json
import logging

import aiosqlite
from fastapi import HTTPException, status

log = logging.getLogger("pktcert.auth")

LOCK_MINUTES = 30
DEFAULT_MAX_ATTEMPTS = 3
_MAX_ATTEMPTS_CEILING = 100

# Selected alongside the user row so the lock state comes from the database's
# own clock — locked_until is written with datetime('now', ...), and comparing
# it in Python would mix two clocks and two time zones.
TEMP_LOCKED = "(locked_until IS NOT NULL AND locked_until > datetime('now')) AS temp_locked"
LOCK_COLUMNS = f"is_locked, locked_until, {TEMP_LOCKED}"


def describe(row) -> dict:
    """Lock state of a user row selected with LOCK_COLUMNS."""
    permanent = bool(row["is_locked"])
    temporary = bool(row["temp_locked"]) and not permanent
    return {
        "locked": permanent or temporary,
        "permanent": permanent,
        "until": row["locked_until"] if temporary else None,
    }


def locked_exception(state: dict) -> HTTPException:
    # 423 rather than 401, so a client can tell "locked" from "wrong password".
    if state["permanent"]:
        detail = "This account is locked after repeated failed logins. Contact an administrator to unlock it."
    else:
        detail = f"This account is locked after repeated failed logins. Try again after {state['until']} UTC."
    return HTTPException(status_code=status.HTTP_423_LOCKED, detail=detail)


async def int_setting(db: aiosqlite.Connection, key: str, default: int, ceiling: int) -> int:
    async with db.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cur:
        row = await cur.fetchone()
    if not row:
        return default
    try:
        value = int(json.loads(row[0]))
    except (ValueError, TypeError):
        return default
    return value if 1 <= value <= ceiling else default


async def max_attempts(db: aiosqlite.Connection) -> int:
    return await int_setting(db, "login_max_failed_attempts", DEFAULT_MAX_ATTEMPTS, _MAX_ATTEMPTS_CEILING)


async def record_failure(db: aiosqlite.Connection, user_id: int) -> dict:
    """Count one failed attempt and lock the account if that reaches the limit.
    One UPDATE does the counting and the locking, so two attempts arriving
    together cannot both read the same count. Returns the lock state after."""
    limit = await max_attempts(db)
    await db.execute(
        f"""UPDATE users SET
              failed_login_count = CASE WHEN failed_login_count + 1 >= :limit THEN 0
                                        ELSE failed_login_count + 1 END,
              lockout_count = CASE WHEN failed_login_count + 1 >= :limit
                                   THEN lockout_count + 1 ELSE lockout_count END,
              is_locked = CASE WHEN failed_login_count + 1 >= :limit AND lockout_count + 1 >= 2
                               THEN 1 ELSE is_locked END,
              locked_until = CASE WHEN failed_login_count + 1 >= :limit AND lockout_count + 1 < 2
                                  THEN datetime('now', '+{LOCK_MINUTES} minutes') ELSE locked_until END
            WHERE id = :id""",
        {"limit": limit, "id": user_id},
    )
    await db.commit()
    async with db.execute(f"SELECT username, {LOCK_COLUMNS} FROM users WHERE id = ?", (user_id,)) as cur:
        row = await cur.fetchone()
    state = describe(row)
    if state["permanent"]:
        log.warning(f"Account '{row['username']}' locked permanently after repeated failed logins — an admin must unlock it")
    elif state["locked"]:
        log.warning(f"Account '{row['username']}' locked for {LOCK_MINUTES} minutes after {limit} failed logins")
    return state


async def record_success(db: aiosqlite.Connection, user_id: int) -> None:
    await db.execute(
        "UPDATE users SET failed_login_count = 0, lockout_count = 0, locked_until = NULL WHERE id = ?",
        (user_id,),
    )


async def unlock(db: aiosqlite.Connection, user_id: int) -> bool:
    cur = await db.execute(
        "UPDATE users SET failed_login_count = 0, lockout_count = 0, locked_until = NULL, is_locked = 0 "
        "WHERE id = ?",
        (user_id,),
    )
    await db.commit()
    return cur.rowcount > 0
