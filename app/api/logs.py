"""
/api/logs/* — pktCert's own application log (app_logs table), populated by
app/logging_handler.py's SQLiteLogHandler. Single log source — this is not
target/device syslogs, just pktCert's own startup/scan/alert/auth
event stream.
"""
from __future__ import annotations

import logging

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Request

from app.database import get_db
from app.dependencies import CurrentUser, AdminUser

router = APIRouter()

_VALID_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def _log_out(r) -> dict:
    return {
        "id": r["id"], "level": r["level"], "logger": r["logger"],
        "message": r["message"], "exc_info": r["exc_info"], "created_at": r["created_at"],
    }


@router.get("")
async def list_app_logs(
    user: CurrentUser,
    level: str | None = None,
    logger: str | None = None,
    search: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 200,
    offset: int = 0,
    db: aiosqlite.Connection = Depends(get_db),
):
    query = "SELECT * FROM app_logs WHERE 1=1"
    params: list = []
    if level:
        query += " AND level = ?"
        params.append(level.upper())
    if logger:
        query += " AND logger LIKE ?"
        params.append(f"{logger}%")
    if search:
        query += " AND message LIKE ?"
        params.append(f"%{search}%")
    if since:
        query += " AND created_at >= ?"
        params.append(since)
    if until:
        query += " AND created_at <= ?"
        params.append(until)

    count_query = query.replace("SELECT *", "SELECT COUNT(*)", 1)
    async with db.execute(count_query, params) as cur:
        total_row = await cur.fetchone()
    total = total_row[0] if total_row else 0

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    async with db.execute(query, params) as cur:
        rows = await cur.fetchall()
    return {"total": total, "limit": limit, "offset": offset, "records": [_log_out(r) for r in rows]}


@router.get("/stats")
async def log_stats(request: Request, user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT COUNT(*) FROM app_logs") as cur:
        total = (await cur.fetchone())[0]
    async with db.execute("SELECT level, COUNT(*) FROM app_logs GROUP BY level") as cur:
        by_level = {r[0]: r[1] for r in await cur.fetchall()}
    async with db.execute("SELECT DISTINCT logger FROM app_logs ORDER BY logger") as cur:
        loggers = [r[0] for r in await cur.fetchall()]
    async with db.execute("SELECT created_at FROM app_logs ORDER BY id DESC LIMIT 1") as cur:
        latest_row = await cur.fetchone()

    handler = getattr(request.app.state, "log_handler", None)
    capture_level = logging.getLevelName(handler.level) if handler else "WARNING"

    return {
        "total": total, "by_level": by_level, "loggers": loggers,
        "latest_ts": latest_row[0] if latest_row else None, "capture_level": capture_level,
    }


@router.delete("")
async def clear_logs(user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("DELETE FROM app_logs")
    await db.commit()
    return {"status": "ok"}


@router.post("/level")
async def set_capture_level(request: Request, user: AdminUser, level: str):
    level = level.upper()
    if level not in _VALID_LEVELS:
        raise HTTPException(status_code=400, detail=f"level must be one of {_VALID_LEVELS}")
    handler = getattr(request.app.state, "log_handler", None)
    if not handler:
        raise HTTPException(status_code=503, detail="Log handler not available")
    handler.set_level(getattr(logging, level))
    return {"capture_level": level}
