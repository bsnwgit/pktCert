"""
/api/scan-targets/* — CRUD for active TLS discovery targets (host or CIDR +
port list, on a schedule), plus a manual "Scan Now" trigger.
"""
from __future__ import annotations

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.config import get_settings
from app.database import get_db
from app.dependencies import AdminUser, CurrentUser
from app.cert.scanner import scan_target_once

router = APIRouter()


def _target_out(r) -> dict:
    return {
        "id": r["id"], "name": r["name"], "host": r["host"], "cidr": r["cidr"],
        "ports": r["ports"], "schedule_minutes": r["schedule_minutes"], "enabled": bool(r["enabled"]),
        "last_scan_at": r["last_scan_at"], "last_status": r["last_status"], "last_error": r["last_error"],
        "created_at": r["created_at"],
    }


class ScanTargetRequest(BaseModel):
    name: str
    host: str | None = None
    cidr: str | None = None
    ports: str = "443"
    schedule_minutes: int = 1440
    enabled: bool = True


@router.get("")
async def list_targets(user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM scan_targets ORDER BY name") as cur:
        rows = await cur.fetchall()
    return [_target_out(r) for r in rows]


@router.post("", status_code=201)
async def create_target(body: ScanTargetRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    if not body.host and not body.cidr:
        raise HTTPException(400, "Either host or cidr is required")
    cur = await db.execute(
        """INSERT INTO scan_targets (name, host, cidr, ports, schedule_minutes, enabled)
           VALUES (?, ?, ?, ?, ?, ?) RETURNING *""",
        (body.name, body.host, body.cidr, body.ports, body.schedule_minutes, int(body.enabled)),
    )
    row = await cur.fetchone()
    await db.commit()
    return _target_out(row)


@router.patch("/{target_id}")
async def update_target(target_id: int, body: ScanTargetRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT id FROM scan_targets WHERE id = ?", (target_id,)) as cur:
        if not await cur.fetchone():
            raise HTTPException(404, "Scan target not found")
    await db.execute(
        """UPDATE scan_targets SET name = ?, host = ?, cidr = ?, ports = ?, schedule_minutes = ?, enabled = ?
           WHERE id = ?""",
        (body.name, body.host, body.cidr, body.ports, body.schedule_minutes, int(body.enabled), target_id),
    )
    await db.commit()
    async with db.execute("SELECT * FROM scan_targets WHERE id = ?", (target_id,)) as cur:
        row = await cur.fetchone()
    return _target_out(row)


@router.delete("/{target_id}", status_code=204)
async def delete_target(target_id: int, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("DELETE FROM scan_targets WHERE id = ?", (target_id,))
    await db.commit()


@router.post("/{target_id}/scan-now")
async def scan_now(target_id: int, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT id FROM scan_targets WHERE id = ?", (target_id,)) as cur:
        if not await cur.fetchone():
            raise HTTPException(404, "Scan target not found")
    settings = get_settings()
    result = await scan_target_once(settings.db_path, target_id)
    return result
