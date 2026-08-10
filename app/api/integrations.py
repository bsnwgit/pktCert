"""
/api/integrations/* — named connections to sibling pkt* apps, so pktCert
can reuse data they've already collected (e.g. pktIPAM's known host/subnet
inventory to help seed Scan Targets) instead of re-discovering it from
scratch. Multiple named instances per app_name are supported — separate
from /api/suite/*, which is the INBOUND side (pktHub calling into pktCert).

Setup: on the sibling app, open Settings -> Security -> Suite Integration
and copy its suite token, then paste that app's base_url and the token
here — you can add as many named connections as you have deployments.
"""
from __future__ import annotations

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.database import get_db
from app.dependencies import CurrentUser, AdminUser
from app.integrations.suite_client import SuiteClient
from app.cert.crypto import decrypt_str, encrypt_str

router = APIRouter()

_APPS = ("pktipam", "pktsnmp", "pktflow", "pktlog", "pktpcap", "pkthub")


class IntegrationCreate(BaseModel):
    name: str
    app_name: str
    base_url: str
    suite_token: str
    enabled: bool = True
    verify_tls: bool = True


class IntegrationUpdate(BaseModel):
    name: str | None = None
    base_url: str | None = None
    suite_token: str | None = None
    enabled: bool | None = None
    verify_tls: bool | None = None


def _verify_tls(r) -> bool:
    """verify_tls column added in migration 005; default to secure if absent."""
    return bool(r["verify_tls"]) if "verify_tls" in r.keys() and r["verify_tls"] is not None else True


def _out(r) -> dict:
    return {
        "id": r["id"], "name": r["name"], "app_name": r["app_name"], "base_url": r["base_url"],
        "has_token": bool(r["suite_token"]), "enabled": bool(r["enabled"]),
        "verify_tls": _verify_tls(r),
        "health_status": r["health_status"], "last_health_check": r["last_health_check"],
    }


@router.get("")
async def list_integrations(user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM integrations ORDER BY name") as cur:
        rows = await cur.fetchall()
    return [_out(r) for r in rows]


@router.post("", status_code=201)
async def create_integration(body: IntegrationCreate, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    if body.app_name not in _APPS:
        raise HTTPException(status_code=400, detail=f"app_name must be one of {_APPS}")
    try:
        cur = await db.execute(
            """INSERT INTO integrations (name, app_name, base_url, suite_token, enabled, verify_tls)
               VALUES (?, ?, ?, ?, ?, ?) RETURNING *""",
            (body.name, body.app_name, body.base_url.rstrip("/"),
             encrypt_str(body.suite_token) if body.suite_token else "", int(body.enabled), int(body.verify_tls)),
        )
        row = await cur.fetchone()
        await db.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(status_code=409, detail=f"An integration named '{body.name}' already exists")
    return _out(row)


@router.put("/{integration_id}")
async def update_integration(integration_id: int, body: IntegrationUpdate, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM integrations WHERE id = ?", (integration_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Integration not found")
    existing = dict(row)
    updates = body.model_dump(exclude_none=True)
    if "base_url" in updates:
        updates["base_url"] = updates["base_url"].rstrip("/")
    if "suite_token" in updates:
        # Only re-encrypt when a new plaintext token was actually supplied —
        # existing["suite_token"] is already Fernet-encrypted, encrypting it
        # again would make it undecryptable.
        updates["suite_token"] = encrypt_str(updates["suite_token"]) if updates["suite_token"] else ""
    existing.update(updates)
    try:
        await db.execute(
            """UPDATE integrations SET name = ?, base_url = ?, suite_token = ?, enabled = ?,
               verify_tls = ?, updated_at = datetime('now') WHERE id = ?""",
            (existing["name"], existing["base_url"], existing["suite_token"], int(existing["enabled"]),
             int(_verify_tls(existing)), integration_id),
        )
        await db.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(status_code=409, detail=f"An integration named '{existing['name']}' already exists")
    async with db.execute("SELECT * FROM integrations WHERE id = ?", (integration_id,)) as cur:
        row = await cur.fetchone()
    return _out(row)


@router.delete("/{integration_id}", status_code=204)
async def delete_integration(integration_id: int, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("DELETE FROM integrations WHERE id = ?", (integration_id,))
    await db.commit()


@router.post("/{integration_id}/test")
async def test_integration(integration_id: int, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM integrations WHERE id = ?", (integration_id,)) as cur:
        row = await cur.fetchone()
    if not row or not row["base_url"]:
        raise HTTPException(status_code=400, detail="Integration is not configured yet")

    client = SuiteClient(row["base_url"], decrypt_str(row["suite_token"]), suite_user="pktcert",
                         suite_role="admin", verify_tls=_verify_tls(row))
    healthy, detail = await client.health_check()
    status_str = "ok" if healthy else "error"
    await db.execute(
        "UPDATE integrations SET health_status = ?, last_health_check = datetime('now') WHERE id = ?",
        (status_str, integration_id),
    )
    await db.commit()
    return {"healthy": healthy, "detail": detail}
