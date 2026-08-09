"""
/api/templates/* — issuance templates (key algorithm/size, validity,
key usage / EKU, default CA) used by /api/certificates/issue.
"""
from __future__ import annotations

import json

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.database import get_db
from app.dependencies import AdminUser, CurrentUser

router = APIRouter()


def _template_out(r) -> dict:
    return {
        "id": r["id"], "name": r["name"], "key_algorithm": r["key_algorithm"],
        "key_size": r["key_size"], "validity_days": r["validity_days"],
        "key_usage": json.loads(r["key_usage_json"]),
        "extended_key_usage": json.loads(r["extended_key_usage_json"]),
        "default_ca_id": r["default_ca_id"], "created_at": r["created_at"],
    }


class TemplateRequest(BaseModel):
    name: str
    key_algorithm: str = "rsa"
    key_size: int = 2048
    validity_days: int = 365
    key_usage: list[str] = ["digital_signature", "key_encipherment"]
    extended_key_usage: list[str] = ["server_auth"]
    default_ca_id: int | None = None


@router.get("")
async def list_templates(user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM cert_templates ORDER BY name") as cur:
        rows = await cur.fetchall()
    return [_template_out(r) for r in rows]


@router.post("", status_code=201)
async def create_template(body: TemplateRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    try:
        cur = await db.execute(
            """INSERT INTO cert_templates (name, key_algorithm, key_size, validity_days,
               key_usage_json, extended_key_usage_json, default_ca_id)
               VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING *""",
            (body.name, body.key_algorithm, body.key_size, body.validity_days,
             json.dumps(body.key_usage), json.dumps(body.extended_key_usage), body.default_ca_id),
        )
    except aiosqlite.IntegrityError:
        raise HTTPException(409, f"Template '{body.name}' already exists")
    row = await cur.fetchone()
    await db.commit()
    return _template_out(row)


@router.patch("/{template_id}")
async def update_template(template_id: int, body: TemplateRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT id FROM cert_templates WHERE id = ?", (template_id,)) as cur:
        if not await cur.fetchone():
            raise HTTPException(404, "Template not found")
    await db.execute(
        """UPDATE cert_templates SET name = ?, key_algorithm = ?, key_size = ?, validity_days = ?,
           key_usage_json = ?, extended_key_usage_json = ?, default_ca_id = ? WHERE id = ?""",
        (body.name, body.key_algorithm, body.key_size, body.validity_days,
         json.dumps(body.key_usage), json.dumps(body.extended_key_usage), body.default_ca_id, template_id),
    )
    await db.commit()
    async with db.execute("SELECT * FROM cert_templates WHERE id = ?", (template_id,)) as cur:
        row = await cur.fetchone()
    return _template_out(row)


@router.delete("/{template_id}", status_code=204)
async def delete_template(template_id: int, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("DELETE FROM cert_templates WHERE id = ?", (template_id,))
    await db.commit()
