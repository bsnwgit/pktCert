"""
/api/enrollment-profiles/* — managing the credentials devices enrol with.

A profile is the unit of authorisation for EST and SCEP: a shared secret bound
to one CA and one template, optionally limited to one name suffix and to a
maximum number of certificates.

The secret is a bearer credential — anything holding it can obtain a
certificate, which is unavoidable for unattended device enrolment. So the
containment is in how little any one profile can do, and in being able to see
and revoke it: the secret is shown exactly once, at creation, and is
Fernet-encrypted at rest thereafter like every other secret pktCert holds.
"""
from __future__ import annotations

import secrets

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.cert.crypto import encrypt_str
from app.database import get_db
from app.dependencies import AdminUser, CurrentUser

router = APIRouter()

_PROTOCOLS = {"est", "scep"}


def _out(r) -> dict:
    return {
        "id": r["id"], "name": r["name"], "protocol": r["protocol"],
        "ca_id": r["ca_id"], "template_id": r["template_id"],
        "username": r["username"], "enabled": bool(r["enabled"]),
        "allowed_name_suffix": r["allowed_name_suffix"],
        "max_certs": r["max_certs"], "issued_count": r["issued_count"],
        "created_at": r["created_at"], "last_used_at": r["last_used_at"],
        # Never the secret itself — it is shown once at creation and never again.
    }


class ProfileRequest(BaseModel):
    name: str
    protocol: str
    ca_id: int
    template_id: int
    username: str = ""
    allowed_name_suffix: str = ""
    max_certs: int | None = None
    enabled: bool = True
    # Left empty, pktCert generates one. Better than letting an operator pick
    # a memorable string for a credential that mints certificates.
    secret: str = ""


@router.get("")
async def list_profiles(user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM enrollment_profiles ORDER BY name") as cur:
        return [_out(r) for r in await cur.fetchall()]


@router.post("", status_code=201)
async def create_profile(body: ProfileRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    if body.protocol not in _PROTOCOLS:
        raise HTTPException(400, f"protocol must be one of: {', '.join(sorted(_PROTOCOLS))}")
    if body.protocol == "est" and not body.username.strip():
        raise HTTPException(400, "EST profiles need a username — devices authenticate with HTTP Basic")

    async with db.execute("SELECT status FROM certificate_authorities WHERE id = ?", (body.ca_id,)) as cur:
        ca = await cur.fetchone()
    if not ca:
        raise HTTPException(404, "CA not found")
    async with db.execute("SELECT id FROM cert_templates WHERE id = ?", (body.template_id,)) as cur:
        if not await cur.fetchone():
            raise HTTPException(404, "Template not found")

    secret = body.secret or secrets.token_urlsafe(24)

    try:
        cur = await db.execute(
            """INSERT INTO enrollment_profiles
               (name, protocol, ca_id, template_id, username, secret_enc, enabled,
                allowed_name_suffix, max_certs)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *""",
            (body.name, body.protocol, body.ca_id, body.template_id,
             body.username.strip() or None, encrypt_str(secret), int(body.enabled),
             body.allowed_name_suffix.strip() or None, body.max_certs),
        )
    except aiosqlite.IntegrityError:
        raise HTTPException(409, f"An enrolment profile named '{body.name}' already exists")
    row = await cur.fetchone()
    await db.commit()
    # The only time the secret is ever returned.
    return {**_out(row), "secret": secret}


@router.patch("/{profile_id}")
async def update_profile(
    profile_id: int, body: ProfileRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)
):
    async with db.execute("SELECT * FROM enrollment_profiles WHERE id = ?", (profile_id,)) as cur:
        existing = await cur.fetchone()
    if not existing:
        raise HTTPException(404, "Enrolment profile not found")

    await db.execute(
        """UPDATE enrollment_profiles SET name = ?, ca_id = ?, template_id = ?, username = ?,
           enabled = ?, allowed_name_suffix = ?, max_certs = ? WHERE id = ?""",
        (body.name, body.ca_id, body.template_id, body.username.strip() or None,
         int(body.enabled), body.allowed_name_suffix.strip() or None, body.max_certs, profile_id),
    )
    await db.commit()
    async with db.execute("SELECT * FROM enrollment_profiles WHERE id = ?", (profile_id,)) as cur:
        return _out(await cur.fetchone())


@router.post("/{profile_id}/rotate-secret")
async def rotate_secret(profile_id: int, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    """Replace the secret. Every device still using the old one stops enrolling
    immediately — which is the point when a secret has leaked, and the reason
    profiles are scoped narrowly enough that rotating one is survivable."""
    async with db.execute("SELECT id FROM enrollment_profiles WHERE id = ?", (profile_id,)) as cur:
        if not await cur.fetchone():
            raise HTTPException(404, "Enrolment profile not found")
    secret = secrets.token_urlsafe(24)
    await db.execute(
        "UPDATE enrollment_profiles SET secret_enc = ? WHERE id = ?", (encrypt_str(secret), profile_id)
    )
    await db.commit()
    return {"secret": secret}


@router.delete("/{profile_id}", status_code=204)
async def delete_profile(profile_id: int, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("DELETE FROM enrollment_profiles WHERE id = ?", (profile_id,))
    await db.commit()


@router.get("/log")
async def enrollment_log(
    user: CurrentUser,
    outcome: str | None = None,
    limit: int = 200,
    db: aiosqlite.Connection = Depends(get_db),
):
    query = "SELECT * FROM enrollment_log"
    params: list = []
    if outcome:
        query += " WHERE outcome = ?"
        params.append(outcome)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    async with db.execute(query, params) as cur:
        rows = await cur.fetchall()
    return [
        {
            "id": r["id"], "profile_id": r["profile_id"], "protocol": r["protocol"],
            "operation": r["operation"], "client_ip": r["client_ip"], "subject": r["subject"],
            "outcome": r["outcome"], "detail": r["detail"],
            "certificate_id": r["certificate_id"], "created_at": r["created_at"],
        }
        for r in rows
    ]
