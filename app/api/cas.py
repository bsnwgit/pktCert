"""
/api/cas/* — Certificate Authority management: generate a new root or
intermediate CA, import an existing one, list/inspect, and serve CRLs.

CA private keys are Fernet-encrypted at rest (app/cert/crypto.py) and are
NEVER included in any response body — every read-path here strips
private_key_enc before returning a row.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.database import get_db
from app.dependencies import AdminUser, CurrentUser
from app.cert import x509_utils
from app.cert.crypto import decrypt_str, encrypt_str

router = APIRouter()


def _ca_out(r) -> dict:
    return {
        "id": r["id"], "name": r["name"], "ca_type": r["ca_type"],
        "parent_ca_id": r["parent_ca_id"], "subject": r["subject"],
        "cert_pem": r["cert_pem"], "key_algorithm": r["key_algorithm"],
        "key_size": r["key_size"], "signature_algorithm": r["signature_algorithm"],
        "not_before": r["not_before"], "not_after": r["not_after"],
        "status": r["status"], "crl_number": r["crl_number"], "source": r["source"],
        "created_at": r["created_at"],
    }


class CaGenerateRequest(BaseModel):
    name: str
    ca_type: str = "root"          # root | intermediate
    parent_ca_id: int | None = None
    key_algorithm: str = "rsa"     # rsa | ec
    key_size: int = 4096
    validity_days: int = 3650


class CaImportRequest(BaseModel):
    name: str
    cert_pem: str
    private_key_pem: str
    ca_type: str = "root"
    parent_ca_id: int | None = None


@router.get("")
async def list_cas(user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM certificate_authorities ORDER BY name") as cur:
        rows = await cur.fetchall()
    return [_ca_out(r) for r in rows]


@router.get("/{ca_id}")
async def get_ca(ca_id: int, user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM certificate_authorities WHERE id = ?", (ca_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "CA not found")
    return _ca_out(row)


def _generate_ca_sync(body: CaGenerateRequest, parent_row: dict | None) -> tuple:
    key = x509_utils.generate_private_key(body.key_algorithm, body.key_size)
    parent_cert = parent_key = None
    if parent_row is not None:
        parent_cert = x509_utils.cert_from_pem(parent_row["cert_pem"])
        parent_key = x509_utils.key_from_pem(decrypt_str(parent_row["private_key_enc"]))
    cert = x509_utils.build_ca_certificate(
        body.name, key, ca_type=body.ca_type, validity_days=body.validity_days,
        parent_cert=parent_cert, parent_key=parent_key,
    )
    return x509_utils.cert_to_pem(cert), x509_utils.key_to_pem(key)


@router.post("/generate")
async def generate_ca(body: CaGenerateRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    if body.ca_type not in ("root", "intermediate"):
        raise HTTPException(400, "ca_type must be 'root' or 'intermediate'")

    parent_row = None
    if body.ca_type == "intermediate":
        if not body.parent_ca_id:
            raise HTTPException(400, "parent_ca_id is required for an intermediate CA")
        async with db.execute("SELECT * FROM certificate_authorities WHERE id = ?", (body.parent_ca_id,)) as cur:
            parent_row = await cur.fetchone()
        if not parent_row:
            raise HTTPException(404, "Parent CA not found")

    cert_pem, key_pem = await asyncio.to_thread(_generate_ca_sync, body, dict(parent_row) if parent_row else None)
    info = x509_utils.parse_certificate(cert_pem)

    cur = await db.execute(
        """INSERT INTO certificate_authorities
           (name, ca_type, parent_ca_id, subject, cert_pem, private_key_enc,
            key_algorithm, key_size, signature_algorithm, not_before, not_after, source)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'generated') RETURNING *""",
        (body.name, body.ca_type, body.parent_ca_id, info["subject"], cert_pem, encrypt_str(key_pem),
         body.key_algorithm, body.key_size, info["signature_algorithm"], info["not_before"], info["not_after"]),
    )
    row = await cur.fetchone()
    await db.execute(
        "INSERT INTO cert_events (ca_id, event_type, message) VALUES (?, 'issued', ?)",
        (row["id"], f"CA '{body.name}' generated ({body.ca_type})"),
    )
    await db.commit()
    return _ca_out(row)


@router.post("/import")
async def import_ca(body: CaImportRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    try:
        cert = x509_utils.cert_from_pem(body.cert_pem)
        key = x509_utils.key_from_pem(body.private_key_pem)
    except Exception as e:
        raise HTTPException(400, f"Invalid certificate or private key: {e}")

    info = x509_utils.parse_certificate(body.cert_pem)
    cur = await db.execute(
        """INSERT INTO certificate_authorities
           (name, ca_type, parent_ca_id, subject, cert_pem, private_key_enc,
            key_algorithm, key_size, signature_algorithm, not_before, not_after, source)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'imported') RETURNING *""",
        (body.name, body.ca_type, body.parent_ca_id, info["subject"], body.cert_pem, encrypt_str(body.private_key_pem),
         info["key_algorithm"], info["key_size"], info["signature_algorithm"], info["not_before"], info["not_after"]),
    )
    row = await cur.fetchone()
    await db.execute(
        "INSERT INTO cert_events (ca_id, event_type, message) VALUES (?, 'issued', ?)",
        (row["id"], f"CA '{body.name}' imported"),
    )
    await db.commit()
    return _ca_out(row)


@router.delete("/{ca_id}", status_code=204)
async def delete_ca(ca_id: int, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute(
        "SELECT COUNT(*) AS n FROM certificates WHERE ca_id = ? AND status != 'revoked'", (ca_id,)
    ) as cur:
        row = await cur.fetchone()
    if row and row["n"] > 0:
        raise HTTPException(400, f"CA has {row['n']} active issued certificate(s) — revoke or reassign them first")
    await db.execute("DELETE FROM certificate_authorities WHERE id = ?", (ca_id,))
    await db.commit()


def build_crl_sync(ca_row: dict, revoked: list[dict], crl_number: int) -> str:
    """Shared by this module's authenticated PEM/JSON endpoint (below) and
    app/api/crl.py's unauthenticated DER endpoint referenced by issued
    certs' CRL Distribution Point extension — one CRL-assembly path for
    both, so they never drift."""
    ca_cert = x509_utils.cert_from_pem(ca_row["cert_pem"])
    ca_key = x509_utils.key_from_pem(decrypt_str(ca_row["private_key_enc"]))
    entries = [
        {
            "serial_number": int(r["serial_number"], 16),
            "revoked_at": datetime.fromisoformat(r["revoked_at"]).replace(tzinfo=timezone.utc)
            if r["revoked_at"] and "+" not in r["revoked_at"] else datetime.now(timezone.utc),
        }
        for r in revoked if r["serial_number"]
    ]
    return x509_utils.build_crl(ca_cert, ca_key, entries, crl_number)


@router.get("/{ca_id}/crl")
async def get_crl(ca_id: int, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM certificate_authorities WHERE id = ?", (ca_id,)) as cur:
        ca_row = await cur.fetchone()
    if not ca_row:
        raise HTTPException(404, "CA not found")

    async with db.execute(
        "SELECT serial_number, revoked_at FROM certificates WHERE ca_id = ? AND status = 'revoked'", (ca_id,)
    ) as cur:
        revoked = await cur.fetchall()

    crl_pem = await asyncio.to_thread(build_crl_sync, dict(ca_row), [dict(r) for r in revoked], ca_row["crl_number"] + 1)
    await db.execute(
        "UPDATE certificate_authorities SET crl_number = crl_number + 1 WHERE id = ?", (ca_id,)
    )
    await db.commit()
    return {"crl_pem": crl_pem}
