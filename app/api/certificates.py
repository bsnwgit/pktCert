"""
/api/certificates/* — the unified certificate inventory (scanned,
CT-discovered, internally issued, or uploaded from an external CA):
list/detail/download, issue new certs from a CA+template, sign an
uploaded CSR, upload an externally-issued cert, revoke, and reveal
secrets (private key / install passcode).

Security model for secrets (private_key_enc, passcode_enc): both are
Fernet-encrypted at rest (app/cert/crypto.py) and are NEVER included in
list/detail responses or the plain GET download route — only
POST /{id}/reveal-secret returns the decrypted value, and that route
requires the caller to re-enter their current password (step-up
re-auth), same bar regardless of whether the cert was issued by pktCert's
own CA or uploaded from an external one. Every successful reveal is
logged to cert_events for audit.
"""
from __future__ import annotations

import asyncio
import json

import aiosqlite
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from app.auth.local import verify_password
from app.database import get_db
from app.dependencies import AdminUser, CurrentUser
from app.cert import x509_utils
from app.cert.crypto import decrypt_str, encrypt_str

router = APIRouter()


def _cert_out(r) -> dict:
    return {
        "id": r["id"], "common_name": r["common_name"], "san": json.loads(r["san_json"] or "[]"),
        "issuer": r["issuer"], "subject": r["subject"], "serial_number": r["serial_number"],
        "fingerprint_sha256": r["fingerprint_sha256"], "not_before": r["not_before"], "not_after": r["not_after"],
        "key_algorithm": r["key_algorithm"], "key_size": r["key_size"], "signature_algorithm": r["signature_algorithm"],
        "status": r["status"], "source": r["source"], "scan_target_id": r["scan_target_id"],
        "host": r["host"], "port": r["port"], "ca_id": r["ca_id"], "template_id": r["template_id"],
        "has_private_key": bool(r["private_key_enc"]), "has_passcode": bool(r["passcode_enc"]),
        "first_seen_at": r["first_seen_at"], "last_seen_at": r["last_seen_at"],
        "revoked_at": r["revoked_at"], "revoked_reason": r["revoked_reason"], "created_at": r["created_at"],
    }


@router.get("")
async def list_certificates(
    user: CurrentUser,
    status: str | None = None,
    source: str | None = None,
    ca_id: int | None = None,
    search: str | None = None,
    limit: int = 500,
    db: aiosqlite.Connection = Depends(get_db),
):
    query = "SELECT * FROM certificates WHERE 1=1"
    params: list = []
    if status:
        query += " AND status = ?"
        params.append(status)
    if source:
        query += " AND source = ?"
        params.append(source)
    if ca_id:
        query += " AND ca_id = ?"
        params.append(ca_id)
    if search:
        query += " AND (common_name LIKE ? OR host LIKE ? OR san_json LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like, like])
    query += " ORDER BY not_after ASC NULLS LAST LIMIT ?"
    params.append(limit)
    async with db.execute(query, params) as cur:
        rows = await cur.fetchall()
    return [_cert_out(r) for r in rows]


@router.get("/{cert_id}")
async def get_certificate(cert_id: int, user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Certificate not found")
    return _cert_out(row)


@router.get("/{cert_id}/download")
async def download_certificate(
    cert_id: int, user: AdminUser, fmt: str = "pem", db: aiosqlite.Connection = Depends(get_db)
):
    """fmt: pem (leaf only) | chain — public certificate data only. The
    private key and install passcode are secrets and are never served from
    a plain GET; use POST /{id}/reveal-secret (requires re-entering your
    current password) for those instead."""
    async with db.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Certificate not found")

    if fmt == "chain":
        return {"pem": row["chain_pem"] or row["cert_pem"]}
    if fmt not in ("pem",):
        raise HTTPException(400, "fmt must be 'pem' or 'chain' — use POST /{id}/reveal-secret for the private key or passcode")
    return {"pem": row["cert_pem"]}


class RevealSecretRequest(BaseModel):
    field: str  # "key" | "passcode"
    password: str


@router.post("/{cert_id}/reveal-secret")
async def reveal_secret(cert_id: int, body: RevealSecretRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    """Step-up re-auth: the caller must supply their *current* password
    again (verified against the users table) before a private key or
    install passcode is decrypted and returned. Every successful reveal is
    logged to cert_events so access to these secrets is auditable. Suite-
    proxied callers (X-Suite-Token, synthetic user id 0) have no local
    password and will always be rejected here — they must log in as a real
    local admin to reveal a secret."""
    if body.field not in ("key", "passcode"):
        raise HTTPException(400, "field must be 'key' or 'passcode'")

    async with db.execute("SELECT hashed_password FROM users WHERE id = ?", (user["id"],)) as cur:
        user_row = await cur.fetchone()
    if not user_row or not verify_password(body.password, user_row["hashed_password"]):
        raise HTTPException(401, "Incorrect password")

    async with db.execute(
        "SELECT common_name, private_key_enc, passcode_enc FROM certificates WHERE id = ?", (cert_id,)
    ) as cur:
        cert_row = await cur.fetchone()
    if not cert_row:
        raise HTTPException(404, "Certificate not found")

    enc = cert_row["private_key_enc"] if body.field == "key" else cert_row["passcode_enc"]
    if not enc:
        raise HTTPException(404, f"No {body.field} stored for this certificate")

    value = decrypt_str(enc)
    await db.execute(
        "INSERT INTO cert_events (certificate_id, event_type, message) VALUES (?, 'secret_accessed', ?)",
        (cert_id, f"{'Private key' if body.field == 'key' else 'Passcode'} revealed by {user['username']}"),
    )
    await db.commit()
    return {body.field: value}


@router.post("/upload", status_code=201)
async def upload_certificate(
    user: AdminUser,
    db: aiosqlite.Connection = Depends(get_db),
    cert_file: UploadFile = File(...),
    key_file: UploadFile | None = File(None),
    passphrase: str = Form(""),
    passcode: str = Form(""),
):
    """Store a certificate issued by an external/outside CA — either as
    separate cert (+ optional key) PEM files, or a single PKCS#12 (.pfx/.p12)
    bundle. An optional install/use passcode (e.g. the PFX export password,
    or a note ops needs to install the cert) is encrypted at rest alongside
    any private key, same as internally-issued certs — see the module
    docstring for the reveal/audit model."""
    raw = await cert_file.read()

    if b"-----BEGIN CERTIFICATE-----" in raw:
        cert_pem = raw.decode()
        chain_pem = cert_pem
        key_pem = None
        if key_file is not None:
            key_raw = await key_file.read()
            key_pem = key_raw.decode()
    else:
        try:
            cert_pem, key_pem, chain_pem = await asyncio.to_thread(
                x509_utils.load_pkcs12_bundle, raw, passphrase or None
            )
        except Exception as e:
            raise HTTPException(400, f"Could not parse certificate file: {e}")

    try:
        info = x509_utils.parse_certificate(cert_pem)
    except Exception as e:
        raise HTTPException(400, f"Invalid certificate: {e}")

    private_key_enc = encrypt_str(key_pem) if key_pem else None
    passcode_enc = encrypt_str(passcode) if passcode else None

    try:
        cur = await db.execute(
            """INSERT INTO certificates
               (common_name, san_json, issuer, subject, serial_number, fingerprint_sha256,
                not_before, not_after, key_algorithm, key_size, signature_algorithm,
                status, source, cert_pem, chain_pem, private_key_enc, passcode_enc)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'valid', 'external', ?, ?, ?, ?) RETURNING *""",
            (info["common_name"], json.dumps(info["san"]), info["issuer"], info["subject"],
             info["serial_number"], info["fingerprint_sha256"], info["not_before"], info["not_after"],
             info["key_algorithm"], info["key_size"], info["signature_algorithm"],
             cert_pem, chain_pem, private_key_enc, passcode_enc),
        )
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "A certificate with this fingerprint already exists")
    row = await cur.fetchone()
    await db.execute(
        "INSERT INTO cert_events (certificate_id, event_type, message) VALUES (?, 'uploaded', ?)",
        (row["id"], f"External certificate uploaded by {user['username']}"),
    )
    await db.commit()
    return _cert_out(row)


class IssueRequest(BaseModel):
    common_name: str
    sans: list[str] = []
    ca_id: int
    template_id: int


def _issue_sync(ca_row: dict, template_row: dict, common_name: str, sans: list[str]) -> tuple:
    ca_cert = x509_utils.cert_from_pem(ca_row["cert_pem"])
    ca_key = x509_utils.key_from_pem(decrypt_str(ca_row["private_key_enc"]))
    leaf_key = x509_utils.generate_private_key(template_row["key_algorithm"], template_row["key_size"])
    csr = x509_utils.generate_csr(common_name, sans, leaf_key)
    cert = x509_utils.sign_certificate(
        csr, ca_cert, ca_key,
        validity_days=template_row["validity_days"],
        key_usage=json.loads(template_row["key_usage_json"]),
        extended_key_usage=json.loads(template_row["extended_key_usage_json"]),
    )
    return x509_utils.cert_to_pem(cert), x509_utils.key_to_pem(leaf_key)


@router.post("/issue", status_code=201)
async def issue_certificate(body: IssueRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM certificate_authorities WHERE id = ?", (body.ca_id,)) as cur:
        ca_row = await cur.fetchone()
    if not ca_row:
        raise HTTPException(404, "CA not found")
    if ca_row["status"] != "active":
        raise HTTPException(400, f"CA is not active (status: {ca_row['status']})")

    async with db.execute("SELECT * FROM cert_templates WHERE id = ?", (body.template_id,)) as cur:
        template_row = await cur.fetchone()
    if not template_row:
        raise HTTPException(404, "Template not found")

    cert_pem, key_pem = await asyncio.to_thread(
        _issue_sync, dict(ca_row), dict(template_row), body.common_name, body.sans or [body.common_name]
    )
    info = x509_utils.parse_certificate(cert_pem)

    cur = await db.execute(
        """INSERT INTO certificates
           (common_name, san_json, issuer, subject, serial_number, fingerprint_sha256,
            not_before, not_after, key_algorithm, key_size, signature_algorithm,
            status, source, cert_pem, private_key_enc, ca_id, template_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'valid', 'issued', ?, ?, ?, ?) RETURNING *""",
        (info["common_name"], json.dumps(info["san"]), info["issuer"], info["subject"],
         info["serial_number"], info["fingerprint_sha256"], info["not_before"], info["not_after"],
         info["key_algorithm"], info["key_size"], info["signature_algorithm"],
         cert_pem, encrypt_str(key_pem), body.ca_id, body.template_id),
    )
    row = await cur.fetchone()
    await db.execute(
        "INSERT INTO cert_events (certificate_id, ca_id, event_type, message) VALUES (?, ?, 'issued', ?)",
        (row["id"], body.ca_id, f"Issued for '{body.common_name}' by CA '{ca_row['name']}'"),
    )
    await db.commit()
    # The private key is shown once, right here, as the direct response to
    # the action that just generated it — no re-auth needed for that (it's
    # not a stored-secret *reveal*, the caller already has it in hand).
    # Any later access goes through POST /{id}/reveal-secret instead.
    return {**_cert_out(row), "private_key_pem": key_pem}


class CsrSignRequest(BaseModel):
    csr_pem: str
    ca_id: int
    template_id: int


def _sign_csr_sync(ca_row: dict, template_row: dict, csr_pem: str) -> str:
    ca_cert = x509_utils.cert_from_pem(ca_row["cert_pem"])
    ca_key = x509_utils.key_from_pem(decrypt_str(ca_row["private_key_enc"]))
    csr = x509_utils.csr_from_pem(csr_pem)
    cert = x509_utils.sign_certificate(
        csr, ca_cert, ca_key,
        validity_days=template_row["validity_days"],
        key_usage=json.loads(template_row["key_usage_json"]),
        extended_key_usage=json.loads(template_row["extended_key_usage_json"]),
    )
    return x509_utils.cert_to_pem(cert)


@router.post("/csr", status_code=201)
async def sign_csr(body: CsrSignRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM certificate_authorities WHERE id = ?", (body.ca_id,)) as cur:
        ca_row = await cur.fetchone()
    if not ca_row:
        raise HTTPException(404, "CA not found")
    async with db.execute("SELECT * FROM cert_templates WHERE id = ?", (body.template_id,)) as cur:
        template_row = await cur.fetchone()
    if not template_row:
        raise HTTPException(404, "Template not found")

    try:
        cert_pem = await asyncio.to_thread(_sign_csr_sync, dict(ca_row), dict(template_row), body.csr_pem)
    except Exception as e:
        raise HTTPException(400, f"Failed to sign CSR: {e}")
    info = x509_utils.parse_certificate(cert_pem)

    cur = await db.execute(
        """INSERT INTO certificates
           (common_name, san_json, issuer, subject, serial_number, fingerprint_sha256,
            not_before, not_after, key_algorithm, key_size, signature_algorithm,
            status, source, cert_pem, ca_id, template_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'valid', 'issued', ?, ?, ?) RETURNING *""",
        (info["common_name"], json.dumps(info["san"]), info["issuer"], info["subject"],
         info["serial_number"], info["fingerprint_sha256"], info["not_before"], info["not_after"],
         info["key_algorithm"], info["key_size"], info["signature_algorithm"],
         cert_pem, body.ca_id, body.template_id),
    )
    row = await cur.fetchone()
    await db.execute(
        "INSERT INTO cert_events (certificate_id, ca_id, event_type, message) VALUES (?, ?, 'issued', ?)",
        (row["id"], body.ca_id, f"CSR signed for '{info['common_name']}' by CA '{ca_row['name']}'"),
    )
    await db.commit()
    return _cert_out(row)


class RevokeRequest(BaseModel):
    reason: str = ""


@router.post("/{cert_id}/revoke")
async def revoke_certificate(cert_id: int, body: RevokeRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Certificate not found")
    await db.execute(
        "UPDATE certificates SET status = 'revoked', revoked_at = datetime('now'), revoked_reason = ? WHERE id = ?",
        (body.reason or None, cert_id),
    )
    await db.execute(
        "INSERT INTO cert_events (certificate_id, ca_id, event_type, message) VALUES (?, ?, 'revoked', ?)",
        (cert_id, row["ca_id"], f"Revoked: {body.reason or 'no reason given'}"),
    )
    await db.commit()
    return {"status": "ok"}
