"""
/api/certificates/* — the unified certificate inventory (scanned,
CT-discovered, internally issued, or uploaded from an external CA):
list/detail/download, issue new certs from a CA+template, sign an
uploaded CSR, upload an externally-issued cert, revoke, and reveal
secrets (private key / install passcode).

Security model for secrets (private_key_enc, passcode_enc): both are
Fernet-encrypted at rest (app/cert/crypto.py) and are NEVER included in
list/detail responses — only POST /{id}/reveal-secret returns the
decrypted value, and that route requires the caller to re-enter their
current password (step-up re-auth), same bar regardless of whether the
cert was issued by pktCert's own CA or uploaded from an external one.

Every certificate download, including the plain public cert/chain PEM
via POST /{id}/download, requires that same password re-entry every
time (no client-side caching across downloads) and is logged to
cert_events for audit — same bar as reveal-secret.
"""
from __future__ import annotations

import asyncio
import json
import re

import aiosqlite
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.auth.local import verify_password
from app.database import get_db
from app.dependencies import AdminUser, AnalystUser, CurrentUser
from app.api import approvals
from app.cert import ct_search, issuance, x509_utils
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
        "key_encrypted": bool(r["key_encrypted"]) if "key_encrypted" in r.keys() else False,
        "first_seen_at": r["first_seen_at"], "last_seen_at": r["last_seen_at"],
        "revoked_at": r["revoked_at"], "revoked_reason": r["revoked_reason"], "created_at": r["created_at"],
        "revoked_reason_code": r["revoked_reason_code"] if "revoked_reason_code" in r.keys() else None,
        # Renewal chain (migration 008). Guarded with a key check so this keeps
        # working against a row read before the migration applied.
        "renewed_from_id": r["renewed_from_id"] if "renewed_from_id" in r.keys() else None,
        "renewed_to_id": r["renewed_to_id"] if "renewed_to_id" in r.keys() else None,
        "auto_renew": bool(r["auto_renew"]) if "auto_renew" in r.keys() else False,
        "auto_renew_days": r["auto_renew_days"] if "auto_renew_days" in r.keys() else 30,
        # Public certificates (migration 017) renew through their managed
        # request rather than a CA and template, so the detail view needs to
        # know which one maintains this certificate to offer renewal at all.
        "public_request_id": r["public_request_id"] if "public_request_id" in r.keys() else None,
        "acme_order_id": r["acme_order_id"] if "acme_order_id" in r.keys() else None,
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


@router.post("/{cert_id}/ct-check")
async def ct_check_certificate(cert_id: int, user: AnalystUser, db: aiosqlite.Connection = Depends(get_db)):
    """Validate one certificate against Certificate Transparency via crt.sh.

    Sends only the certificate's public DNS names to crt.sh — names that cannot
    be public (.local, IPs, single labels) are never sent. Analyst or higher,
    because it spends a third party's free service on the caller's behalf, and
    audit-logged like the other certificate actions."""
    async with db.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Certificate not found")
    async with db.execute("SELECT serial_number FROM certificates WHERE serial_number IS NOT NULL") as cur:
        known_serials = {r["serial_number"] for r in await cur.fetchall()}

    result = await ct_search.validate_against_crtsh(_cert_out(row), known_serials)

    await db.execute(
        "INSERT INTO cert_events (certificate_id, event_type, message) VALUES (?, 'ct_checked', ?)",
        (cert_id, f"Checked against crt.sh by {user['username']}: {result['verdict']}"),
    )
    await db.commit()
    return result


class CtCheckAnyRequest(BaseModel):
    pem: str | None = Field(default=None, max_length=65536)
    host: str | None = Field(default=None, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)


@router.post("/ct-check")
async def ct_check_any(body: CtCheckAnyRequest, user: AnalystUser, db: aiosqlite.Connection = Depends(get_db)):
    """Validate a certificate that is not in the inventory against crt.sh.

    Takes either a PEM or a host and port to fetch it from. Fetching makes this
    server open a connection to a caller-chosen address, which is the same power
    scan targets have, so it needs the same role: admin. A PEM only needs
    analyst. Nothing is stored — the certificate is checked and forgotten."""
    if bool(body.pem) == bool(body.host):
        raise HTTPException(400, "Provide either a PEM certificate or a host, not both and not neither")

    fetched_from = None
    if body.host:
        if user["role"] != "admin":
            raise HTTPException(403, "Admin role required to fetch a certificate from a host")
        host = body.host.strip()
        if not re.fullmatch(r"[A-Za-z0-9._:-]+", host):
            raise HTTPException(400, "Host must be a DNS name or IP address")
        try:
            pem, _chain = await asyncio.to_thread(x509_utils.fetch_cert_chain, host, body.port, 8.0)
        except Exception as e:
            raise HTTPException(502, f"Could not fetch a certificate from {host}:{body.port} ({type(e).__name__})")
        fetched_from = f"{host}:{body.port}"
    else:
        pem = body.pem

    try:
        info = x509_utils.parse_certificate(pem)
    except Exception:
        raise HTTPException(400, "That is not a readable PEM certificate")

    async with db.execute("SELECT id, serial_number FROM certificates WHERE serial_number IS NOT NULL") as cur:
        inventory = await cur.fetchall()
    known_serials = {r["serial_number"] for r in inventory}

    result = await ct_search.validate_against_crtsh(info, known_serials)
    result["certificate"] = {
        "common_name": info["common_name"], "san": info["san"], "issuer": info["issuer"],
        "serial_number": info["serial_number"], "fingerprint_sha256": info["fingerprint_sha256"],
        "not_before": info["not_before"], "not_after": info["not_after"], "fetched_from": fetched_from,
    }

    # Only a certificate that is in the inventory has an audit trail to write to.
    mine = next((r["id"] for r in inventory
                 if ct_search._norm_serial(r["serial_number"]) == ct_search._norm_serial(info["serial_number"])), None)
    result["in_inventory_id"] = mine
    if mine is not None:
        await db.execute(
            "INSERT INTO cert_events (certificate_id, event_type, message) VALUES (?, 'ct_checked', ?)",
            (mine, f"Checked against crt.sh by {user['username']}: {result['verdict']}"),
        )
        await db.commit()
    return result


class DownloadRequest(BaseModel):
    fmt: str = "pem"  # pem (leaf only) | chain
    password: str


async def _step_up_row(db: aiosqlite.Connection, user: dict):
    """The local account whose password authorises a step-up, or None.

    A suite-proxied caller is pktHub presenting somebody it has already
    authenticated, under a synthetic identity with id 0 and no row of its own —
    so looking the password up by id finds nothing and every step-up fails,
    whatever was typed. Match on the username pktHub sends instead, and the
    check means exactly what it means on a direct login: a real password,
    against a real active account, logged the same way.

    This is the one thing that must not be relaxed to make managed mode work.
    Waving a suite token through without a password would remove step-up from
    private key material in a certificate authority, which is the property
    tests/test_export_stepup.py exists to hold.
    """
    if user.get("_via_suite"):
        async with db.execute(
            "SELECT hashed_password FROM users WHERE username = ? AND is_active = 1",
            (user.get("username") or "",),
        ) as cur:
            return await cur.fetchone()
    async with db.execute(
        "SELECT hashed_password FROM users WHERE id = ?", (user["id"],)
    ) as cur:
        return await cur.fetchone()


def _check_step_up(user: dict, row, password: str) -> None:
    """Reject a bad password, and say plainly when there is no account to check.

    The two are worth telling apart. A hub user with no pktCert account of the
    same name can retype a correct password forever and be told it is wrong;
    naming the cause is what turns that into something an admin can fix. The
    caller is already authenticated by this point, so this discloses nothing to
    anyone who was not already inside.
    """
    if not row or not row["hashed_password"]:
        if user.get("_via_suite"):
            raise HTTPException(
                401,
                f"No pktCert account named '{user.get('username')}' to check a password against. "
                "Downloads and reveals need a local pktCert account of the same name as the "
                "pktHub user — create one, or open pktCert directly and sign in.",
            )
        raise HTTPException(401, "Incorrect password")
    if not verify_password(password, row["hashed_password"]):
        raise HTTPException(401, "Incorrect password")


@router.post("/{cert_id}/download")
async def download_certificate(
    cert_id: int, body: DownloadRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)
):
    """Every download — even of the public certificate/chain PEM, not just
    the private key or passcode — requires re-entering the caller's current
    password, same step-up re-auth as /reveal-secret, and is logged the same
    way. Nothing is cached client-side: each download prompts again."""
    if body.fmt not in ("pem", "chain"):
        raise HTTPException(400, "fmt must be 'pem' or 'chain' — use POST /{id}/reveal-secret for the private key or passcode")

    _check_step_up(user, await _step_up_row(db, user), body.password)

    async with db.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Certificate not found")

    await db.execute(
        "INSERT INTO cert_events (certificate_id, event_type, message) VALUES (?, 'downloaded', ?)",
        (cert_id, f"{body.fmt} downloaded by {user['username']}"),
    )
    await db.commit()

    if body.fmt == "chain":
        return {"pem": row["chain_pem"] or row["cert_pem"]}
    return {"pem": row["cert_pem"]}


class RevealSecretRequest(BaseModel):
    field: str  # "key" | "passcode"
    password: str
    # pkcs8 is the default because it is what everything current reads. pkcs1
    # exists for appliances that only parse the traditional form — see
    # x509_utils.key_pem_to_pkcs1. Ignored for a passcode, which is not a key.
    key_format: str = "pkcs8"  # pkcs8 | pkcs1


@router.post("/{cert_id}/reveal-secret")
async def reveal_secret(cert_id: int, body: RevealSecretRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    """Step-up re-auth: the caller must supply their *current* password
    again (verified against the users table) before a private key or
    install passcode is decrypted and returned. Every successful reveal is
    logged to cert_events so access to these secrets is auditable. A suite-
    proxied caller is checked against the local account matching the username
    pktHub sends — see _step_up_row — so this works in managed mode without the
    password ever becoming optional."""
    if body.field not in ("key", "passcode"):
        raise HTTPException(400, "field must be 'key' or 'passcode'")
    if body.key_format not in ("pkcs8", "pkcs1"):
        raise HTTPException(400, "key_format must be 'pkcs8' or 'pkcs1'")

    _check_step_up(user, await _step_up_row(db, user), body.password)

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

    if body.field == "key" and body.key_format == "pkcs1":
        # A key exported under a passphrase stays as it is: pktCert never kept
        # that passphrase, so there is nothing here to open it with. Saying so
        # beats handing back a PKCS#8 file the appliance will refuse in silence.
        if "ENCRYPTED" in value:
            raise HTTPException(
                400,
                "This key is stored passphrase-protected, so pktCert cannot rewrite it as "
                "PKCS#1 — it does not hold the passphrase. Download it as PKCS#8 and convert "
                "it yourself with: openssl rsa -in key.pem -out key-pkcs1.pem",
            )
        try:
            value = x509_utils.key_pem_to_pkcs1(value)
        except Exception as exc:
            raise HTTPException(400, f"Could not rewrite this key as PKCS#1: {exc}") from exc

    await db.execute(
        "INSERT INTO cert_events (certificate_id, event_type, message) VALUES (?, 'secret_accessed', ?)",
        (cert_id, f"{'Private key' if body.field == 'key' else 'Passcode'} revealed by {user['username']}"
                  + (" (PKCS#1)" if body.field == "key" and body.key_format == "pkcs1" else "")),
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
    # Optional passphrase applied to the *exported* private key. When set, the
    # returned/stored key PEM is encrypted with it, so installing the key on a
    # remote server requires entering this secret. Not stored by pktCert.
    key_passphrase: str = ""
    auto_renew: bool = False
    auto_renew_days: int = 30
    # Shown to whoever approves this, when approval is required. Ignored
    # otherwise.
    justification: str = ""


@router.post("/issue", status_code=201)
async def issue_certificate(body: IssueRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM certificate_authorities WHERE id = ?", (body.ca_id,)) as cur:
        ca_row = await cur.fetchone()
    if not ca_row:
        raise HTTPException(404, "CA not found")
    if ca_row["status"] != "active":
        raise HTTPException(400, f"CA is not active (status: {ca_row['status']})")
    refusal = issuance.signing_refusal(ca_row)
    if refusal:
        raise HTTPException(400, refusal)

    async with db.execute("SELECT * FROM cert_templates WHERE id = ?", (body.template_id,)) as cur:
        template_row = await cur.fetchone()
    if not template_row:
        raise HTTPException(404, "Template not found")

    # Separation of duties, when it's switched on (off by default — see
    # app/api/approvals.py). Nothing is issued here; a second admin's approval
    # is what performs the issuance.
    if await approvals.approval_required(db, "issue"):
        request_row = await approvals.create_request(
            db, user, "issue",
            common_name=body.common_name, sans=body.sans,
            ca_id=body.ca_id, template_id=body.template_id,
            auto_renew=body.auto_renew, auto_renew_days=body.auto_renew_days,
            justification=body.justification,
        )
        return JSONResponse(
            status_code=202,
            content={
                "pending_approval": True,
                "request_id": request_row["id"],
                "detail": (
                    f"Request {request_row['id']} is awaiting approval from another admin. "
                    "The certificate and its private key are created at approval time."
                ),
            },
        )

    row, key_pem = await issuance.issue_certificate(
        db, ca_row, template_row, body.common_name, body.sans,
        key_passphrase=body.key_passphrase or "",
        auto_renew=body.auto_renew, auto_renew_days=body.auto_renew_days,
    )
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


def _sign_csr_sync(ca_row: dict, template_row: dict, csr_pem: str, crl_url: str, aia_url: str) -> str:
    ca_cert = x509_utils.cert_from_pem(ca_row["cert_pem"])
    ca_key = x509_utils.key_from_pem(decrypt_str(ca_row["private_key_enc"]))
    csr = x509_utils.csr_from_pem(csr_pem)

    # Proof of possession. A CSR is self-signed with the very key it asks us
    # to certify, so this signature is the only evidence the requester holds
    # the private key for the public key we're about to bind their name to.
    # Without the check, anyone could lift someone else's public key into a
    # CSR and be issued a certificate for it.
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid — it was not signed by the key it presents")

    cert = x509_utils.sign_certificate(
        csr, ca_cert, ca_key,
        validity_days=template_row["validity_days"],
        key_usage=json.loads(template_row["key_usage_json"]),
        extended_key_usage=json.loads(template_row["extended_key_usage_json"]),
        crl_url=crl_url,
        aia_url=aia_url,
    )
    return x509_utils.cert_to_pem(cert)


@router.post("/csr", status_code=201)
async def sign_csr(body: CsrSignRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM certificate_authorities WHERE id = ?", (body.ca_id,)) as cur:
        ca_row = await cur.fetchone()
    if not ca_row:
        raise HTTPException(404, "CA not found")
    if ca_row["status"] != "active":
        raise HTTPException(400, f"CA is not active (status: {ca_row['status']})")
    refusal = issuance.signing_refusal(ca_row)
    if refusal:
        raise HTTPException(400, refusal)
    async with db.execute("SELECT * FROM cert_templates WHERE id = ?", (body.template_id,)) as cur:
        template_row = await cur.fetchone()
    if not template_row:
        raise HTTPException(404, "Template not found")

    # Same CRL Distribution Point the /issue path stamps on. Without it a
    # CSR-signed certificate can be revoked here and no relying party can
    # ever discover that — the revocation would live only in this database.
    base_url = await issuance.get_crl_base_url(db)
    crl_url = f"{base_url}/crl/{body.ca_id}.crl"
    aia_url = f"{base_url}/aia/{body.ca_id}.crt"

    try:
        cert_pem = await asyncio.to_thread(
            _sign_csr_sync, dict(ca_row), dict(template_row), body.csr_pem, crl_url, aia_url
        )
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


class RenewRequest(BaseModel):
    # Renewal always generates a fresh keypair. Re-certifying the same public
    # key would carry any compromise of the old key straight into the new
    # certificate, and pktCert has no way to know whether that key has been
    # copied around servers in the meantime.
    key_passphrase: str = ""
    auto_renew: bool | None = None      # None = inherit the previous cert's setting
    auto_renew_days: int | None = None


@router.post("/{cert_id}/renew", status_code=201)
async def renew_certificate(
    cert_id: int, body: RenewRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)
):
    """Replace a certificate with a freshly issued one carrying the same
    subject and SANs, from the same CA and template.

    The old certificate is marked 'superseded' rather than revoked. It stays
    valid and deployed until whoever installs the replacement gets to it —
    revoking it here would break the running service immediately. Revoke it
    yourself once the new one is in place.
    """
    async with db.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,)) as cur:
        old = await cur.fetchone()
    if not old:
        raise HTTPException(404, "Certificate not found")
    if old["source"] != "issued" or not old["ca_id"] or not old["template_id"]:
        raise HTTPException(
            400,
            "Only certificates issued by pktCert can be renewed — a discovered or "
            "externally-issued certificate has to be replaced at its own CA.",
        )
    if old["status"] == "superseded" and old["renewed_to_id"]:
        raise HTTPException(400, f"Already renewed by certificate {old['renewed_to_id']}")

    async with db.execute("SELECT * FROM certificate_authorities WHERE id = ?", (old["ca_id"],)) as cur:
        ca_row = await cur.fetchone()
    if not ca_row:
        raise HTTPException(404, "Issuing CA no longer exists")
    if ca_row["status"] != "active":
        raise HTTPException(400, f"Issuing CA is not active (status: {ca_row['status']})")
    refusal = issuance.signing_refusal(ca_row)
    if refusal:
        raise HTTPException(400, refusal)

    async with db.execute("SELECT * FROM cert_templates WHERE id = ?", (old["template_id"],)) as cur:
        template_row = await cur.fetchone()
    if not template_row:
        raise HTTPException(404, "Template used for the original certificate no longer exists")

    try:
        sans = json.loads(old["san_json"] or "[]")
    except ValueError:
        sans = []

    row, key_pem = await issuance.issue_certificate(
        db, ca_row, template_row, old["common_name"], sans,
        key_passphrase=body.key_passphrase or "",
        renewed_from_id=cert_id,
        auto_renew=old["auto_renew"] if body.auto_renew is None else body.auto_renew,
        auto_renew_days=old["auto_renew_days"] if body.auto_renew_days is None else body.auto_renew_days,
    )
    await issuance.supersede(db, cert_id, row["id"])
    await db.execute(
        "INSERT INTO cert_events (certificate_id, ca_id, event_type, message) VALUES (?, ?, 'renewed', ?)",
        (row["id"], ca_row["id"],
         f"Renewed '{old['common_name']}' (replaces certificate {cert_id}) by {user['username']}"),
    )
    await db.execute(
        "INSERT INTO cert_events (certificate_id, ca_id, event_type, message) VALUES (?, ?, 'renewed', ?)",
        (cert_id, ca_row["id"], f"Superseded by certificate {row['id']}"),
    )
    await db.commit()
    # Same contract as /issue: the new private key is shown once, here, as the
    # direct response to the action that generated it.
    return {**_cert_out(row), "private_key_pem": key_pem}


class AutoRenewRequest(BaseModel):
    auto_renew: bool
    auto_renew_days: int = 30


@router.patch("/{cert_id}/auto-renew")
async def set_auto_renew(
    cert_id: int, body: AutoRenewRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)
):
    """Turn automatic renewal on or off for one certificate."""
    async with db.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Certificate not found")
    if body.auto_renew and (row["source"] != "issued" or not row["ca_id"] or not row["template_id"]):
        raise HTTPException(400, "Only certificates issued by pktCert can be auto-renewed")
    if body.auto_renew_days < 1:
        raise HTTPException(400, "auto_renew_days must be at least 1")

    await db.execute(
        "UPDATE certificates SET auto_renew = ?, auto_renew_days = ? WHERE id = ?",
        (int(body.auto_renew), body.auto_renew_days, cert_id),
    )
    await db.commit()
    async with db.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,)) as cur:
        updated = await cur.fetchone()
    return _cert_out(updated)


class RevokeRequest(BaseModel):
    reason: str = ""
    # RFC 5280 reasonCode, published in the CRL entry so relying parties can
    # tell a compromised key from a routine replacement. The free-text `reason`
    # above stays a human note and never leaves this database.
    reason_code: str = "unspecified"
    justification: str = ""


@router.post("/{cert_id}/revoke")
async def revoke_certificate(cert_id: int, body: RevokeRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    if body.reason_code not in x509_utils.REASON_CODES:
        raise HTTPException(
            400,
            f"reason_code must be one of: {', '.join(sorted(x509_utils.REASON_CODES))}",
        )

    async with db.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Certificate not found")

    # Separation of duties, when switched on. Revocation is as consequential as
    # issuance in the other direction — it can take a service offline — so it
    # gets its own toggle rather than riding on the issuance one.
    if await approvals.approval_required(db, "revoke"):
        request_row = await approvals.create_request(
            db, user, "revoke",
            certificate_id=cert_id, reason=body.reason, reason_code=body.reason_code,
            ca_id=row["ca_id"], justification=body.justification,
        )
        return JSONResponse(
            status_code=202,
            content={
                "pending_approval": True,
                "request_id": request_row["id"],
                "detail": (
                    f"Request {request_row['id']} is awaiting approval from another admin. "
                    "The certificate is still valid until then."
                ),
            },
        )

    await db.execute(
        """UPDATE certificates SET status = 'revoked', revoked_at = datetime('now'),
           revoked_reason = ?, revoked_reason_code = ? WHERE id = ?""",
        (body.reason or None, body.reason_code, cert_id),
    )
    await db.execute(
        "INSERT INTO cert_events (certificate_id, ca_id, event_type, message) VALUES (?, ?, 'revoked', ?)",
        (cert_id, row["ca_id"],
         f"Revoked ({body.reason_code}): {body.reason or 'no further detail'}"),
    )
    await db.commit()
    return {"status": "ok", "reason_code": body.reason_code}
