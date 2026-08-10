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

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.database import get_db
from app.dependencies import AdminUser, CurrentUser
from app.cert import crl_manager, issuance, x509_utils
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
        # Constraint metadata (migration 009), guarded so a row read before the
        # migration applied still renders.
        "path_length": r["path_length"] if "path_length" in r.keys() else None,
        # Offline-root support (migration 011).
        "key_storage": r["key_storage"] if "key_storage" in r.keys() else "local",
        "has_csr": bool(r["csr_pem"]) if "csr_pem" in r.keys() else False,
        "has_uploaded_crl": bool(r["uploaded_crl_pem"]) if "uploaded_crl_pem" in r.keys() else False,
        "name_constraints": (
            json.loads(r["name_constraints_json"])
            if "name_constraints_json" in r.keys() and r["name_constraints_json"]
            else None
        ),
    }


class CaGenerateRequest(BaseModel):
    name: str
    ca_type: str = "root"          # root | intermediate
    parent_ca_id: int | None = None
    key_algorithm: str = "rsa"     # rsa | ec
    key_size: int = 4096
    validity_days: int = 3650
    # How many further CAs may sit below this one. Left unset, an intermediate
    # gets 0 (it may issue end-entity certificates but not another CA) and a
    # root stays unconstrained. Every CA used to be built unconstrained, which
    # made a compromised intermediate as dangerous as the root itself.
    path_length: int | None = None
    # Optional NameConstraints — the strongest containment available for an
    # internal CA. A CA constrained to ".corp.example.com" cannot mint a
    # working certificate for anything else, even if its key is stolen.
    permitted_dns: list[str] = []
    excluded_dns: list[str] = []
    permitted_ip: list[str] = []
    excluded_ip: list[str] = []

    def constraints(self) -> dict:
        return {
            "permitted_dns": self.permitted_dns, "excluded_dns": self.excluded_dns,
            "permitted_ip": self.permitted_ip, "excluded_ip": self.excluded_ip,
        }


class CaImportRequest(BaseModel):
    name: str
    cert_pem: str
    private_key_pem: str
    ca_type: str = "root"
    parent_ca_id: int | None = None
    # Any properly stored CA key is exported passphrase-encrypted; without
    # this there was no way to import one at all.
    key_passphrase: str = ""


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


def _generate_ca_sync(body: CaGenerateRequest, parent_row: dict | None, aia_url: str | None) -> tuple:
    key = x509_utils.generate_private_key(body.key_algorithm, body.key_size)
    parent_cert = parent_key = None
    if parent_row is not None:
        parent_cert = x509_utils.cert_from_pem(parent_row["cert_pem"])
        parent_key = x509_utils.key_from_pem(decrypt_str(parent_row["private_key_enc"]))
    cert = x509_utils.build_ca_certificate(
        body.name, key, ca_type=body.ca_type, validity_days=body.validity_days,
        parent_cert=parent_cert, parent_key=parent_key,
        path_length=body.path_length,
        name_constraints=body.constraints(),
        aia_url=aia_url,
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

    # An intermediate points at its parent so a client holding only a leaf can
    # walk up the chain. A root has no issuer to point at.
    aia_url = None
    if parent_row is not None:
        base_url = await issuance.get_crl_base_url(db)
        aia_url = f"{base_url}/aia/{parent_row['id']}.crt"

    cert_pem, key_pem = await asyncio.to_thread(
        _generate_ca_sync, body, dict(parent_row) if parent_row else None, aia_url
    )
    info = x509_utils.parse_certificate(cert_pem)
    constraints = body.constraints()
    has_constraints = any(constraints.values())

    cur = await db.execute(
        """INSERT INTO certificate_authorities
           (name, ca_type, parent_ca_id, subject, cert_pem, private_key_enc,
            key_algorithm, key_size, signature_algorithm, not_before, not_after, source,
            path_length, name_constraints_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'generated', ?, ?) RETURNING *""",
        (body.name, body.ca_type, body.parent_ca_id, info["subject"], cert_pem, encrypt_str(key_pem),
         body.key_algorithm, body.key_size, info["signature_algorithm"], info["not_before"], info["not_after"],
         body.path_length if body.path_length is not None else (0 if body.ca_type == "intermediate" else None),
         json.dumps(constraints) if has_constraints else None),
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
    """Bring an existing CA under pktCert's management.

    Validated properly now. Import previously accepted anything that parsed:
    a leaf certificate imported as a "CA", or a certificate paired with
    somebody else's private key, was stored without complaint and only failed
    later — at signing time, or worse, at every relying party trying to verify
    a certificate it had issued.
    """
    try:
        cert = x509_utils.cert_from_pem(body.cert_pem)
    except Exception as e:
        raise HTTPException(400, f"Invalid certificate: {e}")

    try:
        key = x509_utils.key_from_pem(body.private_key_pem, body.key_passphrase or None)
    except TypeError:
        # cryptography raises TypeError specifically for "password given but
        # key isn't encrypted" / "key is encrypted but no password given".
        raise HTTPException(
            400,
            "This private key is passphrase-encrypted — supply key_passphrase "
            "(or omit it if the key isn't encrypted)."
            if not body.key_passphrase
            else "This private key is not passphrase-encrypted — leave key_passphrase empty.",
        )
    except Exception as e:
        raise HTTPException(400, f"Invalid private key: {e}")

    if not x509_utils.key_matches_certificate(key, cert):
        raise HTTPException(
            400,
            "The private key does not match this certificate — they are not a pair. "
            "Importing them anyway would produce certificates nothing can verify.",
        )

    problems = x509_utils.certificate_ca_problems(cert)
    if problems:
        raise HTTPException(400, "This certificate cannot act as a CA: " + "; ".join(problems))

    if body.ca_type == "intermediate" and body.parent_ca_id:
        async with db.execute(
            "SELECT id FROM certificate_authorities WHERE id = ?", (body.parent_ca_id,)
        ) as cur:
            if not await cur.fetchone():
                raise HTTPException(404, "Parent CA not found")

    info = x509_utils.parse_certificate(body.cert_pem)
    path_length, constraints = x509_utils.certificate_constraints(cert)

    # Store the key in the canonical unencrypted PKCS#8 form. It is immediately
    # Fernet-encrypted at rest either way, and normalising here means signing
    # never has to rediscover the import passphrase — which pktCert does not
    # keep, exactly as it doesn't keep an issued key's passphrase.
    normalised_key_pem = x509_utils.key_to_pem(key)

    cur = await db.execute(
        """INSERT INTO certificate_authorities
           (name, ca_type, parent_ca_id, subject, cert_pem, private_key_enc,
            key_algorithm, key_size, signature_algorithm, not_before, not_after, source,
            path_length, name_constraints_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'imported', ?, ?) RETURNING *""",
        (body.name, body.ca_type, body.parent_ca_id, info["subject"], body.cert_pem,
         encrypt_str(normalised_key_pem),
         info["key_algorithm"], info["key_size"], info["signature_algorithm"],
         info["not_before"], info["not_after"],
         path_length, json.dumps(constraints) if constraints else None),
    )
    row = await cur.fetchone()
    await db.execute(
        "INSERT INTO cert_events (ca_id, event_type, message) VALUES (?, 'issued', ?)",
        (row["id"], f"CA '{body.name}' imported"),
    )
    await db.commit()
    return _ca_out(row)


# ── Offline root workflow ──────────────────────────────────────────────────
#
# The root's private key never enters pktCert. It holds the root certificate
# only; an intermediate keypair is generated here, its CSR is carried to the
# offline machine and signed there, and the signed certificate comes back.
# Issuance then runs off the intermediate, so a compromise of this server
# costs an intermediate that can be revoked rather than the root every
# machine trusts.


class RootCertImportRequest(BaseModel):
    name: str
    cert_pem: str


@router.post("/import-root-cert")
async def import_root_certificate(
    body: RootCertImportRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)
):
    """Register an offline root by certificate alone — no private key.

    pktCert can never sign with this CA. That is the entire point: the key is
    somewhere this server cannot reach, so compromising this server cannot
    produce a certificate under the root.
    """
    try:
        cert = x509_utils.cert_from_pem(body.cert_pem)
    except Exception as e:
        raise HTTPException(400, f"Invalid certificate: {e}")

    problems = x509_utils.certificate_ca_problems(cert)
    if problems:
        raise HTTPException(400, "This certificate cannot act as a CA: " + "; ".join(problems))

    info = x509_utils.parse_certificate(body.cert_pem)
    path_length, constraints = x509_utils.certificate_constraints(cert)

    # private_key_enc is NOT NULL in the schema and there is no key to put in
    # it. Empty string records "deliberately absent" — every signing path
    # checks key_storage, not this column, so an empty value can never be
    # mistaken for a usable key.
    cur = await db.execute(
        """INSERT INTO certificate_authorities
           (name, ca_type, subject, cert_pem, private_key_enc, key_algorithm, key_size,
            signature_algorithm, not_before, not_after, source, key_storage,
            path_length, name_constraints_json)
           VALUES (?, 'root', ?, ?, '', ?, ?, ?, ?, ?, 'imported', 'offline', ?, ?) RETURNING *""",
        (body.name, info["subject"], body.cert_pem, info["key_algorithm"], info["key_size"],
         info["signature_algorithm"], info["not_before"], info["not_after"],
         path_length, json.dumps(constraints) if constraints else None),
    )
    row = await cur.fetchone()
    await db.execute(
        "INSERT INTO cert_events (ca_id, event_type, message) VALUES (?, 'issued', ?)",
        (row["id"], f"Offline root CA '{body.name}' registered (certificate only — no private key held)"),
    )
    await db.commit()
    return _ca_out(row)


class IntermediateCsrRequest(BaseModel):
    name: str
    parent_ca_id: int
    key_algorithm: str = "rsa"
    key_size: int = 4096
    path_length: int | None = 0
    permitted_dns: list[str] = []
    excluded_dns: list[str] = []
    permitted_ip: list[str] = []
    excluded_ip: list[str] = []

    def constraints(self) -> dict:
        return {
            "permitted_dns": self.permitted_dns, "excluded_dns": self.excluded_dns,
            "permitted_ip": self.permitted_ip, "excluded_ip": self.excluded_ip,
        }


def _generate_intermediate_csr_sync(body: IntermediateCsrRequest) -> tuple[str, str]:
    key = x509_utils.generate_private_key(body.key_algorithm, body.key_size)
    csr = x509_utils.generate_ca_csr(
        body.name, key, path_length=body.path_length, name_constraints=body.constraints()
    )
    return x509_utils.csr_to_pem(csr), x509_utils.key_to_pem(key)


@router.post("/request-intermediate")
async def request_intermediate(
    body: IntermediateCsrRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)
):
    """Generate an intermediate keypair here and a CSR to take to the offline
    root. The CA is created in 'pending_signature' and cannot issue anything
    until its signed certificate is imported."""
    async with db.execute(
        "SELECT * FROM certificate_authorities WHERE id = ?", (body.parent_ca_id,)
    ) as cur:
        parent = await cur.fetchone()
    if not parent:
        raise HTTPException(404, "Parent CA not found")

    csr_pem, key_pem = await asyncio.to_thread(_generate_intermediate_csr_sync, body)
    constraints = body.constraints()

    cur = await db.execute(
        """INSERT INTO certificate_authorities
           (name, ca_type, parent_ca_id, subject, cert_pem, private_key_enc,
            key_algorithm, key_size, signature_algorithm, not_before, not_after,
            status, source, key_storage, csr_pem, path_length, name_constraints_json)
           VALUES (?, 'intermediate', ?, ?, '', ?, ?, ?, 'sha256', '', '',
                   'pending_signature', 'generated', 'local', ?, ?, ?) RETURNING *""",
        (body.name, body.parent_ca_id, f"CN={body.name}", encrypt_str(key_pem),
         body.key_algorithm, body.key_size, csr_pem, body.path_length,
         json.dumps(constraints) if any(constraints.values()) else None),
    )
    row = await cur.fetchone()
    await db.execute(
        "INSERT INTO cert_events (ca_id, event_type, message) VALUES (?, 'csr_generated', ?)",
        (row["id"], f"Intermediate CSR generated for '{body.name}' — awaiting signature by '{parent['name']}'"),
    )
    await db.commit()
    return {**_ca_out(row), "csr_pem": csr_pem}


@router.get("/{ca_id}/csr")
async def get_ca_csr(ca_id: int, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    """Re-download a pending intermediate's CSR. The trip to an offline
    machine is rarely done in one sitting, and regenerating would produce a
    different key."""
    async with db.execute(
        "SELECT name, csr_pem, status FROM certificate_authorities WHERE id = ?", (ca_id,)
    ) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "CA not found")
    if not row["csr_pem"]:
        raise HTTPException(404, "This CA has no pending CSR")
    return {"name": row["name"], "csr_pem": row["csr_pem"], "status": row["status"]}


class SignedCertImportRequest(BaseModel):
    cert_pem: str


@router.post("/{ca_id}/import-signed-cert")
async def import_signed_certificate(
    ca_id: int, body: SignedCertImportRequest, user: AdminUser,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Take back the intermediate certificate signed by the offline root and
    activate the CA.

    Everything is checked before activation. A certificate that doesn't match
    the key held here, or wasn't signed by the parent it claims, would produce
    an intermediate whose every issued certificate fails at the relying party
    — a failure that surfaces far from this mistake and is miserable to trace.
    """
    async with db.execute("SELECT * FROM certificate_authorities WHERE id = ?", (ca_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "CA not found")
    if row["status"] != "pending_signature":
        raise HTTPException(400, f"This CA is not awaiting a signed certificate (status: {row['status']})")

    try:
        cert = x509_utils.cert_from_pem(body.cert_pem)
    except Exception as e:
        raise HTTPException(400, f"Invalid certificate: {e}")

    key = x509_utils.key_from_pem(decrypt_str(row["private_key_enc"]))
    if not x509_utils.key_matches_certificate(key, cert):
        raise HTTPException(
            400,
            "This certificate does not match the private key pktCert generated for this CA. "
            "It was signed from a different CSR — re-download this CA's CSR and sign that one.",
        )

    problems = x509_utils.certificate_ca_problems(cert)
    if problems:
        raise HTTPException(
            400,
            "The signed certificate is not usable as a CA: " + "; ".join(problems)
            + ". Whoever signed it left out the CA extensions.",
        )

    if row["parent_ca_id"]:
        async with db.execute(
            "SELECT name, cert_pem FROM certificate_authorities WHERE id = ?", (row["parent_ca_id"],)
        ) as cur:
            parent = await cur.fetchone()
        if parent and parent["cert_pem"]:
            parent_cert = x509_utils.cert_from_pem(parent["cert_pem"])
            if cert.issuer != parent_cert.subject:
                raise HTTPException(
                    400,
                    f"This certificate was issued by '{cert.issuer.rfc4514_string()}', not by the "
                    f"expected parent '{parent_cert.subject.rfc4514_string()}'.",
                )
            if not x509_utils.verify_certificate_signed_by(cert, parent_cert):
                raise HTTPException(
                    400,
                    "The signature on this certificate does not verify against the parent CA's key. "
                    "It names the right issuer but was not signed by it.",
                )

    info = x509_utils.parse_certificate(body.cert_pem)
    path_length, constraints = x509_utils.certificate_constraints(cert)
    await db.execute(
        """UPDATE certificate_authorities
           SET cert_pem = ?, subject = ?, signature_algorithm = ?, not_before = ?, not_after = ?,
               status = 'active', csr_pem = NULL, path_length = ?, name_constraints_json = ?
           WHERE id = ?""",
        (body.cert_pem, info["subject"], info["signature_algorithm"], info["not_before"],
         info["not_after"], path_length, json.dumps(constraints) if constraints else None, ca_id),
    )
    await db.execute(
        "INSERT INTO cert_events (ca_id, event_type, message) VALUES (?, 'issued', ?)",
        (ca_id, f"Signed certificate imported for '{row['name']}' — CA is now active"),
    )
    await db.commit()
    async with db.execute("SELECT * FROM certificate_authorities WHERE id = ?", (ca_id,)) as cur:
        return _ca_out(await cur.fetchone())


class CrlUploadRequest(BaseModel):
    crl_pem: str


@router.post("/{ca_id}/upload-crl")
async def upload_crl(
    ca_id: int, body: CrlUploadRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)
):
    """Publish a CRL that was signed elsewhere.

    An offline CA cannot sign its own CRL here — it holds no key here, which
    is the whole point. So revocations under an offline root are published by
    signing the CRL on the offline machine and uploading it, after which the
    normal distribution point serves it like any other.
    """
    async with db.execute("SELECT * FROM certificate_authorities WHERE id = ?", (ca_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "CA not found")

    try:
        crl = x509_utils.crl_from_pem(body.crl_pem)
    except Exception as e:
        raise HTTPException(400, f"Invalid CRL: {e}")

    ca_cert = x509_utils.cert_from_pem(row["cert_pem"])
    if crl.issuer != ca_cert.subject:
        raise HTTPException(
            400,
            f"This CRL was issued by '{crl.issuer.rfc4514_string()}', not by this CA "
            f"('{ca_cert.subject.rfc4514_string()}').",
        )
    if not crl.is_signature_valid(ca_cert.public_key()):
        raise HTTPException(400, "The CRL's signature does not verify against this CA's certificate")

    await db.execute(
        "UPDATE certificate_authorities SET uploaded_crl_pem = ? WHERE id = ?", (body.crl_pem, ca_id)
    )
    await db.execute(
        "INSERT INTO cert_events (ca_id, event_type, message) VALUES (?, 'crl_uploaded', ?)",
        (ca_id, f"Externally-signed CRL uploaded for '{row['name']}' by {user['username']}"),
    )
    await db.commit()
    return {
        "status": "ok",
        "this_update": crl.last_update_utc.isoformat(),
        "next_update": crl.next_update_utc.isoformat() if crl.next_update_utc else None,
        "revoked_count": len(crl),
    }


class CaStatusRequest(BaseModel):
    status: str  # active | disabled


@router.patch("/{ca_id}/status")
async def set_ca_status(
    ca_id: int, body: CaStatusRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)
):
    """Disable a CA (stops it issuing) or re-enable it.

    This is what retiring a CA should look like. A disabled CA still exists,
    still appears in the inventory, and — critically — still publishes its
    CRL, because the certificates it already issued are still deployed and
    still being validated by relying parties.
    """
    if body.status not in ("active", "disabled"):
        raise HTTPException(400, "status must be 'active' or 'disabled'")

    async with db.execute("SELECT * FROM certificate_authorities WHERE id = ?", (ca_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "CA not found")
    if row["status"] not in ("active", "disabled"):
        raise HTTPException(400, f"CA is {row['status']} and cannot be re-enabled")

    await db.execute("UPDATE certificate_authorities SET status = ? WHERE id = ?", (body.status, ca_id))
    await db.execute(
        "INSERT INTO cert_events (ca_id, event_type, message) VALUES (?, 'ca_status', ?)",
        (ca_id, f"CA '{row['name']}' {'disabled' if body.status == 'disabled' else 're-enabled'} by {user['username']}"),
    )
    await db.commit()
    async with db.execute("SELECT * FROM certificate_authorities WHERE id = ?", (ca_id,)) as cur:
        updated = await cur.fetchone()
    return _ca_out(updated)


@router.delete("/{ca_id}", status_code=204)
async def delete_ca(ca_id: int, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    """Delete a CA that never issued anything.

    Deletion used to be allowed once no *non-revoked* certificates remained —
    which is precisely backwards. Revoked certificates are the ones that most
    need their CA: deleting it destroys the only key that can sign the CRL
    carrying their revocations, while those certificates are still deployed
    and still trusted by everything holding them. It also cascaded away the
    CA's entire audit history.

    So a CA that has ever issued anything can only be disabled, never deleted.
    """
    async with db.execute(
        "SELECT COUNT(*) AS n FROM certificates WHERE ca_id = ?", (ca_id,)
    ) as cur:
        row = await cur.fetchone()
    if row and row["n"] > 0:
        raise HTTPException(
            400,
            f"This CA has issued {row['n']} certificate(s) and cannot be deleted — disable it instead. "
            "Deleting it would destroy the key that signs its CRL, leaving every certificate it "
            "issued unrevocable while they are still deployed and trusted.",
        )

    async with db.execute(
        "SELECT COUNT(*) AS n FROM certificate_authorities WHERE parent_ca_id = ?", (ca_id,)
    ) as cur:
        children = await cur.fetchone()
    if children and children["n"] > 0:
        raise HTTPException(400, f"This CA has {children['n']} intermediate CA(s) beneath it — remove those first")

    await db.execute("DELETE FROM certificate_authorities WHERE id = ?", (ca_id,))
    await db.commit()


@router.get("/{ca_id}/crl")
async def get_crl(ca_id: int, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    """Admin view of the CA's current CRL. Serves exactly the same published
    artifact as the public distribution point (GET /crl/{ca_id}.crl) — see
    app/cert/crl_manager.py. This route used to sign its own copy and
    increment the CA's counter on every view, which meant simply *looking* at
    the CRL here published a number the public DP would later reuse for
    different content."""
    async with db.execute("SELECT * FROM certificate_authorities WHERE id = ?", (ca_id,)) as cur:
        ca_row = await cur.fetchone()
    if not ca_row:
        raise HTTPException(404, "CA not found")

    try:
        published = await crl_manager.get_published_crl(db, ca_row)
    except crl_manager.OfflineCrlUnavailable as e:
        # A configuration state, not a fault — say what to do about it.
        raise HTTPException(409, str(e))
    return {
        "crl_pem": published["crl_pem"],
        "crl_number": published["crl_number"],
        "this_update": published["this_update"],
        "next_update": published["next_update"],
    }
