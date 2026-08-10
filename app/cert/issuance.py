"""
app/cert/issuance.py
---------------------
Generating and storing an internally-issued certificate, in one place.

Three callers share it:

  * POST /api/certificates/issue      — issue a new certificate
  * POST /api/certificates/{id}/renew — replace an existing one
  * app/cert/renewal.py               — the auto-renewal loop

They must not drift. A certificate produced by the background renewer has to
be indistinguishable from one issued through the UI — same extensions, same
CRL Distribution Point, same encryption at rest — or auto-renewal quietly
degrades whatever it touches.
"""
from __future__ import annotations

import asyncio
import json
from typing import Optional

import aiosqlite

from app.cert import x509_utils
from app.cert.crypto import decrypt_str, encrypt_str

# Where the CRL Distribution Point points when no crl_base_url is configured.
# Only useful for same-host testing; an admin must set crl_base_url in Settings
# before any other device can check revocation.
_DEFAULT_CRL_BASE = "http://localhost:8763"


def signing_refusal(ca_row) -> str | None:
    """Why this CA cannot sign, or None if it can.

    Two states make a CA unusable for signing regardless of its status:
    an offline CA (pktCert deliberately holds no key for it) and an
    intermediate still waiting for its CSR to come back signed. Both would
    otherwise fail deep inside a signing call with an opaque error about an
    unparseable key.
    """
    keys = ca_row.keys() if hasattr(ca_row, "keys") else ca_row
    if "key_storage" in keys and ca_row["key_storage"] == "offline":
        return (
            f"'{ca_row['name']}' is an offline CA — pktCert holds no private key for it, "
            "by design. Issue from an intermediate signed by it instead."
        )
    if ca_row["status"] == "pending_signature":
        return (
            f"'{ca_row['name']}' is still awaiting its signed certificate. Download its CSR, "
            "have the parent CA sign it, and import the result before issuing from it."
        )
    return None


async def get_crl_base_url(db: aiosqlite.Connection) -> str:
    """Deliberately a separate setting from SAML's 'base_url' (app/auth/saml.py)
    even though both describe "this app's externally-reachable address" — SAML
    wants https:// when SSO is configured, but a CRL Distribution Point should
    stay plain http://. Checking revocation over HTTPS creates a circular trust
    dependency, and the CRL is already self-verifying via the CA's signature."""
    async with db.execute("SELECT value FROM settings WHERE key = 'crl_base_url'") as cur:
        row = await cur.fetchone()
    if not row or not row[0]:
        return _DEFAULT_CRL_BASE
    try:
        return str(json.loads(row[0])).rstrip("/") or _DEFAULT_CRL_BASE
    except (ValueError, TypeError):
        return str(row[0]).rstrip("/")


def _issue_sync(
    ca_row: dict, template_row: dict, common_name: str, sans: list[str],
    crl_url: str, aia_url: str, key_passphrase: str = "",
) -> tuple[str, str]:
    ca_cert = x509_utils.cert_from_pem(ca_row["cert_pem"])
    ca_key = x509_utils.key_from_pem(decrypt_str(ca_row["private_key_enc"]))
    leaf_key = x509_utils.generate_private_key(template_row["key_algorithm"], template_row["key_size"])
    csr = x509_utils.generate_csr(common_name, sans, leaf_key)
    cert = x509_utils.sign_certificate(
        csr, ca_cert, ca_key,
        validity_days=template_row["validity_days"],
        key_usage=json.loads(template_row["key_usage_json"]),
        extended_key_usage=json.loads(template_row["extended_key_usage_json"]),
        crl_url=crl_url,
        aia_url=aia_url,
    )
    return x509_utils.cert_to_pem(cert), x509_utils.key_to_pem(leaf_key, key_passphrase or None)


async def issue_certificate(
    db: aiosqlite.Connection,
    ca_row,
    template_row,
    common_name: str,
    sans: list[str],
    key_passphrase: str = "",
    renewed_from_id: Optional[int] = None,
    auto_renew: bool = False,
    auto_renew_days: int = 30,
) -> tuple[aiosqlite.Row, str]:
    """Generate a keypair, sign a certificate, and store it. Returns the new
    certificates row and the private key PEM — the key is returned rather than
    only stored because the issue/renew endpoints show it to the operator
    once, at the moment they asked for it.

    Does not commit; the caller owns the transaction so the certificate row
    and its audit event land together.
    """
    # Browsers ignore the CN for hostname matching and check only SAN, so the
    # common name must always be present in SAN too. x509_utils enforces this
    # as well, for CSRs that arrive from elsewhere; doing it here keeps the
    # stored san_json honest about what the certificate actually contains.
    all_sans = list(dict.fromkeys([common_name, *sans]))

    base_url = await get_crl_base_url(db)
    crl_url = f"{base_url}/crl/{ca_row['id']}.crl"
    # Same base as the CRL, and plain http:// for the same reason — a client
    # that has to fetch the issuing CA in order to validate a chain cannot be
    # asked to validate a chain in order to fetch it.
    aia_url = f"{base_url}/aia/{ca_row['id']}.crt"

    cert_pem, key_pem = await asyncio.to_thread(
        _issue_sync, dict(ca_row), dict(template_row), common_name, all_sans,
        crl_url, aia_url, key_passphrase,
    )
    info = x509_utils.parse_certificate(cert_pem)

    cur = await db.execute(
        """INSERT INTO certificates
           (common_name, san_json, issuer, subject, serial_number, fingerprint_sha256,
            not_before, not_after, key_algorithm, key_size, signature_algorithm,
            status, source, cert_pem, private_key_enc, key_encrypted, ca_id, template_id,
            renewed_from_id, auto_renew, auto_renew_days)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'valid', 'issued', ?, ?, ?, ?, ?, ?, ?, ?)
           RETURNING *""",
        (info["common_name"], json.dumps(info["san"]), info["issuer"], info["subject"],
         info["serial_number"], info["fingerprint_sha256"], info["not_before"], info["not_after"],
         info["key_algorithm"], info["key_size"], info["signature_algorithm"],
         cert_pem, encrypt_str(key_pem), int(bool(key_passphrase)), ca_row["id"], template_row["id"],
         renewed_from_id, int(bool(auto_renew)), auto_renew_days),
    )
    row = await cur.fetchone()
    return row, key_pem


async def supersede(db: aiosqlite.Connection, old_cert_id: int, new_cert_id: int) -> None:
    """Link a renewed certificate to its replacement and retire the old row.

    'superseded' rather than deleted or expired: the old certificate is still
    deployed and still trusted until it expires, so it belongs in the
    inventory — but it must stop raising expiry alerts, because the thing
    those alerts would be asking for already exists.
    """
    await db.execute(
        "UPDATE certificates SET renewed_to_id = ?, status = 'superseded' WHERE id = ?",
        (new_cert_id, old_cert_id),
    )
