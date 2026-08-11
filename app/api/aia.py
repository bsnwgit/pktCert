"""
GET /aia/{ca_id}.crt — the Authority Information Access (caIssuers)
distribution point referenced by every certificate pktCert issues.

Deliberately unauthenticated, for the same reason as the CRL endpoint
(app/api/crl.py): a CA certificate is public by definition — it's the thing
you install in a trust store, and every relying party validating a chain has
to be able to fetch it without credentials. It contains only the CA's public
key and subject; the private key is Fernet-encrypted in the database and
never leaves the process.

Why this endpoint has to exist: a TLS server that sends only its leaf
certificate and no intermediates is extremely common. Without a caIssuers
URL, a client holding that leaf has a certificate signed by an issuer it has
no way to obtain, and chain building simply fails — the certificate looks
broken even though everything about it is correct. AIA is how the client
finds the missing link.

Serves DER (application/pkix-cert), which is what the AIA specification
expects and what Windows, macOS and OpenSSL all fetch. ?format=pem returns
PEM instead, for humans copying it into a config file.
"""
from __future__ import annotations

import aiosqlite
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException, Response

from app.cert import x509_utils
from app.database import get_db

router = APIRouter()


@router.get("/{ca_id}.crt")
async def get_ca_certificate(
    ca_id: int, format: str = "der", db: aiosqlite.Connection = Depends(get_db)
):
    async with db.execute(
        "SELECT name, cert_pem FROM certificate_authorities WHERE id = ?", (ca_id,)
    ) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "CA not found")

    if format == "pem":
        return Response(
            content=row["cert_pem"],
            media_type="application/x-pem-file",
            headers={"Cache-Control": "public, max-age=3600"},
        )

    cert = x509_utils.cert_from_pem(row["cert_pem"])
    return Response(
        content=cert.public_bytes(serialization.Encoding.DER),
        media_type="application/pkix-cert",
        # A CA certificate changes only when the CA is re-keyed, which is a
        # multi-year event — but keep the window modest anyway so a rotation
        # isn't stuck behind week-old caches.
        headers={"Cache-Control": "public, max-age=3600"},
    )
