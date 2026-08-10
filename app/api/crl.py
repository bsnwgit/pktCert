"""
GET /crl/{ca_id}.crl — the CRL Distribution Point every cert issued via
POST /api/certificates/issue points to (see IssueRequest handling in
app/api/certificates.py). Deliberately unauthenticated: a CRL is a public
list of revoked serial numbers, no different from what any real-world CA
publishes at a plain http:// URL with no login — the whole point is that
any device/client validating a cert from this CA must be able to fetch it
without credentials. This is not the same class of bug as the earlier
unauthenticated-widget/suite-token findings (see pktcert-initial-build
memory) — those leaked admin data; this intentionally serves public data.

Kept separate from GET /api/cas/{id}/crl (app/api/cas.py), which stays
AdminUser-gated and returns PEM/JSON for the admin UI — that endpoint
can't double as the one baked into issued certs.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import aiosqlite
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException, Response

from app.api.cas import build_crl_sync
from app.database import get_db

router = APIRouter()


@router.get("/{ca_id}.crl")
async def get_public_crl(ca_id: int, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM certificate_authorities WHERE id = ?", (ca_id,)) as cur:
        ca_row = await cur.fetchone()
    if not ca_row:
        raise HTTPException(404, "CA not found")

    async with db.execute(
        "SELECT serial_number, revoked_at FROM certificates WHERE ca_id = ? AND status = 'revoked'", (ca_id,)
    ) as cur:
        revoked = await cur.fetchall()

    # Doesn't bump/persist crl_number like the admin endpoint does — this
    # route has no login and no rate limit, so treating it as read-only
    # (reuse the CA's current crl_number, no DB write) avoids turning
    # arbitrary anonymous polling into a write-amplification vector.
    crl_pem = await asyncio.to_thread(
        build_crl_sync, dict(ca_row), [dict(r) for r in revoked], ca_row["crl_number"]
    )
    crl = x509.load_pem_x509_crl(crl_pem.encode())
    crl_der = crl.public_bytes(serialization.Encoding.DER)

    max_age = max(60, int((crl.next_update_utc - datetime.now(timezone.utc)).total_seconds()))
    return Response(
        content=crl_der,
        media_type="application/pkix-crl",
        headers={"Cache-Control": f"public, max-age={max_age}"},
    )
