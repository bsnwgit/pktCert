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
import hashlib
import time
from datetime import datetime, timezone

import aiosqlite
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException, Response

from app.api.cas import build_crl_sync
from app.database import get_db

router = APIRouter()

# In-process CRL cache. This endpoint is unauthenticated and unthrottled, and
# each miss performs a CA private-key SIGNING operation — without a cache a
# flood of anonymous GETs is a cheap CPU-exhaustion vector. We cache the
# signed DER per CA and only re-sign when the revoked set changes or the entry
# ages past _CRL_CACHE_TTL, so anonymous polling reuses one signature.
_CRL_CACHE_TTL = 300.0  # seconds
_crl_cache: dict[int, dict] = {}  # ca_id -> {"fp", "der", "next_update", "built": monotonic}


def _revoked_fingerprint(crl_number: int, revoked: list) -> str:
    h = hashlib.sha256()
    h.update(str(crl_number).encode())
    for r in revoked:
        h.update(b"|")
        h.update((r["serial_number"] or "").encode())
        h.update(str(r["revoked_at"] or "").encode())
    return h.hexdigest()


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
    fp = _revoked_fingerprint(ca_row["crl_number"], revoked)
    now = time.monotonic()
    cached = _crl_cache.get(ca_id)
    if cached and cached["fp"] == fp and (now - cached["built"]) < _CRL_CACHE_TTL:
        crl_der = cached["der"]
        next_update = cached["next_update"]
    else:
        crl_pem = await asyncio.to_thread(
            build_crl_sync, dict(ca_row), [dict(r) for r in revoked], ca_row["crl_number"]
        )
        crl = x509.load_pem_x509_crl(crl_pem.encode())
        crl_der = crl.public_bytes(serialization.Encoding.DER)
        next_update = crl.next_update_utc
        _crl_cache[ca_id] = {"fp": fp, "der": crl_der, "next_update": next_update, "built": now}

    max_age = max(60, int((next_update - datetime.now(timezone.utc)).total_seconds()))
    return Response(
        content=crl_der,
        media_type="application/pkix-crl",
        headers={"Cache-Control": f"public, max-age={max_age}"},
    )
