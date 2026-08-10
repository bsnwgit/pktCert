"""
GET /crl/{ca_id}.crl — the CRL Distribution Point every cert issued via
POST /api/certificates/issue and POST /api/certificates/csr points to (see
app/api/certificates.py). Deliberately unauthenticated: a CRL is a public
list of revoked serial numbers, no different from what any real-world CA
publishes at a plain http:// URL with no login — the whole point is that
any device/client validating a cert from this CA must be able to fetch it
without credentials. This is not the same class of bug as the earlier
unauthenticated-widget/suite-token findings (see pktcert-initial-build
memory) — those leaked admin data; this intentionally serves public data.

The CRL itself is issued and numbered by app/cert/crl_manager.py, which is
also what GET /api/cas/{id}/crl serves — one published artifact, so the two
routes can never hand out different CRLs under the same CRLNumber. This
module only converts the published PEM to the DER that relying parties
expect and sets cache headers.
"""
from __future__ import annotations

from datetime import datetime, timezone

import aiosqlite
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException, Response

from app.cert import crl_manager, x509_utils
from app.database import get_db

router = APIRouter()

# In-process DER cache. This endpoint is unauthenticated and unthrottled, so
# anonymous polling shouldn't cost a DB round-trip and a PEM->DER reparse per
# request. Keyed on the published CRL number, so a newly issued CRL replaces
# the cached copy immediately rather than waiting out a TTL — a revocation
# must never sit behind a cache.
_der_cache: dict[int, dict] = {}  # ca_id -> {"crl_number", "der", "next_update"}


@router.get("/{ca_id}.crl")
async def get_public_crl(ca_id: int, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM certificate_authorities WHERE id = ?", (ca_id,)) as cur:
        ca_row = await cur.fetchone()
    if not ca_row:
        raise HTTPException(404, "CA not found")

    try:
        published = await crl_manager.get_published_crl(db, ca_row)
    except crl_manager.OfflineCrlUnavailable:
        # An offline CA whose CRL hasn't been uploaded yet. 404 rather than a
        # 500: to a relying party this is simply "no CRL published here", and
        # the operator-facing explanation belongs in the admin route, not in a
        # response to an anonymous fetch.
        raise HTTPException(404, "No CRL published for this CA")

    cached = _der_cache.get(ca_id)
    if cached and cached["crl_number"] == published["crl_number"]:
        crl_der = cached["der"]
        next_update = cached["next_update"]
    else:
        crl = x509_utils.crl_from_pem(published["crl_pem"])
        crl_der = crl.public_bytes(serialization.Encoding.DER)
        next_update = crl.next_update_utc
        _der_cache[ca_id] = {"crl_number": published["crl_number"], "der": crl_der, "next_update": next_update}

    # Let clients cache until this CRL is due to be replaced, but never
    # advertise a stale-forever copy: crl_manager re-issues a day before
    # nextUpdate, so the window closes on its own.
    max_age = max(60, int((next_update - datetime.now(timezone.utc)).total_seconds()))
    return Response(
        content=crl_der,
        media_type="application/pkix-crl",
        headers={"Cache-Control": f"public, max-age={max_age}"},
    )
