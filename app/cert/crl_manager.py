"""
app/cert/crl_manager.py
------------------------
The single place a CRL is issued. Both CRL routes go through
get_published_crl(): the admin PEM/JSON view (GET /api/cas/{id}/crl) and the
public distribution point baked into every issued certificate
(GET /crl/{ca_id}.crl).

Why a stored artifact instead of building on demand
---------------------------------------------------
RFC 5280 §5.2.3 makes CRLNumber a monotonically increasing sequence that is
unique per issued CRL. A relying party holding CRL number N may ignore any
later CRL that also claims number N. Previously each endpoint built its own
CRL — the admin route signed with crl_number+1 and incremented, the public
route signed with the current crl_number and never wrote — so revoking a
certificate produced a second, different CRL under a number the admin route
had already published, and a client that had cached the first one could stay
blind to the revocation.

So the CRL is now issued once and stored (crl_publications, migration 006).
Both endpoints serve that stored copy verbatim. A new CRL — and therefore a
new number — is issued only when there is something new to say:

  * the revoked set changed (tracked by a fingerprint over serial +
    revocation date), or
  * the published copy is within _REFRESH_MARGIN of its nextUpdate, so it
    needs re-signing before relying parties start rejecting it as stale.

That keeps numbering monotonic and keeps anonymous polling of the public DP
from driving either writes or CA signing operations: an unchanged CRL is
returned straight from the stored row.
"""
from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone

import aiosqlite
from cryptography import x509

from app.cert import x509_utils
from app.cert.crypto import decrypt_str

# Re-sign a published CRL once it comes within this margin of its nextUpdate,
# rather than waiting for it to lapse — a CRL that expires before its
# replacement is issued makes relying parties fail closed (or, worse, fail
# open) on every certificate the CA ever issued. x509_utils.build_crl sets
# nextUpdate 7 days out, so an idle CA re-issues roughly every 6 days.
_REFRESH_MARGIN = timedelta(days=1)


class OfflineCrlUnavailable(Exception):
    """Raised when a CRL is requested for an offline CA and none has been
    uploaded. Callers turn this into a clear HTTP error rather than a 500 —
    it's a configuration state, not a fault."""


def _parse_utc_ts(value: str | None) -> datetime:
    """Parse a stored timestamp as UTC. Covers both shapes we read here:
    certificates.revoked_at, written by SQLite's datetime('now') — naive UTC,
    space separated — and crl_publications.next_update, an offset-carrying
    isoformat() string. Falls back to now() only when a value genuinely can't
    be parsed; an unparseable date must not abort CRL issuance for the whole
    CA, since a slightly-wrong revocation date beats no CRL at all."""
    if not value:
        return datetime.now(timezone.utc)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def revoked_fingerprint(revoked: list[dict]) -> str:
    """Stable hash of the revoked set, used to decide whether a stored CRL
    still describes current reality. Sorted so row order from SQLite can't
    make an unchanged set look changed and burn a CRL number."""
    h = hashlib.sha256()
    for r in sorted(revoked, key=lambda r: (r["serial_number"] or "")):
        h.update(b"|")
        h.update((r["serial_number"] or "").encode())
        h.update(str(r["revoked_at"] or "").encode())
        # Covers the reason code as well — otherwise correcting a revocation
        # reason would leave the published CRL saying the old thing forever.
        h.update(str(r.get("revoked_reason_code") or "").encode())
    return h.hexdigest()


def build_crl_sync(ca_row: dict, revoked: list[dict], crl_number: int) -> str:
    """CPU-bound: decrypts the CA key and signs. Callers use asyncio.to_thread."""
    ca_cert = x509_utils.cert_from_pem(ca_row["cert_pem"])
    ca_key = x509_utils.key_from_pem(decrypt_str(ca_row["private_key_enc"]))
    entries = [
        {
            "serial_number": int(r["serial_number"], 16),
            "revoked_at": _parse_utc_ts(r["revoked_at"]),
            "reason": r.get("revoked_reason_code"),
        }
        for r in revoked
        if r["serial_number"]
    ]
    return x509_utils.build_crl(ca_cert, ca_key, entries, crl_number)


async def _fetch_revoked(db: aiosqlite.Connection, ca_id: int) -> list[dict]:
    async with db.execute(
        """SELECT serial_number, revoked_at, revoked_reason_code FROM certificates
           WHERE ca_id = ? AND status = 'revoked'""",
        (ca_id,),
    ) as cur:
        return [dict(r) for r in await cur.fetchall()]


async def get_published_crl(db: aiosqlite.Connection, ca_row) -> dict:
    """Return the CA's current published CRL, issuing a new one only if the
    revoked set changed or the stored copy is near expiry.

    Returns {"crl_pem", "crl_number", "this_update", "next_update", "issued"}
    where `issued` says whether this call minted a new CRL.
    """
    ca_id = ca_row["id"]

    # An offline CA holds no private key here, so pktCert cannot sign a CRL
    # for it — that's the point of keeping the key offline, not a limitation
    # to work around. What it can do is publish a CRL that was signed on the
    # offline machine and uploaded (POST /api/cas/{id}/upload-crl).
    if "key_storage" in ca_row.keys() and ca_row["key_storage"] == "offline":
        uploaded = ca_row["uploaded_crl_pem"] if "uploaded_crl_pem" in ca_row.keys() else None
        if not uploaded:
            raise OfflineCrlUnavailable(
                f"CA '{ca_row['name']}' is offline — pktCert holds no key to sign its CRL. "
                "Sign the CRL on the machine holding the key and upload it "
                "(POST /api/cas/{id}/upload-crl)."
            )
        crl = x509_utils.crl_from_pem(uploaded)
        try:
            number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        except x509.ExtensionNotFound:
            number = 0
        return {
            "crl_pem": uploaded,
            "crl_number": number,
            "this_update": crl.last_update_utc.isoformat(),
            "next_update": crl.next_update_utc.isoformat() if crl.next_update_utc else "",
            "issued": False,
        }

    revoked = await _fetch_revoked(db, ca_id)
    fp = revoked_fingerprint(revoked)
    now = datetime.now(timezone.utc)

    async with db.execute("SELECT * FROM crl_publications WHERE ca_id = ?", (ca_id,)) as cur:
        published = await cur.fetchone()

    if published is not None and published["revoked_fp"] == fp:
        next_update = _parse_utc_ts(published["next_update"])
        if now < next_update - _REFRESH_MARGIN:
            return {
                "crl_pem": published["crl_pem"],
                "crl_number": published["crl_number"],
                "this_update": published["this_update"],
                "next_update": published["next_update"],
                "issued": False,
            }

    # Never reuse a number: take the highest the CA has ever handed out —
    # including any issued by the pre-006 admin endpoint, which tracked the
    # counter on certificate_authorities alone — and go one past it.
    last_number = max(int(ca_row["crl_number"] or 0), int(published["crl_number"]) if published else 0)
    crl_number = last_number + 1

    crl_pem = await asyncio.to_thread(build_crl_sync, dict(ca_row), revoked, crl_number)
    crl = x509_utils.crl_from_pem(crl_pem)
    this_update = crl.last_update_utc.isoformat()
    next_update = crl.next_update_utc.isoformat()

    # Two concurrent requests can both reach here and both sign number N+1.
    # The guard keeps the first write and makes the loser discard its copy
    # rather than publishing a second, differently-timestamped CRL under the
    # same number — so we re-read the row afterwards and serve whichever one
    # actually landed.
    await db.execute(
        """INSERT INTO crl_publications (ca_id, crl_number, revoked_fp, crl_pem, this_update, next_update)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(ca_id) DO UPDATE SET
               crl_number  = excluded.crl_number,
               revoked_fp  = excluded.revoked_fp,
               crl_pem     = excluded.crl_pem,
               this_update = excluded.this_update,
               next_update = excluded.next_update,
               issued_at   = datetime('now')
           WHERE excluded.crl_number > crl_publications.crl_number""",
        (ca_id, crl_number, fp, crl_pem, this_update, next_update),
    )
    await db.execute(
        "UPDATE certificate_authorities SET crl_number = max(crl_number, ?) WHERE id = ?",
        (crl_number, ca_id),
    )
    await db.commit()

    async with db.execute("SELECT * FROM crl_publications WHERE ca_id = ?", (ca_id,)) as cur:
        row = await cur.fetchone()

    return {
        "crl_pem": row["crl_pem"],
        "crl_number": row["crl_number"],
        "this_update": row["this_update"],
        "next_update": row["next_update"],
        "issued": row["crl_number"] == crl_number,
    }
