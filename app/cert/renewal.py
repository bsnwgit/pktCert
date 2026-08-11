"""
app/cert/renewal.py
--------------------
Automatic certificate renewal.

A certificate with auto_renew = 1 is reissued once it comes within
auto_renew_days of expiry, using the same CA, template, subject and SANs —
the same code path as a manual renewal (app/cert/issuance.py), so an
auto-renewed certificate is indistinguishable from a hand-issued one.

What this does NOT do is install anything. The new certificate and its
freshly generated private key are stored here; getting them onto the server
that serves them is still a human step (or a job for whatever configuration
management runs that host). Auto-renewal removes the "nobody noticed it was
expiring" failure, not the deployment step — which is exactly why it's
opt-in per certificate rather than a global default.

Renewal deliberately does not revoke the old certificate. It stays valid,
marked 'superseded', until whoever installs the replacement gets to it;
revoking on renewal would break the running service the moment the new cert
was issued.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

import aiosqlite

from app.cert import issuance

log = logging.getLogger("pktcert.renewal")

# Renewal is not time-critical to the minute — a certificate inside its
# renewal window stays renewable for days. Ten minutes keeps the loop cheap
# while still reacting well within any sane window.
_TICK_SECONDS = 600


async def _due_for_renewal(db: aiosqlite.Connection) -> list[aiosqlite.Row]:
    """Certificates opted into auto-renewal that have entered their window.

    Excludes anything already superseded (its replacement exists) or revoked,
    and requires the issuing CA and template to still be present — renewal
    reuses both, so a certificate whose template was deleted can't be renewed
    automatically and needs a human decision instead.
    """
    async with db.execute(
        """SELECT c.* FROM certificates c
           JOIN certificate_authorities ca ON ca.id = c.ca_id
           JOIN cert_templates t           ON t.id = c.template_id
           WHERE c.auto_renew = 1
             AND c.source = 'issued'
             AND c.status NOT IN ('superseded', 'revoked')
             AND c.renewed_to_id IS NULL
             AND ca.status = 'active'
             AND ca.key_storage = 'local'
             AND c.not_after IS NOT NULL
             AND c.not_after < datetime('now', '+' || c.auto_renew_days || ' days')"""
    ) as cur:
        return await cur.fetchall()


async def renew_one(db: aiosqlite.Connection, old) -> Optional[int]:
    """Renew a single certificate. Returns the new certificate id, or None if
    it couldn't be renewed (logged, never raised — one bad certificate must
    not stop the rest of the batch)."""
    try:
        async with db.execute(
            "SELECT * FROM certificate_authorities WHERE id = ?", (old["ca_id"],)
        ) as cur:
            ca_row = await cur.fetchone()
        async with db.execute(
            "SELECT * FROM cert_templates WHERE id = ?", (old["template_id"],)
        ) as cur:
            template_row = await cur.fetchone()
        if not ca_row or not template_row:
            log.warning(f"Auto-renew skipped for certificate {old['id']}: CA or template missing")
            return None

        try:
            sans = json.loads(old["san_json"] or "[]")
        except ValueError:
            sans = []

        # No key passphrase on an auto-renewal: there is nobody at a keyboard
        # to supply or receive one. The key is still Fernet-encrypted at rest
        # like every other stored key.
        row, _key_pem = await issuance.issue_certificate(
            db, ca_row, template_row, old["common_name"], sans,
            renewed_from_id=old["id"],
            auto_renew=True, auto_renew_days=old["auto_renew_days"],
        )
        await issuance.supersede(db, old["id"], row["id"])
        await db.execute(
            "INSERT INTO cert_events (certificate_id, ca_id, event_type, message) VALUES (?, ?, 'renewed', ?)",
            (row["id"], ca_row["id"],
             f"Auto-renewed '{old['common_name']}' (replaces certificate {old['id']}) — "
             f"the new key still has to be installed"),
        )
        await db.execute(
            "INSERT INTO cert_events (certificate_id, ca_id, event_type, message) VALUES (?, ?, 'renewed', ?)",
            (old["id"], ca_row["id"], f"Superseded by auto-renewed certificate {row['id']}"),
        )
        await db.commit()
        log.info(f"Auto-renewed certificate {old['id']} ('{old['common_name']}') as {row['id']}")
        return row["id"]
    except Exception as e:
        log.error(f"Auto-renew failed for certificate {old['id']}: {e}")
        return None


async def run_once(db_path: str) -> dict:
    """One renewal pass. Also used by the manual 'Run Auto-Renewal Now' path."""
    renewed, failed = [], 0
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA busy_timeout=5000")
        due = await _due_for_renewal(db)
        for old in due:
            new_id = await renew_one(db, old)
            if new_id:
                renewed.append(new_id)
            else:
                failed += 1
    return {"status": "ok", "due": len(due), "renewed": renewed, "failed": failed}


class RenewalEngine:
    _instance: "Optional[RenewalEngine]" = None

    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None
        self._db_path: str = ""

    async def start(self, db_path: str) -> None:
        RenewalEngine._instance = self
        self._db_path = db_path
        self._task = asyncio.create_task(self._run_loop())
        log.info("Renewal engine started")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _run_loop(self) -> None:
        while True:
            try:
                result = await run_once(self._db_path)
                if result["renewed"] or result["failed"]:
                    log.info(f"Auto-renewal pass: {result}")
            except Exception as e:
                log.error(f"Renewal engine tick error: {e}")
            await asyncio.sleep(_TICK_SECONDS)
