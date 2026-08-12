"""
Certificate Transparency auto-discovery.

Settings → Discovery has offered a **CT auto-discovery** toggle and a
**Watched domains** list since the app was built, the README documents the
feature under its own heading, and `ct_search.py` implements both the crt.sh
and Censys queries. Nothing ever read either setting and neither search
function was called from anywhere — the toggle wrote a value to the database
and had no other effect.

This is the missing half: a scheduled job that reads those two settings,
searches CT for each watched domain, and adds anything new to the inventory.

Notes for whoever touches this next:

* crt.sh returns log *entries*, not certificates, and its rows do not reliably
  carry a full PEM. `ct_search.search_crtsh` says so in its own docstring. So a
  CT hit is treated as a lead: the hostname is connected to and the live
  certificate fetched with the same code path the active scanner uses, which
  keeps one definition of "what a certificate record looks like".
* A CT log lists every name a certificate was ever issued for, including hosts
  that no longer resolve and internal names that never faced the internet.
  Failures to connect are expected and logged at debug, not as errors.
* Discovered rows are marked `source='ct'`, so the inventory can distinguish a
  certificate somebody is actually serving from one that merely appears in a
  public log.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

import aiosqlite

from app.config import get_settings

log = logging.getLogger("pktcert.ct_discovery")

# CT logs move slowly and crt.sh is a shared free service — hourly is plenty
# and keeps this well inside any reasonable courtesy limit.
_INTERVAL_SECONDS = 3600

# Let startup settle before the first search.
_FIRST_RUN_DELAY_SECONDS = 120

# crt.sh can return thousands of historic entries for a busy domain. Only the
# most recent are worth probing; the rest are long expired.
_MAX_HOSTS_PER_DOMAIN = 200


class CTDiscovery:
    def __init__(self, interval_seconds: int = _INTERVAL_SECONDS):
        self._interval = interval_seconds
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run_loop())
        log.info(f"CT auto-discovery started (interval={self._interval}s)")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _setting(self, db: aiosqlite.Connection, key: str):
        async with db.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except (ValueError, TypeError):
            return row[0]

    async def run_once(self) -> dict:
        cfg = get_settings()
        async with aiosqlite.connect(cfg.db_path) as db:
            db.row_factory = aiosqlite.Row

            enabled = await self._setting(db, "discovery_ct_auto_enabled")
            if not (enabled is True or str(enabled).lower() in ("1", "true", "yes")):
                log.info("CT auto-discovery is off — skipping")
                return {"skipped": True, "reason": "disabled"}

            domains = await self._setting(db, "discovery_ct_watched_domains") or []
            if isinstance(domains, str):
                domains = [d.strip() for d in domains.split(",") if d.strip()]
            if not domains:
                log.info("CT auto-discovery on, but no watched domains configured — skipping")
                return {"skipped": True, "reason": "no domains"}

            found, added, unreachable = 0, 0, 0
            for domain in domains:
                hosts = await self._hosts_for_domain(domain)
                found += len(hosts)
                for host in hosts:
                    got = await self._probe_and_store(db, host, domain)
                    if got is True:
                        added += 1
                    elif got is None:
                        unreachable += 1
            await db.commit()

        log.info(
            f"CT auto-discovery complete: {found} name(s) across {len(domains)} domain(s), "
            f"{added} new certificate(s) added, {unreachable} host(s) unreachable"
        )
        return {"names_seen": found, "added": added, "unreachable": unreachable}

    async def _hosts_for_domain(self, domain: str) -> list[str]:
        """Distinct hostnames a CT log has seen certificates issued for."""
        from app.cert import ct_search

        try:
            rows = await ct_search.search_crtsh(domain)
        except Exception as e:
            log.warning(f"crt.sh search failed for {domain}: {e}")
            return []

        hosts: list[str] = []
        seen: set[str] = set()
        for row in rows:
            # name_value holds one or more names, newline separated.
            for name in str(row.get("name_value") or "").split("\n"):
                name = name.strip().lstrip("*.").lower()
                # A wildcard reduces to its parent, which is worth probing;
                # an empty or obviously non-DNS entry is not.
                if not name or "." not in name or " " in name or name in seen:
                    continue
                seen.add(name)
                hosts.append(name)
                if len(hosts) >= _MAX_HOSTS_PER_DOMAIN:
                    return hosts
        return hosts

    async def _probe_and_store(
        self, db: aiosqlite.Connection, host: str, domain: str
    ) -> Optional[bool]:
        """Fetch the live certificate for *host* and record it.

        Returns True if a new certificate was stored, False if it was already
        known, and None if the host could not be reached — which is normal for
        CT results and is not an error.
        """
        from app.cert import x509_utils

        try:
            leaf_pem, chain_pem = await asyncio.to_thread(
                x509_utils.fetch_cert_chain, host, 443, 5.0
            )
            info = x509_utils.parse_certificate(leaf_pem)
        except Exception as e:
            log.debug(f"CT lead {host} not reachable on 443 — {e}")
            return None

        async with db.execute(
            "SELECT id FROM certificates WHERE fingerprint_sha256 = ?",
            (info["fingerprint_sha256"],),
        ) as cur:
            existing = await cur.fetchone()

        if existing:
            await db.execute(
                "UPDATE certificates SET last_seen_at = datetime('now') WHERE id = ?",
                (existing[0],),
            )
            return False

        await db.execute(
            """INSERT INTO certificates
               (common_name, san_json, issuer, subject, serial_number, fingerprint_sha256,
                not_before, not_after, key_algorithm, key_size, signature_algorithm,
                status, source, host, port, cert_pem, chain_pem)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'valid', 'ct', ?, 443, ?, ?)""",
            (
                info["common_name"], json.dumps(info["san"]), info["issuer"], info["subject"],
                info["serial_number"], info["fingerprint_sha256"], info["not_before"],
                info["not_after"], info["key_algorithm"], info["key_size"],
                info["signature_algorithm"], host, leaf_pem, chain_pem,
            ),
        )
        async with db.execute(
            "SELECT id FROM certificates WHERE fingerprint_sha256 = ?",
            (info["fingerprint_sha256"],),
        ) as cur:
            row = await cur.fetchone()
        if row:
            await db.execute(
                "INSERT INTO cert_events (certificate_id, event_type, message) "
                "VALUES (?, 'discovered', ?)",
                (row[0], f"Discovered via Certificate Transparency search of {domain}"),
            )
        return True

    async def _run_loop(self) -> None:
        await asyncio.sleep(_FIRST_RUN_DELAY_SECONDS)
        while True:
            try:
                await self.run_once()
            except Exception as e:
                log.error(f"CT auto-discovery error: {e}")
            await asyncio.sleep(self._interval)
