"""
app/cert/scanner.py
--------------------
Background loop that scans every enabled scan_target on its own configured
schedule, connects via TLS to fetch the live certificate (+ chain where the
peer offers one), and upserts the result into the certificates table
(matched by fingerprint_sha256 — a cert already seen elsewhere, e.g. via CT
search, just gets its scan_target_id/host/port/last_seen_at attached rather
than being duplicated).

Manual "Scan Now" (app/api/scan_targets.py) calls scan_target_once()
directly — same code path as the scheduled loop, just triggered
out-of-band, so there's exactly one implementation of "what a scan does".
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Optional

import aiosqlite

from app.cert import x509_utils

log = logging.getLogger("pktcert.scanner")

_TICK_SECONDS = 30


def _expand_hosts(target) -> list[str]:
    if target["cidr"]:
        try:
            net = ipaddress.ip_network(target["cidr"], strict=False)
        except ValueError:
            return []
        # Cap fan-out so a fat-fingered /8 doesn't take the process down.
        return [str(ip) for ip in list(net.hosts())[:4096]] or [str(net.network_address)]
    if target["host"]:
        return [target["host"]]
    return []


def _expand_ports(target) -> list[int]:
    ports = []
    for p in (target["ports"] or "443").split(","):
        p = p.strip()
        if p.isdigit():
            ports.append(int(p))
    return ports or [443]


async def _scan_one(host: str, port: int) -> Optional[dict]:
    try:
        leaf_pem, chain_pem = await asyncio.to_thread(x509_utils.fetch_cert_chain, host, port, 5.0)
        info = x509_utils.parse_certificate(leaf_pem)
        info["cert_pem"] = leaf_pem
        info["chain_pem"] = chain_pem
        return info
    except Exception as e:
        log.debug(f"Scan failed for {host}:{port} — {e}")
        return None


async def _upsert_certificate(db: aiosqlite.Connection, info: dict, scan_target_id: int, host: str, port: int) -> None:
    async with db.execute(
        "SELECT id FROM certificates WHERE fingerprint_sha256 = ?", (info["fingerprint_sha256"],)
    ) as cur:
        existing = await cur.fetchone()

    import json as _json
    if existing:
        await db.execute(
            """UPDATE certificates SET last_seen_at = datetime('now'), scan_target_id = ?,
               host = ?, port = ? WHERE id = ?""",
            (scan_target_id, host, port, existing[0]),
        )
        return

    await db.execute(
        """INSERT INTO certificates
           (common_name, san_json, issuer, subject, serial_number, fingerprint_sha256,
            not_before, not_after, key_algorithm, key_size, signature_algorithm,
            status, source, scan_target_id, host, port, cert_pem, chain_pem)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'valid', 'scan', ?, ?, ?, ?, ?)""",
        (
            info["common_name"], _json.dumps(info["san"]), info["issuer"], info["subject"],
            info["serial_number"], info["fingerprint_sha256"], info["not_before"], info["not_after"],
            info["key_algorithm"], info["key_size"], info["signature_algorithm"],
            scan_target_id, host, port, info["cert_pem"], info["chain_pem"],
        ),
    )
    cur = await db.execute("SELECT id FROM certificates WHERE fingerprint_sha256 = ?", (info["fingerprint_sha256"],))
    row = await cur.fetchone()
    if row:
        await db.execute(
            "INSERT INTO cert_events (certificate_id, event_type, message) VALUES (?, 'discovered', ?)",
            (row[0], f"Discovered via scan of {host}:{port}"),
        )


async def scan_target_once(db_path: str, target_id: int) -> dict:
    """Scan a single target immediately, update its status, and return a summary."""
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM scan_targets WHERE id = ?", (target_id,)) as cur:
            target = await cur.fetchone()
        if not target:
            return {"status": "error", "detail": "Scan target not found"}

        hosts = _expand_hosts(target)
        ports = _expand_ports(target)
        found, errors = 0, []

        for host in hosts:
            for port in ports:
                info = await _scan_one(host, port)
                if info:
                    await _upsert_certificate(db, info, target_id, host, port)
                    found += 1
                else:
                    errors.append(f"{host}:{port}")

        status = "ok" if found > 0 or not errors else "error"
        last_error = f"{len(errors)} unreachable" if errors and found == 0 else None
        await db.execute(
            "UPDATE scan_targets SET last_scan_at = datetime('now'), last_status = ?, last_error = ? WHERE id = ?",
            (status, last_error, target_id),
        )
        await db.commit()

        return {"status": status, "certificates_found": found, "hosts_scanned": len(hosts) * len(ports), "errors": len(errors)}


class ScanEngine:
    _instance: "Optional[ScanEngine]" = None

    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None
        self._db_path: str = ""

    async def start(self, db_path: str) -> None:
        ScanEngine._instance = self
        self._db_path = db_path
        self._task = asyncio.create_task(self._run_loop())
        log.info("Scan engine started")

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
                await self._tick()
            except Exception as e:
                log.error(f"Scan engine tick error: {e}")
            await asyncio.sleep(_TICK_SECONDS)

    async def _tick(self) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """SELECT id FROM scan_targets
                   WHERE enabled = 1 AND schedule_minutes > 0
                     AND (last_scan_at IS NULL OR last_scan_at < datetime('now', '-' || schedule_minutes || ' minutes'))"""
            ) as cur:
                due = await cur.fetchall()

        for row in due:
            try:
                await scan_target_once(self._db_path, row["id"])
            except Exception as e:
                log.error(f"Scan of target {row['id']} failed: {e}")
