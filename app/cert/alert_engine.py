"""
app/cert/alert_engine.py
-------------------------
Lightweight certificate alert engine. Runs on an interval, evaluates
enabled alert_rules against the current state of certificates /
certificate_authorities / scan_targets, and opens/keeps-open/
auto-resolves alert_events.

Supported condition_type values:
  cert_expiring             - a valid certificate's not_after is within
                               `threshold` days (default 30)
  cert_expired               - a certificate's not_after has already passed
  cert_revoked                - a certificate was revoked (fires once, no
                               auto-resolve — revocation is terminal)
  ca_expiring                 - a CA's not_after is within `threshold` days
                               (default 90 — CAs need longer lead time)
  scan_target_unreachable     - a scan target's last_status = 'error'

A newly opened event is dispatched to whichever channels its rule enables
(app/notifications.py), with every outcome recorded in notification_log.
Only the opening tick notifies — an event that merely stays open does not
re-notify, or an expiring certificate would page someone every 60 seconds
until it was renewed.

Also runs a nightly-scale expiry-status refresh so certificates.status
(valid/expiring/expired) stays current even between scans, and exposes
run_cleanup_once() for the Data -> Storage "Run Cleanup" button (trims old
resolved alert_events and their notification_log rows, matching the
retention pattern used across the suite).
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

import aiosqlite

from app import notifications

log = logging.getLogger("pktcert.alerts")

_EVAL_INTERVAL = 60  # seconds


class AlertEngine:
    _instance: "Optional[AlertEngine]" = None

    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None
        self._db_path: str = ""

    async def start(self, db_path: str) -> None:
        AlertEngine._instance = self
        self._db_path = db_path
        self._task = asyncio.create_task(self._run_loop())
        log.info("Alert engine started")

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
                await self._refresh_statuses()
                await self._evaluate()
            except Exception as e:
                log.error(f"Alert engine evaluation error: {e}")
            await asyncio.sleep(_EVAL_INTERVAL)

    async def _refresh_statuses(self) -> None:
        """Keep certificates.status current between scans."""
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """UPDATE certificates SET status = 'expired'
                   WHERE status NOT IN ('revoked', 'expired', 'superseded') AND not_after IS NOT NULL
                     AND not_after < datetime('now')"""
            )
            await db.execute(
                """UPDATE certificates SET status = 'expiring'
                   WHERE status = 'valid' AND not_after IS NOT NULL
                     AND not_after < datetime('now', '+30 days')"""
            )
            await db.execute(
                """UPDATE certificates SET status = 'valid'
                   WHERE status IN ('expiring') AND not_after IS NOT NULL
                     AND not_after >= datetime('now', '+30 days')"""
            )
            await db.commit()

    async def _evaluate(self) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM alert_rules WHERE enabled = 1") as cur:
                rules = await cur.fetchall()

            for rule in rules:
                handler = _HANDLERS.get(rule["condition_type"])
                if handler:
                    await handler(db, rule)
            await db.commit()


async def _fire_or_keep(db: aiosqlite.Connection, rule, certificate_id=None, ca_id=None,
                         message: str = "", value: Optional[float] = None):
    """Open a new alert_event if one isn't already active for this
    rule+target, and it hasn't auto-resolved within the rule's cooldown
    window (so a flapping condition doesn't reopen a new event every
    evaluation tick). A newly opened event is then dispatched to whichever
    channels the rule has enabled."""
    async with db.execute(
        """SELECT id FROM alert_events
           WHERE rule_id = ? AND active = 1
             AND certificate_id IS ? AND ca_id IS ?""",
        (rule["id"], certificate_id, ca_id),
    ) as cur:
        existing = await cur.fetchone()
    if existing:
        return

    cooldown_min = rule["cooldown_min"] or 0
    if cooldown_min:
        async with db.execute(
            """SELECT id FROM alert_events
               WHERE rule_id = ? AND certificate_id IS ? AND ca_id IS ?
                 AND resolved_at >= datetime('now', ?)
               ORDER BY resolved_at DESC LIMIT 1""",
            (rule["id"], certificate_id, ca_id, f"-{cooldown_min} minutes"),
        ) as cur:
            recently_resolved = await cur.fetchone()
        if recently_resolved:
            return

    cur = await db.execute(
        """INSERT INTO alert_events
           (rule_id, certificate_id, ca_id, severity, message, value, threshold, active)
           VALUES (?, ?, ?, ?, ?, ?, ?, 1) RETURNING id""",
        (rule["id"], certificate_id, ca_id, rule["severity"], message, value, rule["threshold"]),
    )
    row = await cur.fetchone()
    if row:
        await _dispatch(db, rule, row[0], message, certificate_id, ca_id)


async def _dispatch(db: aiosqlite.Connection, rule, event_id: int, message: str,
                    certificate_id=None, ca_id=None) -> None:
    """Send a newly opened alert to every channel its rule enables, recording
    each outcome in notification_log.

    Only fires for *newly opened* events, never on subsequent ticks that
    merely keep an event open — otherwise an expiring certificate would
    re-notify every 60 seconds until someone renewed it.
    """
    try:
        channels = json.loads(rule["channels"])
    except (TypeError, ValueError):
        channels = ["inapp"]

    details = {"certificate_id": certificate_id, "ca_id": ca_id,
               "condition_type": rule["condition_type"]}

    for channel in channels or ["inapp"]:
        status, detail = await notifications.send_to_channel(
            db, channel, rule_name=rule["name"], message=message,
            severity=rule["severity"], event_id=event_id, details=details,
        )
        if status == "failed":
            log.warning(f"Alert {event_id} delivery failed on {channel}: {detail}")
        await db.execute(
            "INSERT INTO notification_log (event_id, channel, status, error) VALUES (?, ?, ?, ?)",
            (event_id, channel, status, detail if status != "sent" else None),
        )


async def _auto_resolve(db: aiosqlite.Connection, rule, still_bad_cert_ids: set, still_bad_ca_ids: set):
    async with db.execute(
        "SELECT id, certificate_id, ca_id FROM alert_events WHERE rule_id = ? AND active = 1",
        (rule["id"],),
    ) as cur:
        active = await cur.fetchall()
    for row in active:
        cert_ok = row["certificate_id"] is None or row["certificate_id"] not in still_bad_cert_ids
        ca_ok = row["ca_id"] is None or row["ca_id"] not in still_bad_ca_ids
        if cert_ok and ca_ok:
            await db.execute(
                """UPDATE alert_events SET active = 0, resolved = 1, auto_resolved = 1,
                   resolved_at = datetime('now') WHERE id = ?""",
                (row["id"],),
            )


async def _check_cert_expiring(db: aiosqlite.Connection, rule) -> None:
    threshold_days = int(rule["threshold"] or 30)
    async with db.execute(
        """SELECT id, common_name, not_after FROM certificates
           WHERE status NOT IN ('revoked', 'expired', 'superseded')
             AND not_after IS NOT NULL
             AND not_after < datetime('now', ?)
             AND not_after >= datetime('now')""",
        (f"+{threshold_days} days",),
    ) as cur:
        rows = await cur.fetchall()
    bad_ids = set()
    for r in rows:
        bad_ids.add(r["id"])
        await _fire_or_keep(db, rule, certificate_id=r["id"],
                             message=f"Certificate '{r['common_name']}' expires {r['not_after']}")
    await _auto_resolve(db, rule, bad_ids, set())


async def _check_cert_expired(db: aiosqlite.Connection, rule) -> None:
    async with db.execute(
        """SELECT id, common_name, not_after FROM certificates
           WHERE status != 'superseded'
             AND (status = 'expired' OR (not_after IS NOT NULL AND not_after < datetime('now')))"""
    ) as cur:
        rows = await cur.fetchall()
    bad_ids = set()
    for r in rows:
        bad_ids.add(r["id"])
        await _fire_or_keep(db, rule, certificate_id=r["id"],
                             message=f"Certificate '{r['common_name']}' expired {r['not_after']}")
    await _auto_resolve(db, rule, bad_ids, set())


async def _check_cert_revoked(db: aiosqlite.Connection, rule) -> None:
    # Revocation is terminal — fire once per cert, never auto-resolve.
    async with db.execute(
        "SELECT id, common_name, revoked_at, revoked_reason FROM certificates WHERE status = 'revoked'"
    ) as cur:
        rows = await cur.fetchall()
    for r in rows:
        reason = f" ({r['revoked_reason']})" if r["revoked_reason"] else ""
        await _fire_or_keep(db, rule, certificate_id=r["id"],
                             message=f"Certificate '{r['common_name']}' was revoked{reason}")


async def _check_ca_expiring(db: aiosqlite.Connection, rule) -> None:
    threshold_days = int(rule["threshold"] or 90)
    async with db.execute(
        """SELECT id, name, not_after FROM certificate_authorities
           WHERE status = 'active' AND not_after < datetime('now', ?)
             AND not_after >= datetime('now')""",
        (f"+{threshold_days} days",),
    ) as cur:
        rows = await cur.fetchall()
    bad_ids = set()
    for r in rows:
        bad_ids.add(r["id"])
        await _fire_or_keep(db, rule, ca_id=r["id"],
                             message=f"CA '{r['name']}' expires {r['not_after']}")
    await _auto_resolve(db, rule, set(), bad_ids)


async def _check_scan_target_unreachable(db: aiosqlite.Connection, rule) -> None:
    async with db.execute(
        "SELECT id, name, last_error FROM scan_targets WHERE enabled = 1 AND last_status = 'error'"
    ) as cur:
        rows = await cur.fetchall()
    # scan_targets isn't certificate/CA-scoped, so track "still bad" via a
    # synthetic certificate_id-shaped bucket isn't applicable — use ca_id
    # slot as a free integer key space is unsafe (collides with real CAs),
    # so this condition simply fires per-target without an auto-resolve
    # target set; the next tick's fire_or_keep no-ops once the target
    # recovers because the WHERE clause above stops returning that row,
    # leaving cleanup to the acknowledge/resolve UI.
    for r in rows:
        await _fire_or_keep(db, rule, message=f"Scan target '{r['name']}' unreachable: {r['last_error'] or 'unknown error'}")


_HANDLERS = {
    "cert_expiring": _check_cert_expiring,
    "cert_expired": _check_cert_expired,
    "cert_revoked": _check_cert_revoked,
    "ca_expiring": _check_ca_expiring,
    "scan_target_unreachable": _check_scan_target_unreachable,
}


async def run_cleanup_once() -> dict:
    """Trim old resolved alert_events past a fixed retention window.
    Invoked on a schedule isn't wired here (kept simple, v1) — exposed for
    the Data -> Storage 'Run Cleanup' button in Settings."""
    from app.config import get_settings
    settings = get_settings()
    async with aiosqlite.connect(settings.db_path) as db:
        # notification_log rows go first and explicitly. The schema cascades
        # them, but this connection doesn't turn foreign_keys on (SQLite
        # defaults it off per-connection), so relying on the cascade here
        # would silently strand them.
        cur = await db.execute(
            """DELETE FROM notification_log WHERE event_id IN (
                   SELECT id FROM alert_events
                   WHERE resolved = 1 AND resolved_at < datetime('now', '-90 days'))"""
        )
        removed_notifications = cur.rowcount
        cur = await db.execute(
            "DELETE FROM alert_events WHERE resolved = 1 AND resolved_at < datetime('now', '-90 days')"
        )
        removed = cur.rowcount
        await db.commit()
    return {
        "status": "ok",
        "removed_alert_events": removed,
        "removed_notification_log": removed_notifications,
    }
