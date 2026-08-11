"""
app/cert/alert_engine.py
-------------------------
Lightweight certificate alert engine. Runs on an interval, evaluates
enabled alert_rules against the current state of certificates /
certificate_authorities / scan_targets, and opens/keeps-open/
auto-resolves alert_events.

What each rule watches for lives in app/cert/alert_conditions.py, along with
the parameters that condition accepts — expiry windows, minimum key sizes,
which signature algorithms count as broken, and so on. Conditions only report
what currently matches; every decision about opening, keeping and resolving an
event is made here, so adding a condition needs no knowledge of this file.

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
from app.cert import alert_conditions

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
                await _evaluate_rule(db, rule)
            await db.commit()


async def _fire_or_keep(db: aiosqlite.Connection, rule, certificate_id=None, ca_id=None,
                         message: str = "", value: Optional[float] = None):
    """Open a new alert_event if one isn't already active for this
    rule+target, and it hasn't auto-resolved within the rule's cooldown
    window (so a flapping condition doesn't reopen a new event every
    evaluation tick). A newly opened event is then dispatched to whichever
    channels the rule has enabled."""
    # Some conditions have no certificate or CA to key on — a scan target that
    # won't answer, an address failing enrolment. For those the message *is*
    # the identity, so deduplicating on the ids alone would collapse every
    # unreachable target into one alert and hide all but the first.
    targetless = certificate_id is None and ca_id is None
    if targetless:
        async with db.execute(
            "SELECT id FROM alert_events WHERE rule_id = ? AND active = 1 AND message = ?",
            (rule["id"], message),
        ) as cur:
            existing = await cur.fetchone()
    else:
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


async def _auto_resolve(db: aiosqlite.Connection, rule, still_bad_cert_ids: set,
                        still_bad_ca_ids: set, still_bad_messages: set | None = None):
    """Close alerts whose cause has gone away.

    Targetless alerts reconcile on their message, for the same reason they
    deduplicate on it: there is no id to compare. Without that they resolved
    themselves on the very tick that opened them — nothing to match against
    meant "nothing still wrong" — so a scan target could be down for a week
    and re-alert every minute without an alert ever staying open.
    """
    async with db.execute(
        "SELECT id, certificate_id, ca_id, message FROM alert_events WHERE rule_id = ? AND active = 1",
        (rule["id"],),
    ) as cur:
        active = await cur.fetchall()
    for row in active:
        if row["certificate_id"] is None and row["ca_id"] is None:
            if still_bad_messages is not None and row["message"] not in still_bad_messages:
                await db.execute(
                    """UPDATE alert_events SET active = 0, resolved = 1, auto_resolved = 1,
                       resolved_at = datetime('now') WHERE id = ?""",
                    (row["id"],),
                )
            continue
        cert_ok = row["certificate_id"] is None or row["certificate_id"] not in still_bad_cert_ids
        ca_ok = row["ca_id"] is None or row["ca_id"] not in still_bad_ca_ids
        if cert_ok and ca_ok:
            await db.execute(
                """UPDATE alert_events SET active = 0, resolved = 1, auto_resolved = 1,
                   resolved_at = datetime('now') WHERE id = ?""",
                (row["id"],),
            )


async def _evaluate_rule(db: aiosqlite.Connection, rule) -> None:
    """Run one rule through its condition and reconcile the open alerts.

    Conditions live in app/cert/alert_conditions.py and only ever *report* —
    they return the things currently matching. Everything about opening,
    keeping, and resolving events is decided here, so a new condition needs no
    knowledge of the alerting machinery.
    """
    entry = alert_conditions.EVALUATORS.get(rule["condition_type"])
    if entry is None:
        return
    evaluate, target = entry

    try:
        matches = await evaluate(db, rule)
    except Exception as e:
        log.error(f"Alert rule '{rule['name']}' ({rule['condition_type']}) failed to evaluate: {e}")
        return

    still_bad_certs, still_bad_cas, still_bad_messages = set(), set(), set()
    for target_id, message in matches:
        still_bad_messages.add(message)
        certificate_id = target_id if target == "certificate" else None
        ca_id = target_id if target == "ca" else None
        if certificate_id is not None:
            still_bad_certs.add(certificate_id)
        if ca_id is not None:
            still_bad_cas.add(ca_id)
        await _fire_or_keep(db, rule, certificate_id=certificate_id, ca_id=ca_id, message=message)

    if rule["condition_type"] not in alert_conditions.TERMINAL:
        await _auto_resolve(db, rule, still_bad_certs, still_bad_cas, still_bad_messages)


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
