"""
History of Certificate Transparency checks (crt.sh validations).

Every validation — of an inventory certificate or of one pasted or fetched on
the CT Checks page — leaves a row, so everyone with a login can see what has
been checked and what the answer was, rather than each person repeating a
lookup against a free shared service.

A check is slow on a large domain (crt.sh took over 30 seconds for a single name
on one of the biggest), longer than a proxy in front of this app will wait. So a
check is recorded as ``running`` the moment it starts, the request returns, and
:func:`finish_check` fills in the answer when crt.sh has given it. The page
polls the row. ``failed`` means the check itself broke or was interrupted — it
says nothing about the certificate.

What is kept is what identifies the certificate and the verdict, plus the full
result so a row can be expanded later. A PEM is never stored.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import aiosqlite

from app.cert import ct_search
from app.database import DB_PATH

log = logging.getLogger("pktcert.ct_history")

# Pseudo-verdicts for a row that has no answer (yet).
RUNNING = "running"
FAILED = "failed"

# Nothing legitimate takes this long: ten names, each allowed a long wait and a
# retry. Past it the check is abandoned rather than left "running" forever.
_OVERALL_TIMEOUT_SECONDS = 900


async def record_start(
    db: aiosqlite.Connection,
    *,
    username: str,
    source: str,
    certificate_id: int | None,
    cert: dict[str, Any],
    fetched_from: str | None = None,
) -> int:
    cur = await db.execute(
        """INSERT INTO ct_checks
           (checked_by, source, certificate_id, common_name, issuer, serial_number,
            fingerprint_sha256, not_after, fetched_from, verdict, unexpected_count, result_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '{}')""",
        (
            username, source, certificate_id,
            cert.get("common_name") or "", cert.get("issuer") or "",
            cert.get("serial_number") or "", cert.get("fingerprint_sha256") or "",
            cert.get("not_after"), fetched_from, RUNNING,
        ),
    )
    await db.commit()
    return cur.lastrowid


async def _store(db: aiosqlite.Connection, check_id: int, verdict: str, unexpected: int, result: dict) -> None:
    await db.execute(
        "UPDATE ct_checks SET verdict = ?, unexpected_count = ?, result_json = ? WHERE id = ?",
        (verdict, unexpected, json.dumps(result), check_id),
    )
    await db.commit()


async def finish_check(
    check_id: int,
    *,
    username: str,
    cert: dict[str, Any],
    certificate_summary: dict[str, Any] | None,
) -> None:
    """Run the crt.sh validation for a ``running`` row and store the outcome.

    Runs after the response has gone, on its own connection — the request's
    connection is closed by then. Never raises: whatever goes wrong ends up on
    the row as ``failed`` so nobody is left watching a check that will not finish.
    """
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA busy_timeout=5000")
            try:
                async with db.execute("SELECT id, serial_number FROM certificates WHERE serial_number IS NOT NULL") as cur:
                    inventory = await cur.fetchall()
                known = {r["serial_number"] for r in inventory}
                result = await asyncio.wait_for(
                    ct_search.validate_against_crtsh(cert, known), _OVERALL_TIMEOUT_SECONDS
                )
            except asyncio.TimeoutError:
                await _store(db, check_id, FAILED, 0, {"error": "crt.sh took too long to answer; try again later"})
                return
            except Exception as e:
                log.warning(f"CT check {check_id} failed: {type(e).__name__}: {e}")
                await _store(db, check_id, FAILED, 0, {"error": f"The check failed ({type(e).__name__})"})
                return

            mine = next(
                (r["id"] for r in inventory
                 if ct_search._norm_serial(r["serial_number"]) == ct_search._norm_serial(cert.get("serial_number"))),
                None,
            )
            if certificate_summary is not None:
                result["certificate"] = certificate_summary
            result["in_inventory_id"] = mine

            if mine is not None:
                await db.execute(
                    "INSERT INTO cert_events (certificate_id, event_type, message) VALUES (?, 'ct_checked', ?)",
                    (mine, f"Checked against crt.sh by {username}: {result['verdict']}"),
                )
            await db.execute("UPDATE ct_checks SET certificate_id = COALESCE(certificate_id, ?) WHERE id = ?", (mine, check_id))
            await _store(db, check_id, result["verdict"], len(result.get("unexpected") or []), result)
    except Exception as e:  # the database itself failed; nothing left to record on
        log.error(f"CT check {check_id} could not be stored: {type(e).__name__}: {e}")


async def fail_interrupted() -> int:
    """Called at startup: a check still ``running`` belonged to a process that
    has since gone, and will never finish."""
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "UPDATE ct_checks SET verdict = ?, result_json = ? WHERE verdict = ?",
            (FAILED, json.dumps({"error": "Interrupted by a restart; run the check again"}), RUNNING),
        )
        await db.commit()
        return cur.rowcount
