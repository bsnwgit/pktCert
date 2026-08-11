"""
/api/alerts/* — alert rule configuration + alert event feed.
"""
from __future__ import annotations

import csv
import io
import json

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app import notifications
from app.cert import alert_conditions
from app.database import get_db
from app.dependencies import CurrentUser, AnalystUser, AdminUser

router = APIRouter()

# Derived from the condition registry rather than duplicated — a new
# condition becomes selectable by existing here and nowhere else.
_CONDITION_TYPES = set(alert_conditions.CONDITIONS)

# Mirrors app/notifications.py, which owns the senders. Settings -> Notifications
# has always been able to configure and test PagerDuty and TraceCat, but rules
# couldn't target them because this set was narrower than the senders available.
_CHANNEL_TYPES = notifications.CHANNEL_TYPES

_CSV_COLUMNS = ["name", "condition_type", "threshold", "severity", "enabled", "channels"]


class RuleRequest(BaseModel):
    name: str
    condition_type: str
    threshold: float | None = None
    severity: str = "warning"
    enabled: bool = True
    channels: list[str] = ["inapp"]
    # Whatever this condition needs — see app/cert/alert_conditions.py. Absent
    # values fall back to the legacy `threshold` column and then the
    # condition's own default, so rules written before parameters existed keep
    # working unchanged.
    params: dict = {}
    # Which certificates the rule watches: ca_id, source, name_like, host_like.
    # Empty means all of them.
    scope: dict = {}


def _json_or(r, column: str, fallback):
    """Read a JSON column, tolerating a row read before the column existed."""
    try:
        raw = r[column]
    except (KeyError, IndexError):
        return fallback
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return fallback


@router.get("/conditions")
async def list_conditions(user: CurrentUser):
    """Every condition a rule can use, with the parameters it accepts.

    The Alerts page renders parameter inputs from this rather than hardcoding
    them per condition, so a condition added to the registry is immediately
    configurable in the UI with no frontend change."""
    return [c.as_dict() for c in alert_conditions.CONDITIONS.values()]


def _rule_out(r) -> dict:
    try:
        channels = json.loads(r["channels"])
    except (KeyError, IndexError, TypeError, ValueError):
        channels = ["inapp"]
    return {
        "id": r["id"], "name": r["name"], "condition_type": r["condition_type"],
        "threshold": r["threshold"], "severity": r["severity"],
        "enabled": bool(r["enabled"]), "channels": channels, "created_at": r["created_at"],
        "params": _json_or(r, "params_json", {}),
        "scope": _json_or(r, "scope_json", {}),
    }


def _event_out(r) -> dict:
    return {
        "id": r["id"], "rule_id": r["rule_id"], "certificate_id": r["certificate_id"],
        "ca_id": r["ca_id"], "severity": r["severity"], "message": r["message"],
        "value": r["value"], "threshold": r["threshold"], "active": bool(r["active"]),
        "acked": bool(r["acked"]), "acked_by": r["acked_by"], "acked_at": r["acked_at"],
        "resolved": bool(r["resolved"]), "auto_resolved": bool(r["auto_resolved"]),
        "resolved_at": r["resolved_at"], "created_at": r["created_at"],
    }


# -- Rules ---------------------------------------------------------------------

@router.get("/rules")
async def list_rules(user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM alert_rules ORDER BY name") as cur:
        rows = await cur.fetchall()
    return [_rule_out(r) for r in rows]


@router.get("/rules/export")
async def export_rules(user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM alert_rules ORDER BY name") as cur:
        rows = await cur.fetchall()
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS)
    writer.writeheader()
    for r in rows:
        try:
            channels = json.loads(r["channels"])
        except (KeyError, IndexError, TypeError, ValueError):
            channels = ["inapp"]
        writer.writerow({
            "name": r["name"], "condition_type": r["condition_type"],
            "threshold": r["threshold"] if r["threshold"] is not None else "",
            "severity": r["severity"], "enabled": int(r["enabled"]),
            "channels": ",".join(channels),
        })
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="pktcert-alert-rules.csv"'},
    )


@router.post("/rules/import-csv")
async def import_rules_csv(user: AdminUser, file: UploadFile = File(...), db: aiosqlite.Connection = Depends(get_db)):
    raw = (await file.read()).decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(raw))
    created, skipped, errors = 0, 0, []

    for i, row in enumerate(reader, start=2):  # header is row 1
        name = (row.get("name") or "").strip()
        condition_type = (row.get("condition_type") or "").strip()
        if not name or not condition_type:
            skipped += 1
            errors.append(f"Row {i}: missing name or condition_type")
            continue
        if condition_type not in _CONDITION_TYPES:
            skipped += 1
            errors.append(f"Row {i}: unknown condition_type '{condition_type}'")
            continue
        threshold_raw = (row.get("threshold") or "").strip()
        try:
            threshold = float(threshold_raw) if threshold_raw else None
        except ValueError:
            skipped += 1
            errors.append(f"Row {i}: invalid threshold '{threshold_raw}'")
            continue
        severity = (row.get("severity") or "warning").strip() or "warning"
        enabled = (row.get("enabled") or "1").strip() not in ("0", "false", "False", "")
        channels_raw = (row.get("channels") or "inapp").strip()
        channels = [c.strip() for c in channels_raw.split(",") if c.strip() in _CHANNEL_TYPES] or ["inapp"]

        try:
            await db.execute(
                """INSERT INTO alert_rules (name, condition_type, threshold, severity, enabled, cooldown_min, channels)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (name, condition_type, threshold, severity, int(enabled), 0, json.dumps(channels)),
            )
            created += 1
        except aiosqlite.IntegrityError as e:
            skipped += 1
            errors.append(f"Row {i}: {e}")

    await db.commit()
    return {"created": created, "skipped": skipped, "errors": errors}


@router.post("/rules", status_code=201)
async def create_rule(body: RuleRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    if body.condition_type not in _CONDITION_TYPES:
        raise HTTPException(status_code=400, detail=f"condition_type must be one of {sorted(_CONDITION_TYPES)}")
    channels = [c for c in body.channels if c in _CHANNEL_TYPES] or ["inapp"]
    cur = await db.execute(
        """INSERT INTO alert_rules (name, condition_type, threshold, severity, enabled, cooldown_min,
           channels, params_json, scope_json)
           VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?) RETURNING *""",
        (body.name, body.condition_type, body.threshold, body.severity, int(body.enabled),
         json.dumps(channels), json.dumps(body.params or {}), json.dumps(body.scope or {})),
    )
    row = await cur.fetchone()
    await db.commit()
    return _rule_out(row)


@router.patch("/rules/{rule_id}")
async def update_rule(rule_id: int, body: RuleRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT id FROM alert_rules WHERE id = ?", (rule_id,)) as cur:
        if not await cur.fetchone():
            raise HTTPException(status_code=404, detail="Rule not found")
    channels = [c for c in body.channels if c in _CHANNEL_TYPES] or ["inapp"]
    await db.execute(
        """UPDATE alert_rules SET name = ?, condition_type = ?, threshold = ?, severity = ?, enabled = ?,
           channels = ?, params_json = ?, scope_json = ? WHERE id = ?""",
        (body.name, body.condition_type, body.threshold, body.severity, int(body.enabled),
         json.dumps(channels), json.dumps(body.params or {}), json.dumps(body.scope or {}), rule_id),
    )
    await db.commit()
    async with db.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)) as cur:
        row = await cur.fetchone()
    return _rule_out(row)


@router.post("/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: int, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Rule not found")
    new_enabled = 0 if row["enabled"] else 1
    await db.execute("UPDATE alert_rules SET enabled = ? WHERE id = ?", (new_enabled, rule_id))
    await db.commit()
    async with db.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)) as cur:
        row = await cur.fetchone()
    return _rule_out(row)


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: int, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
    await db.commit()


# -- Events ----------------------------------------------------------------------

@router.get("/events")
async def list_events(
    user: CurrentUser,
    active: bool | None = None,
    acked: bool | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 200,
    db: aiosqlite.Connection = Depends(get_db),
):
    query = "SELECT * FROM alert_events WHERE 1=1"
    params: list = []
    if active is not None:
        query += " AND active = ?"
        params.append(int(active))
    if acked is not None:
        query += " AND acked = ?"
        params.append(int(acked))
    if since:
        query += " AND created_at >= ?"
        params.append(since)
    if until:
        query += " AND created_at <= ?"
        params.append(until)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    async with db.execute(query, params) as cur:
        rows = await cur.fetchall()
    return [_event_out(r) for r in rows]


@router.post("/events/{event_id}/ack")
async def ack_event(event_id: int, user: AnalystUser, db: aiosqlite.Connection = Depends(get_db)):
    await db.execute(
        "UPDATE alert_events SET acked = 1, acked_by = ?, acked_at = datetime('now') WHERE id = ?",
        (user["username"], event_id),
    )
    await db.commit()
    return {"status": "ok"}


@router.post("/events/ack-all")
async def ack_all_events(user: AnalystUser, db: aiosqlite.Connection = Depends(get_db)):
    cur = await db.execute(
        "UPDATE alert_events SET acked = 1, acked_by = ?, acked_at = datetime('now') WHERE active = 1 AND acked = 0",
        (user["username"],),
    )
    await db.commit()
    return {"status": "ok", "acked": cur.rowcount}


@router.post("/events/{event_id}/resolve")
async def resolve_event(event_id: int, user: AnalystUser, db: aiosqlite.Connection = Depends(get_db)):
    await db.execute(
        "UPDATE alert_events SET active = 0, resolved = 1, resolved_at = datetime('now') WHERE id = ?",
        (event_id,),
    )
    await db.commit()
    return {"status": "ok"}
