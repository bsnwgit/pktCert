"""
/api/dashboard/* — summary counts for the Dashboard page.
"""
from __future__ import annotations

import aiosqlite
from fastapi import APIRouter, Depends

from app.database import get_db
from app.dependencies import CurrentUser

router = APIRouter()


@router.get("/summary")
async def summary(user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    async def _count(query: str, params: tuple = ()) -> int:
        async with db.execute(query, params) as cur:
            row = await cur.fetchone()
        return row[0] if row else 0

    total = await _count("SELECT COUNT(*) FROM certificates")
    valid = await _count("SELECT COUNT(*) FROM certificates WHERE status = 'valid'")
    expiring = await _count("SELECT COUNT(*) FROM certificates WHERE status = 'expiring'")
    expired = await _count("SELECT COUNT(*) FROM certificates WHERE status = 'expired'")
    revoked = await _count("SELECT COUNT(*) FROM certificates WHERE status = 'revoked'")
    issued = await _count("SELECT COUNT(*) FROM certificates WHERE source = 'issued'")
    scanned = await _count("SELECT COUNT(*) FROM certificates WHERE source = 'scan'")
    ca_count = await _count("SELECT COUNT(*) FROM certificate_authorities")
    scan_targets = await _count("SELECT COUNT(*) FROM scan_targets WHERE enabled = 1")
    active_alerts = await _count("SELECT COUNT(*) FROM alert_events WHERE active = 1")

    async with db.execute(
        """SELECT id, common_name, not_after, status FROM certificates
           WHERE status IN ('expiring', 'expired') ORDER BY not_after ASC LIMIT 10"""
    ) as cur:
        expiring_soon = [dict(r) for r in await cur.fetchall()]

    async with db.execute(
        """SELECT ca_id, COUNT(*) AS n FROM certificates WHERE ca_id IS NOT NULL GROUP BY ca_id"""
    ) as cur:
        by_ca_rows = await cur.fetchall()
    by_ca = {r["ca_id"]: r["n"] for r in by_ca_rows}

    return {
        "total": total, "valid": valid, "expiring": expiring, "expired": expired, "revoked": revoked,
        "issued": issued, "scanned": scanned, "ca_count": ca_count, "scan_targets": scan_targets,
        "active_alerts": active_alerts, "expiring_soon": expiring_soon, "by_ca": by_ca,
    }
