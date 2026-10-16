"""
/api/ct-checks — the history of crt.sh validations, readable by every role.

The checks themselves are run by POST /api/certificates/ct-check and
POST /api/certificates/{id}/ct-check (analyst or higher; see certificates.py),
which record here. This router only reads: a viewer can see what has been
checked and what came back, but cannot spend crt.sh on anyone's behalf.
"""
from __future__ import annotations

import json

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Query

from app.database import get_db
from app.dependencies import CurrentUser

router = APIRouter()

_VERDICTS = ("logged", "not_logged", "unexpected_found", "unavailable", "inconclusive", "not_applicable",
             "running", "failed")


def _check_out(r) -> dict:
    return {
        "id": r["id"], "checked_at": r["checked_at"], "checked_by": r["checked_by"],
        "source": r["source"], "certificate_id": r["certificate_id"],
        "common_name": r["common_name"], "issuer": r["issuer"], "serial_number": r["serial_number"],
        "fingerprint_sha256": r["fingerprint_sha256"], "not_after": r["not_after"],
        "fetched_from": r["fetched_from"], "verdict": r["verdict"],
        "unexpected_count": r["unexpected_count"],
    }


@router.get("")
async def list_ct_checks(
    user: CurrentUser,
    search: str | None = Query(default=None, max_length=200),
    verdict: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    db: aiosqlite.Connection = Depends(get_db),
):
    if verdict and verdict not in _VERDICTS:
        raise HTTPException(400, "Unknown verdict")
    query = "SELECT * FROM ct_checks WHERE 1=1"
    params: list = []
    if verdict:
        query += " AND verdict = ?"
        params.append(verdict)
    if search:
        query += " AND (common_name LIKE ? OR checked_by LIKE ? OR issuer LIKE ? OR fetched_from LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like, like, like])
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    async with db.execute(query, params) as cur:
        return [_check_out(r) for r in await cur.fetchall()]


@router.get("/{check_id}")
async def get_ct_check(check_id: int, user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM ct_checks WHERE id = ?", (check_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Check not found")
    try:
        result = json.loads(row["result_json"])
    except ValueError:
        result = {}
    return {**_check_out(row), "result": result}
