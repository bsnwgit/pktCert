"""
/api/approvals/* — the separation-of-duties queue.

When approval is required (Settings -> Cert Settings), issuing or revoking a
certificate records a pending request instead of acting, and a *different*
admin approves it. The approval is what performs the real operation, through
exactly the same code path the direct route uses — an approved certificate is
indistinguishable from a directly-issued one.

The feature is off by default. With it off, none of this is reachable in
anger: the certificates routes never create requests, and this queue stays
empty. A small team where everyone is trusted equally gains nothing from an
approval step and loses time on every issuance, so it has to be opted into.

Self-approval is refused. One person clicking twice is not two pairs of eyes,
and allowing it would make the control decorative — which is worse than not
having it, because it looks like a control in an audit.
"""
from __future__ import annotations

import json

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.cert import issuance
from app.database import get_db
from app.dependencies import AdminUser, AnalystUser, CurrentUser

router = APIRouter()


async def approval_required(db: aiosqlite.Connection, action: str) -> bool:
    """Is approval required for 'issue' or 'revoke'? Default False for both."""
    key = "require_issuance_approval" if action == "issue" else "require_revocation_approval"
    async with db.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cur:
        row = await cur.fetchone()
    if not row or row[0] is None:
        return False
    try:
        return bool(json.loads(row[0]))
    except (ValueError, TypeError):
        return False


async def admin_count(db: aiosqlite.Connection) -> int:
    """How many active admins exist — used to warn that a single-admin install
    cannot approve anything, since self-approval is refused."""
    async with db.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1"
    ) as cur:
        row = await cur.fetchone()
    return row[0] if row else 0


def _out(r) -> dict:
    return {
        "id": r["id"], "request_type": r["request_type"], "status": r["status"],
        "common_name": r["common_name"], "sans": json.loads(r["sans_json"] or "[]"),
        "ca_id": r["ca_id"], "template_id": r["template_id"],
        "auto_renew": bool(r["auto_renew"]), "auto_renew_days": r["auto_renew_days"],
        "certificate_id": r["certificate_id"], "reason": r["reason"], "reason_code": r["reason_code"],
        "requested_by": r["requested_by"], "requested_by_id": r["requested_by_id"],
        "justification": r["justification"], "requested_at": r["requested_at"],
        "decided_by": r["decided_by"], "decided_at": r["decided_at"],
        "decision_note": r["decision_note"],
        "resulting_certificate_id": r["resulting_certificate_id"],
    }


async def create_request(
    db: aiosqlite.Connection, user: dict, request_type: str, *,
    common_name: str = "", sans: list[str] | None = None,
    ca_id: int | None = None, template_id: int | None = None,
    auto_renew: bool = False, auto_renew_days: int = 30,
    certificate_id: int | None = None, reason: str = "", reason_code: str = "",
    justification: str = "",
):
    """Record a pending request. Called by the certificates routes when the
    corresponding approval setting is on."""
    cur = await db.execute(
        """INSERT INTO cert_requests
           (request_type, common_name, sans_json, ca_id, template_id, auto_renew, auto_renew_days,
            certificate_id, reason, reason_code, requested_by, requested_by_id, justification)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *""",
        (request_type, common_name or None, json.dumps(sans or []), ca_id, template_id,
         int(bool(auto_renew)), auto_renew_days, certificate_id, reason or None, reason_code or None,
         user["username"], user["id"], justification or None),
    )
    row = await cur.fetchone()
    await db.execute(
        "INSERT INTO cert_events (certificate_id, ca_id, event_type, message) VALUES (?, ?, 'approval_requested', ?)",
        (certificate_id, ca_id,
         f"{request_type.capitalize()} requested by {user['username']} — awaiting approval (request {row['id']})"),
    )
    await db.commit()
    return row


@router.get("")
async def list_requests(
    user: CurrentUser,
    status: str | None = None,
    limit: int = 200,
    db: aiosqlite.Connection = Depends(get_db),
):
    query = "SELECT * FROM cert_requests"
    params: list = []
    if status:
        query += " WHERE status = ?"
        params.append(status)
    query += " ORDER BY requested_at DESC LIMIT ?"
    params.append(limit)
    async with db.execute(query, params) as cur:
        rows = await cur.fetchall()
    return [_out(r) for r in rows]


@router.get("/config")
async def approval_config(user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    """What the UI needs to decide whether to show the queue at all, and to
    warn about a single-admin install that could never approve anything."""
    async with db.execute("SELECT COUNT(*) FROM cert_requests WHERE status = 'pending'") as cur:
        pending = (await cur.fetchone())[0]
    return {
        "issuance_approval_required": await approval_required(db, "issue"),
        "revocation_approval_required": await approval_required(db, "revoke"),
        "admin_count": await admin_count(db),
        "pending_count": pending,
    }


class DecisionRequest(BaseModel):
    note: str = ""


async def _load_pending(db: aiosqlite.Connection, request_id: int):
    async with db.execute("SELECT * FROM cert_requests WHERE id = ?", (request_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Request not found")
    if row["status"] != "pending":
        raise HTTPException(400, f"Request is already {row['status']}")
    return row


@router.post("/{request_id}/approve")
async def approve_request(
    request_id: int, body: DecisionRequest, user: AdminUser,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Approve and execute. The approval is the action — nothing was issued or
    revoked when the request was made."""
    row = await _load_pending(db, request_id)

    # The whole point of the control. Note this compares user ids, so it also
    # blocks the suite-proxy synthetic user (id 0) from rubber-stamping its
    # own requests.
    if row["requested_by_id"] is not None and row["requested_by_id"] == user["id"]:
        raise HTTPException(
            403,
            "You raised this request, so you cannot approve it — approval has to come from "
            "a second admin. If this install only has one admin, turn approval off in "
            "Settings → Cert Settings rather than working around it.",
        )

    result: dict = {}
    if row["request_type"] == "issue":
        async with db.execute("SELECT * FROM certificate_authorities WHERE id = ?", (row["ca_id"],)) as cur:
            ca_row = await cur.fetchone()
        if not ca_row:
            raise HTTPException(404, "The CA for this request no longer exists")
        if ca_row["status"] != "active":
            raise HTTPException(400, f"The CA for this request is not active (status: {ca_row['status']})")
        async with db.execute("SELECT * FROM cert_templates WHERE id = ?", (row["template_id"],)) as cur:
            template_row = await cur.fetchone()
        if not template_row:
            raise HTTPException(404, "The template for this request no longer exists")

        # No key passphrase on an approved issuance: the requester isn't here
        # to choose one, and the approver shouldn't be inventing a secret on
        # their behalf. The key is Fernet-encrypted at rest as always, and the
        # requester retrieves it through the usual step-up re-auth.
        cert_row, _key_pem = await issuance.issue_certificate(
            db, ca_row, template_row, row["common_name"], json.loads(row["sans_json"] or "[]"),
            auto_renew=bool(row["auto_renew"]), auto_renew_days=row["auto_renew_days"],
        )
        await db.execute(
            "UPDATE cert_requests SET resulting_certificate_id = ? WHERE id = ?",
            (cert_row["id"], request_id),
        )
        await db.execute(
            "INSERT INTO cert_events (certificate_id, ca_id, event_type, message) VALUES (?, ?, 'issued', ?)",
            (cert_row["id"], ca_row["id"],
             f"Issued for '{row['common_name']}' — requested by {row['requested_by']}, approved by {user['username']}"),
        )
        result = {"certificate_id": cert_row["id"]}

    elif row["request_type"] == "revoke":
        async with db.execute("SELECT * FROM certificates WHERE id = ?", (row["certificate_id"],)) as cur:
            cert = await cur.fetchone()
        if not cert:
            raise HTTPException(404, "The certificate for this request no longer exists")
        await db.execute(
            """UPDATE certificates SET status = 'revoked', revoked_at = datetime('now'),
               revoked_reason = ?, revoked_reason_code = ? WHERE id = ?""",
            (row["reason"], row["reason_code"] or "unspecified", row["certificate_id"]),
        )
        await db.execute(
            "INSERT INTO cert_events (certificate_id, ca_id, event_type, message) VALUES (?, ?, 'revoked', ?)",
            (row["certificate_id"], cert["ca_id"],
             f"Revoked ({row['reason_code'] or 'unspecified'}) — requested by {row['requested_by']}, "
             f"approved by {user['username']}"),
        )
        result = {"certificate_id": row["certificate_id"]}
    else:
        raise HTTPException(400, f"Unknown request type: {row['request_type']}")

    await db.execute(
        """UPDATE cert_requests SET status = 'approved', decided_by = ?, decided_by_id = ?,
           decided_at = datetime('now'), decision_note = ? WHERE id = ?""",
        (user["username"], user["id"], body.note or None, request_id),
    )
    await db.commit()

    async with db.execute("SELECT * FROM cert_requests WHERE id = ?", (request_id,)) as cur:
        updated = await cur.fetchone()
    return {**_out(updated), **result}


@router.post("/{request_id}/reject")
async def reject_request(
    request_id: int, body: DecisionRequest, user: AdminUser,
    db: aiosqlite.Connection = Depends(get_db),
):
    row = await _load_pending(db, request_id)
    if row["requested_by_id"] is not None and row["requested_by_id"] == user["id"]:
        raise HTTPException(403, "You raised this request — withdraw it instead of rejecting it")

    await db.execute(
        """UPDATE cert_requests SET status = 'rejected', decided_by = ?, decided_by_id = ?,
           decided_at = datetime('now'), decision_note = ? WHERE id = ?""",
        (user["username"], user["id"], body.note or None, request_id),
    )
    await db.execute(
        "INSERT INTO cert_events (certificate_id, ca_id, event_type, message) VALUES (?, ?, 'approval_rejected', ?)",
        (row["certificate_id"], row["ca_id"],
         f"Request {request_id} rejected by {user['username']}: {body.note or 'no reason given'}"),
    )
    await db.commit()
    async with db.execute("SELECT * FROM cert_requests WHERE id = ?", (request_id,)) as cur:
        return _out(await cur.fetchone())


@router.post("/{request_id}/cancel")
async def cancel_request(
    request_id: int, user: AnalystUser, db: aiosqlite.Connection = Depends(get_db),
):
    """Withdraw your own pending request. Admins may cancel anyone's — that's
    housekeeping, not an approval decision, so it isn't a way around the
    two-person rule: cancelling can only ever prevent an action, never cause
    one."""
    row = await _load_pending(db, request_id)
    if user["role"] != "admin" and row["requested_by_id"] != user["id"]:
        raise HTTPException(403, "You can only withdraw your own requests")

    await db.execute(
        """UPDATE cert_requests SET status = 'cancelled', decided_by = ?, decided_by_id = ?,
           decided_at = datetime('now') WHERE id = ?""",
        (user["username"], user["id"], request_id),
    )
    await db.commit()
    async with db.execute("SELECT * FROM cert_requests WHERE id = ?", (request_id,)) as cur:
        return _out(await cur.fetchone())
