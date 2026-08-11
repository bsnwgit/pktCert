"""
/api/settings/* — generic runtime settings key/value store.

Anything not covering startup/infra config (see app/config.py) lives here:
SAML config, alert/metrics retention windows, backup schedule, base_url
used to build the SAML ACS URL, etc. Frontend renders these on the
Settings page grouped by section.
"""
from __future__ import annotations

import json
from typing import Any

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app import notifications
from app.database import get_db
from app.dependencies import CurrentUser, AdminUser

router = APIRouter()

# Keys that must never be echoed back verbatim to non-admin callers.
_SECRET_KEYS = {
    "okta_saml_sp_key",
    "notify_email_password",
    "notify_pagerduty_integration_key",
    "notify_tracecat_api_token",
    "lucid_api_token",
}

# AI provider keys use the masked-with-preserve-on-save convention (a sentinel
# is returned instead of the value, and a save that echoes the sentinel back
# unchanged is a no-op) rather than the role-based omission above — this lets
# an admin see that a key IS set without ever re-exposing it, and never risks
# clobbering it on save.
_MASK = "••••••••"
_AI_MASK_KEYS = {"anthropic_api_key", "openai_api_key"}


def _mask_local_providers(providers: Any) -> Any:
    """Mask each entry's api_key, same convention as _AI_MASK_KEYS."""
    if not isinstance(providers, list):
        return providers
    masked = []
    for p in providers:
        if isinstance(p, dict) and p.get("api_key"):
            p = {**p, "api_key": _MASK}
        masked.append(p)
    return masked


async def _unmask_local_providers(db: aiosqlite.Connection, new_value: Any) -> Any:
    """Preserve existing api_key for any entry whose api_key round-tripped as the mask."""
    if not isinstance(new_value, list):
        return new_value
    async with db.execute("SELECT value FROM settings WHERE key='ai_local_providers'") as cur:
        row = await cur.fetchone()
    old_by_id = {}
    if row:
        try:
            for p in json.loads(row[0]) or []:
                if isinstance(p, dict) and p.get("id"):
                    old_by_id[p["id"]] = p.get("api_key", "")
        except (ValueError, TypeError):
            pass

    result = []
    for p in new_value:
        if isinstance(p, dict) and p.get("api_key") == _MASK:
            p = {**p, "api_key": old_by_id.get(p.get("id"), "")}
        result.append(p)
    return result


class SettingsUpdate(BaseModel):
    values: dict


class TestNotificationRequest(BaseModel):
    channel: str


@router.get("")
async def get_settings(user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT key, value FROM settings") as cur:
        rows = await cur.fetchall()
    out = {}
    for r in rows:
        if r["key"] in _SECRET_KEYS and user["role"] != "admin":
            continue
        try:
            value = json.loads(r["value"])
        except (ValueError, TypeError):
            value = r["value"]
        if r["key"] in _AI_MASK_KEYS and value:
            value = _MASK
        if r["key"] == "ai_local_providers" and value:
            value = _mask_local_providers(value)
        out[r["key"]] = value
    return out


@router.put("")
async def update_settings(body: SettingsUpdate, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    for key, value in body.values.items():
        if key in _AI_MASK_KEYS and value == _MASK:
            continue  # never overwrite a secret with the display mask
        if key == "ai_local_providers":
            value = await _unmask_local_providers(db, value)
        await db.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now')) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (key, json.dumps(value)),
        )
    await db.commit()
    return {"status": "ok"}


@router.post("/test-notification")
async def test_notification(
    body: TestNotificationRequest,
    _: AdminUser,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Send a test notification on the specified channel using saved settings.

    Goes through app/notifications.py — the same senders a real firing alert
    uses. That is deliberate: this endpoint used to carry its own copy of the
    sending logic, so a green test said nothing about whether actual alerts
    would ever be delivered (and for a long time they weren't — nothing was
    wired to dispatch them). A passing test here now genuinely exercises the
    delivery path.
    """
    channel = body.channel
    valid = {"slack", "email", "pagerduty", "webhook", "tracecat"}
    if channel not in valid:
        raise HTTPException(status_code=400, detail=f"Unknown channel: {channel}. Valid: {sorted(valid)}")

    status, detail = await notifications.send_to_channel(
        db,
        channel,
        rule_name="pktCert Test",
        message="pktCert test notification — your configuration is working correctly.",
        severity="info",
        details={"test": True},
    )
    return {"status": status, "detail": detail}
