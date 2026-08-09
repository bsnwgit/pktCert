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
    """Send a test notification on the specified channel using saved settings."""
    channel = body.channel
    valid = {"slack", "email", "pagerduty", "webhook", "tracecat"}
    if channel not in valid:
        raise HTTPException(status_code=400, detail=f"Unknown channel: {channel}. Valid: {sorted(valid)}")

    async def _get(key: str):
        async with db.execute("SELECT value FROM settings WHERE key=?", (key,)) as cur:
            row = await cur.fetchone()
        return json.loads(row[0]) if row else None

    TEST_RULE = "pktCert Test"
    TEST_MSG  = "pktCert test notification — your configuration is working correctly."
    TEST_SEV  = "info"

    try:
        if channel == "slack":
            enabled = await _get("notify_slack_enabled")
            if not enabled:
                return {"status": "skipped", "detail": "Slack is not enabled"}
            url = await _get("notify_slack_webhook_url") or ""
            if not url:
                return {"status": "skipped", "detail": "No webhook URL configured"}
            import httpx
            payload = {"text": f":white_circle: *pktCert Test — {TEST_RULE}*\n{TEST_MSG}"}
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, json=payload, timeout=10)
            if resp.status_code == 200:
                return {"status": "sent", "detail": "Slack message delivered"}
            return {"status": "failed", "detail": f"Slack returned HTTP {resp.status_code}: {resp.text[:200]}"}

        elif channel == "email":
            enabled = await _get("notify_email_enabled")
            if not enabled:
                return {"status": "skipped", "detail": "Email is not enabled"}
            host      = await _get("notify_email_smtp_host")   or ""
            port      = await _get("notify_email_smtp_port")   or 587
            tls       = await _get("notify_email_smtp_tls")
            use_tls   = tls if tls is not None else True
            username  = await _get("notify_email_username")    or ""
            password  = await _get("notify_email_password")    or ""
            from_addr = await _get("notify_email_from")        or "pktcert@localhost"
            to_addrs  = await _get("notify_email_default_to")  or []
            if not host or not to_addrs:
                return {"status": "skipped", "detail": "SMTP host or recipient list not configured"}
            import aiosmtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[pktCert Test] {TEST_RULE}"
            msg["From"]    = from_addr
            msg["To"]      = ", ".join(to_addrs)
            msg.attach(MIMEText(f"pktCert Test Notification\n\n{TEST_MSG}", "plain"))
            await aiosmtplib.send(
                msg,
                hostname=host, port=int(port), use_tls=bool(use_tls),
                username=username or None, password=password or None,
            )
            return {"status": "sent", "detail": f"Email sent to {', '.join(to_addrs)}"}

        elif channel == "pagerduty":
            enabled = await _get("notify_pagerduty_enabled")
            if not enabled:
                return {"status": "skipped", "detail": "PagerDuty is not enabled"}
            key = await _get("notify_pagerduty_integration_key") or ""
            if not key:
                return {"status": "skipped", "detail": "No integration key configured"}
            import httpx
            payload = {
                "routing_key": key,
                "event_action": "trigger",
                "payload": {
                    "summary": f"[pktCert Test] {TEST_RULE}: {TEST_MSG}",
                    "severity": "info",
                    "source": "pktcert",
                },
            }
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    "https://events.pagerduty.com/v2/enqueue", json=payload, timeout=10
                )
            if resp.status_code in (200, 202):
                return {"status": "sent", "detail": "PagerDuty event triggered"}
            return {"status": "failed", "detail": f"PagerDuty returned HTTP {resp.status_code}: {resp.text[:200]}"}

        elif channel == "webhook":
            enabled = await _get("notify_webhook_enabled")
            if not enabled:
                return {"status": "skipped", "detail": "Webhook is not enabled"}
            url      = await _get("notify_webhook_url")              or ""
            method   = await _get("notify_webhook_method")           or "POST"
            template = await _get("notify_webhook_payload_template") or ""
            headers  = await _get("notify_webhook_headers")          or {}
            if not url:
                return {"status": "skipped", "detail": "No webhook URL configured"}
            try:
                from jinja2 import Template
                from datetime import datetime, timezone
                rendered = Template(template).render(
                    alert_name=TEST_RULE, message=TEST_MSG,
                    severity=TEST_SEV, fired_at=datetime.now(tz=timezone.utc).isoformat(),
                )
                body_json = json.loads(rendered)
            except Exception as e:
                return {"status": "failed", "detail": f"Template render error: {e}"}
            import httpx
            async with httpx.AsyncClient() as client:
                resp = await client.request(
                    method.upper(), url, json=body_json, headers=headers, timeout=10
                )
            if resp.status_code < 300:
                return {"status": "sent", "detail": f"Webhook returned HTTP {resp.status_code}"}
            return {"status": "failed", "detail": f"Webhook returned HTTP {resp.status_code}: {resp.text[:200]}"}

        elif channel == "tracecat":
            enabled = await _get("notify_tracecat_enabled")
            if not enabled:
                return {"status": "skipped", "detail": "TraceCat is not enabled"}
            webhook_url = await _get("notify_tracecat_webhook_url") or ""
            api_token   = await _get("notify_tracecat_api_token")   or ""
            if not webhook_url:
                return {"status": "skipped", "detail": "No webhook URL configured"}
            from datetime import datetime, timezone
            payload = {
                "source": "pktcert",
                "event_id": 0,
                "alert_name": TEST_RULE,
                "severity": TEST_SEV,
                "message": TEST_MSG,
                "fired_at": datetime.now(tz=timezone.utc).isoformat(),
                "details": {"test": True},
            }
            headers: dict = {"Content-Type": "application/json"}
            if api_token:
                headers["Authorization"] = f"Bearer {api_token}"
            import httpx
            async with httpx.AsyncClient() as client:
                resp = await client.post(webhook_url, json=payload, headers=headers, timeout=10)
            if resp.status_code < 300:
                return {"status": "sent", "detail": f"TraceCat webhook returned HTTP {resp.status_code}"}
            return {"status": "failed", "detail": f"TraceCat returned HTTP {resp.status_code}: {resp.text[:200]}"}

    except Exception as e:
        return {"status": "failed", "detail": str(e)}
