"""
app/notifications.py
---------------------
Outbound notification channels, in one place.

Both callers share these functions deliberately:

  * app/cert/alert_engine.py — dispatches a firing alert to whichever
    channels its rule has enabled
  * app/api/settings.py — the "Send test" buttons in Settings -> Notifications

That sharing is the point. When the test button ran its own copy of the
sending logic, a green test proved nothing about whether real alerts would
ever go out — and in fact they never did, because nothing was wired to send
them. Now a successful test exercises the exact path a real alert takes.

Every sender returns (status, detail):
  sent    — the channel accepted it
  skipped — the channel is disabled or not configured; not a failure
  failed  — configured, but the send errored or was rejected

Senders never raise. A broken Slack webhook must not stop an alert reaching
the other channels, and must not take down the evaluation loop.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import aiosqlite

log = logging.getLogger("pktcert.notifications")

# Channels a rule may target. inapp is the alert_events row itself, which is
# written before dispatch, so it is always "sent".
CHANNEL_TYPES = {"inapp", "email", "slack", "pagerduty", "webhook", "tracecat"}

_SEVERITY_EMOJI = {"critical": ":red_circle:", "warning": ":large_yellow_circle:"}


async def _setting(db: aiosqlite.Connection, key: str):
    async with db.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cur:
        row = await cur.fetchone()
    if not row:
        return None
    try:
        return json.loads(row[0])
    except (ValueError, TypeError):
        return row[0]


async def _send_slack(db, rule_name: str, message: str, severity: str, **_) -> tuple[str, str]:
    if not await _setting(db, "notify_slack_enabled"):
        return "skipped", "Slack is not enabled"
    url = await _setting(db, "notify_slack_webhook_url") or ""
    if not url:
        return "skipped", "No webhook URL configured"

    import httpx
    emoji = _SEVERITY_EMOJI.get(severity, ":white_circle:")
    payload = {"text": f"{emoji} *pktCert — {rule_name}*\n{message}"}
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, json=payload, timeout=10)
    if resp.status_code == 200:
        return "sent", "Slack message delivered"
    return "failed", f"Slack returned HTTP {resp.status_code}: {resp.text[:200]}"


async def _send_email(db, rule_name: str, message: str, severity: str, **_) -> tuple[str, str]:
    if not await _setting(db, "notify_email_enabled"):
        return "skipped", "Email is not enabled"

    host      = await _setting(db, "notify_email_smtp_host")  or ""
    port      = await _setting(db, "notify_email_smtp_port")  or 587
    tls       = await _setting(db, "notify_email_smtp_tls")
    use_tls   = tls if tls is not None else True
    username  = await _setting(db, "notify_email_username")   or ""
    password  = await _setting(db, "notify_email_password")   or ""
    from_addr = await _setting(db, "notify_email_from")       or "pktcert@localhost"
    to_addrs  = await _setting(db, "notify_email_default_to") or []
    if not host or not to_addrs:
        return "skipped", "SMTP host or recipient list not configured"

    import aiosmtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    sev = severity.upper()
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[pktCert {sev}] {rule_name}"
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg.attach(MIMEText(f"pktCert Alert\n\nRule: {rule_name}\nSeverity: {sev}\n\n{message}", "plain"))

    await aiosmtplib.send(
        msg, hostname=host, port=int(port), use_tls=bool(use_tls),
        username=username or None, password=password or None,
    )
    return "sent", f"Email sent to {', '.join(to_addrs)}"


async def _send_pagerduty(db, rule_name: str, message: str, severity: str, **_) -> tuple[str, str]:
    if not await _setting(db, "notify_pagerduty_enabled"):
        return "skipped", "PagerDuty is not enabled"
    key = await _setting(db, "notify_pagerduty_integration_key") or ""
    if not key:
        return "skipped", "No integration key configured"

    import httpx
    payload = {
        "routing_key": key,
        "event_action": "trigger",
        "payload": {
            "summary": f"[pktCert] {rule_name}: {message}",
            "severity": severity if severity in ("critical", "warning", "info") else "warning",
            "source": "pktcert",
        },
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post("https://events.pagerduty.com/v2/enqueue", json=payload, timeout=10)
    if resp.status_code in (200, 202):
        return "sent", "PagerDuty event triggered"
    return "failed", f"PagerDuty returned HTTP {resp.status_code}: {resp.text[:200]}"


async def _send_webhook(db, rule_name: str, message: str, severity: str, **_) -> tuple[str, str]:
    if not await _setting(db, "notify_webhook_enabled"):
        return "skipped", "Webhook is not enabled"
    url      = await _setting(db, "notify_webhook_url")              or ""
    method   = await _setting(db, "notify_webhook_method")           or "POST"
    template = await _setting(db, "notify_webhook_payload_template") or ""
    headers  = await _setting(db, "notify_webhook_headers")          or {}
    if not url:
        return "skipped", "No webhook URL configured"

    try:
        from jinja2 import Template
        rendered = Template(template).render(
            alert_name=rule_name, message=message, severity=severity,
            fired_at=datetime.now(tz=timezone.utc).isoformat(),
        )
        body = json.loads(rendered)
    except Exception as e:
        return "failed", f"Template render error: {e}"

    import httpx
    async with httpx.AsyncClient() as client:
        resp = await client.request(method.upper(), url, json=body, headers=headers, timeout=10)
    if resp.status_code < 300:
        return "sent", f"Webhook returned HTTP {resp.status_code}"
    return "failed", f"Webhook returned HTTP {resp.status_code}: {resp.text[:200]}"


async def _send_tracecat(
    db, rule_name: str, message: str, severity: str,
    event_id: Optional[int] = None, details: Optional[dict] = None, **_,
) -> tuple[str, str]:
    if not await _setting(db, "notify_tracecat_enabled"):
        return "skipped", "TraceCat is not enabled"
    webhook_url = await _setting(db, "notify_tracecat_webhook_url") or ""
    api_token   = await _setting(db, "notify_tracecat_api_token")   or ""
    if not webhook_url:
        return "skipped", "No webhook URL configured"

    import httpx
    payload = {
        "source": "pktcert",
        "event_id": event_id or 0,
        "alert_name": rule_name,
        "severity": severity,
        "message": message,
        "fired_at": datetime.now(tz=timezone.utc).isoformat(),
        "details": details or {},
    }
    headers = {"Content-Type": "application/json"}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
    async with httpx.AsyncClient() as client:
        resp = await client.post(webhook_url, json=payload, headers=headers, timeout=10)
    if resp.status_code < 300:
        return "sent", f"TraceCat webhook returned HTTP {resp.status_code}"
    return "failed", f"TraceCat returned HTTP {resp.status_code}: {resp.text[:200]}"


_SENDERS = {
    "slack": _send_slack,
    "email": _send_email,
    "pagerduty": _send_pagerduty,
    "webhook": _send_webhook,
    "tracecat": _send_tracecat,
}


async def send_to_channel(
    db: aiosqlite.Connection,
    channel: str,
    rule_name: str,
    message: str,
    severity: str = "warning",
    event_id: Optional[int] = None,
    details: Optional[dict] = None,
) -> tuple[str, str]:
    """Deliver one notification on one channel. Never raises — a channel that
    blows up is reported as ('failed', reason) so the caller can carry on to
    the remaining channels."""
    if channel == "inapp":
        # The alert_events row IS the in-app notification, and it was written
        # before dispatch — nothing to send.
        return "sent", "Recorded in-app"

    sender = _SENDERS.get(channel)
    if sender is None:
        return "skipped", f"Unknown channel: {channel}"

    try:
        return await sender(
            db, rule_name=rule_name, message=message, severity=severity,
            event_id=event_id, details=details,
        )
    except Exception as e:
        log.error(f"Notification send failed on {channel}: {e}")
        return "failed", str(e)
