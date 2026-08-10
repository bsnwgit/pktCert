#!/usr/bin/env python3
"""
Alert notification delivery tests.

Standalone script, same style as test_pki_correctness.py — run from the repo
root with `python3 tests/test_alert_notifications.py`.

Alert rules have always stored a `channels` list and the UI has always let you
pick channels, but nothing dispatched: a firing rule wrote an alert_events row
and stopped. An expiry alert with `email` enabled notified nobody, silently.
These tests stand up a real HTTP receiver and assert an actual request arrives.

Covers:
  * a firing rule delivers to its configured channel, for real
  * the delivery outcome is recorded in notification_log
  * only the tick that OPENS an event notifies — a still-open event must not
    re-notify every evaluation cycle
  * a channel that isn't configured is "skipped", not "failed"
  * Settings' "Send test" goes through the same senders as a real alert
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.fernet import Fernet

REPO_ROOT = Path(__file__).resolve().parents[1]

TMP = Path(tempfile.mkdtemp(prefix="pktcert-notify-"))
(TMP / "config.yaml").write_text(
    f"install_dir: {TMP}\n"
    f"secret_key: {'a' * 64}\n"
    f"credential_key: {Fernet.generate_key().decode()}\n"
    f"suite_token: ''\n"
)
os.environ["PKTCERT_CONFIG"] = str(TMP / "config.yaml")
os.environ["PKTCERT_INSTALL_DIR"] = str(TMP)
sys.path.insert(0, str(REPO_ROOT))

import aiosqlite                                    # noqa: E402
from fastapi.testclient import TestClient           # noqa: E402

from app.cert.alert_engine import AlertEngine       # noqa: E402
from app.database import init_db                    # noqa: E402
from app.dependencies import get_current_user       # noqa: E402
from app.main import app                            # noqa: E402

DB = TMP / "pktcert.db"
FAILURES: list[str] = []
RECEIVED: list[dict] = []


def check(label: str, passed: bool, detail: str = "") -> None:
    print(f"{'PASS' if passed else 'FAIL'}  {label}" + (f"  — {detail}" if detail and not passed else ""))
    if not passed:
        FAILURES.append(label)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            RECEIVED.append(json.loads(body))
        except ValueError:
            RECEIVED.append({"_raw": body.decode(errors="replace")})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass  # keep the test output clean


def start_receiver() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_port}/hook"


async def set_setting(key: str, value) -> None:
    async with aiosqlite.connect(str(DB)) as db:
        await db.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now')) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value)),
        )
        await db.commit()


async def seed_expiring_cert() -> None:
    """A certificate 10 days from expiry — inside the default 30-day window."""
    async with aiosqlite.connect(str(DB)) as db:
        await db.execute(
            """INSERT INTO certificates
               (common_name, san_json, issuer, subject, serial_number, fingerprint_sha256,
                not_after, status, source)
               VALUES ('expiring.example.com', '[]', 'CN=Test', 'CN=expiring.example.com',
                       'abc123', 'fp-expiring-1', datetime('now', '+10 days'), 'valid', 'scan')"""
        )
        await db.commit()


async def tick() -> None:
    """Run exactly one evaluation pass, the same one the background loop runs."""
    engine = AlertEngine()
    engine._db_path = str(DB)
    await engine._refresh_statuses()
    await engine._evaluate()


def notification_rows() -> list[tuple]:
    return sqlite3.connect(str(DB)).execute(
        "SELECT channel, status, error FROM notification_log ORDER BY id"
    ).fetchall()


async def main() -> int:
    await init_db()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 1, "username": "admin", "email": "admin@test", "role": "admin", "is_active": True,
    }
    client = TestClient(app)

    hook_url = start_receiver()
    await set_setting("notify_webhook_enabled", True)
    await set_setting("notify_webhook_url", hook_url)
    await set_setting("notify_webhook_method", "POST")
    await set_setting("notify_webhook_payload_template",
                      '{"alert": "{{ alert_name }}", "severity": "{{ severity }}"}')
    # Slack stays deliberately unconfigured, to prove "skipped" != "failed".

    await seed_expiring_cert()
    r = client.post("/api/alerts/rules", json={
        "name": "Cert expiring soon", "condition_type": "cert_expiring", "threshold": 30,
        "severity": "warning", "enabled": True, "cooldown_min": 0,
        "channels": ["inapp", "webhook", "slack"],
    })
    check("rule accepts the widened channel set", r.status_code == 201, r.text[:160])

    print("\n── delivery ──")
    await tick()
    check("a real HTTP request reached the webhook", len(RECEIVED) == 1, f"{len(RECEIVED)} received")
    if RECEIVED:
        check("payload carries the rule name", RECEIVED[0].get("alert") == "Cert expiring soon", str(RECEIVED[0]))

    rows = notification_rows()
    by_channel = {c: (s, e) for c, s, e in rows}
    check("webhook delivery logged as sent", by_channel.get("webhook", ("", ""))[0] == "sent", str(rows))
    check("in-app logged as sent", by_channel.get("inapp", ("", ""))[0] == "sent", str(rows))
    check("unconfigured Slack is skipped, not failed",
          by_channel.get("slack", ("", ""))[0] == "skipped", str(rows))

    print("\n── no re-notification while the event stays open ──")
    await tick()
    await tick()
    check("still exactly one webhook request after further ticks", len(RECEIVED) == 1, f"{len(RECEIVED)} received")
    check("no duplicate notification_log rows", len(notification_rows()) == len(rows),
          f"{len(rows)} -> {len(notification_rows())}")

    print("\n── Settings 'Send test' uses the same senders ──")
    before = len(RECEIVED)
    r = client.post("/api/settings/test-notification", json={"channel": "webhook"})
    check("test-notification reports sent", r.json().get("status") == "sent", r.text[:160])
    check("test actually hit the receiver", len(RECEIVED) == before + 1, f"{len(RECEIVED)} received")
    r = client.post("/api/settings/test-notification", json={"channel": "slack"})
    check("test on an unconfigured channel reports skipped",
          r.json().get("status") == "skipped", r.text[:160])

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
