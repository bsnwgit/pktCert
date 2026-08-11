#!/usr/bin/env python3
"""
Separation-of-duties tests.

Standalone script — run from the repo root:
    python3 tests/test_approvals.py

One admin role used to do everything: request a certificate, issue it, revoke
it, and reveal its private key. Regulated environments require those split so
no single person can mint a trusted identity unobserved.

The single most important property here is that the feature is OFF BY DEFAULT
and, when off, changes nothing at all — a small team should not pay a step on
every issuance for a control it doesn't need. The second is that self-approval
is refused: one person clicking twice is not two pairs of eyes, and permitting
it would make the control decorative, which is worse than not having it because
it still looks like a control in an audit.
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

REPO_ROOT = Path(__file__).resolve().parents[1]

TMP = Path(tempfile.mkdtemp(prefix="pktcert-approvals-"))
(TMP / "config.yaml").write_text(
    f"install_dir: {TMP}\n"
    f"secret_key: {'a' * 64}\n"
    f"credential_key: {Fernet.generate_key().decode()}\n"
    f"suite_token: ''\n"
)
os.environ["PKTCERT_CONFIG"] = str(TMP / "config.yaml")
os.environ["PKTCERT_INSTALL_DIR"] = str(TMP)
sys.path.insert(0, str(REPO_ROOT))

import aiosqlite                                  # noqa: E402
from fastapi.testclient import TestClient         # noqa: E402

from app.database import init_db                  # noqa: E402
from app.dependencies import get_current_user     # noqa: E402
from app.main import app                          # noqa: E402

DB = TMP / "pktcert.db"
FAILURES: list[str] = []

ALICE = {"id": 1, "username": "alice", "email": "a@t", "role": "admin", "is_active": True}
BOB = {"id": 2, "username": "bob", "email": "b@t", "role": "admin", "is_active": True}
_current = {"user": ALICE}


def check(label: str, passed: bool, detail: str = "") -> None:
    print(f"{'PASS' if passed else 'FAIL'}  {label}" + (f"  — {detail}" if detail and not passed else ""))
    if not passed:
        FAILURES.append(label)


def as_user(u: dict) -> None:
    _current["user"] = u


def q(sql: str, *params):
    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


async def set_setting(key: str, value) -> None:
    async with aiosqlite.connect(str(DB)) as db:
        await db.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now')) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value)),
        )
        await db.commit()


async def main() -> int:
    await init_db()
    app.dependency_overrides[get_current_user] = lambda: _current["user"]
    client = TestClient(app)

    ca_id = client.post("/api/cas/generate", json={
        "name": "Approval Root", "ca_type": "root",
        "key_algorithm": "ec", "key_size": 2048, "validity_days": 3650,
    }).json()["id"]
    tpl_id = client.post("/api/templates", json={
        "name": "EC", "key_algorithm": "ec", "key_size": 2048, "validity_days": 90,
        "key_usage": ["digital_signature"], "extended_key_usage": ["server_auth"],
    }).json()["id"]

    print("\n── disabled by default: nothing changes ──")
    cfg = client.get("/api/approvals/config").json()
    check("issuance approval defaults to off", cfg["issuance_approval_required"] is False, str(cfg))
    check("revocation approval defaults to off", cfg["revocation_approval_required"] is False, str(cfg))

    r = client.post("/api/certificates/issue", json={
        "common_name": "direct.example.com", "sans": [], "ca_id": ca_id, "template_id": tpl_id,
    })
    check("issuance is immediate when approval is off", r.status_code == 201, f"HTTP {r.status_code}")
    check("and returns the private key as before", bool(r.json().get("private_key_pem")))
    direct_id = r.json()["id"]
    r = client.post(f"/api/certificates/{direct_id}/revoke", json={"reason_code": "superseded"})
    check("revocation is immediate when approval is off", r.status_code == 200, f"HTTP {r.status_code}")
    check("no requests were recorded", len(q("SELECT id FROM cert_requests")) == 0)

    print("\n── enabled: issuance becomes a request ──")
    await set_setting("require_issuance_approval", True)
    await set_setting("require_revocation_approval", True)

    as_user(ALICE)
    r = client.post("/api/certificates/issue", json={
        "common_name": "approved.example.com", "sans": ["alt.approved.example.com"],
        "ca_id": ca_id, "template_id": tpl_id, "justification": "new web frontend",
    })
    check("issuance returns 202 pending, not 201", r.status_code == 202, f"HTTP {r.status_code}")
    check("response says it is pending", r.json().get("pending_approval") is True, r.text[:160])
    req_id = r.json()["request_id"]
    check("no certificate was created yet",
          len(q("SELECT id FROM certificates WHERE common_name = 'approved.example.com'")) == 0)
    check("the justification is recorded",
          q("SELECT justification FROM cert_requests WHERE id = ?", req_id)[0][0] == "new web frontend")

    print("\n── the two-person rule ──")
    r = client.post(f"/api/approvals/{req_id}/approve", json={})
    check("the requester cannot approve their own request", r.status_code == 403, f"HTTP {r.status_code}")
    check("and is told why", "cannot approve" in r.text, r.text[:200])
    check("still no certificate",
          len(q("SELECT id FROM certificates WHERE common_name = 'approved.example.com'")) == 0)
    r = client.post(f"/api/approvals/{req_id}/reject", json={})
    check("the requester cannot reject their own request either", r.status_code == 403, f"HTTP {r.status_code}")

    as_user(BOB)
    r = client.post(f"/api/approvals/{req_id}/approve", json={"note": "checked with the app team"})
    check("a second admin can approve", r.status_code == 200, r.text[:200])
    new_cert_id = r.json().get("certificate_id")
    check("approval is what creates the certificate", bool(new_cert_id), r.text[:200])

    rows = q("SELECT common_name, san_json, ca_id, template_id, source FROM certificates WHERE id = ?", new_cert_id)
    check("the issued certificate matches the request",
          rows and rows[0]["common_name"] == "approved.example.com" and rows[0]["ca_id"] == ca_id,
          str(dict(rows[0])) if rows else "none")
    check("SANs from the request are carried through",
          "alt.approved.example.com" in json.loads(rows[0]["san_json"]), rows[0]["san_json"])
    req = q("SELECT status, decided_by, decision_note, resulting_certificate_id FROM cert_requests WHERE id = ?", req_id)[0]
    check("the request records who approved it", req["decided_by"] == "bob", str(dict(req)))
    check("and what it produced", req["resulting_certificate_id"] == new_cert_id)
    check("the audit trail names both parties",
          any("alice" in e["message"] and "bob" in e["message"]
              for e in q("SELECT message FROM cert_events WHERE certificate_id = ?", new_cert_id)),
          str([dict(e) for e in q("SELECT message FROM cert_events WHERE certificate_id = ?", new_cert_id)]))

    r = client.post(f"/api/approvals/{req_id}/approve", json={})
    check("an already-decided request cannot be approved twice", r.status_code == 400, f"HTTP {r.status_code}")

    print("\n── revocation goes through the same gate ──")
    as_user(ALICE)
    r = client.post(f"/api/certificates/{new_cert_id}/revoke",
                    json={"reason_code": "key_compromise", "reason": "suspect host"})
    check("revocation returns 202 pending", r.status_code == 202, f"HTTP {r.status_code}")
    rev_req = r.json()["request_id"]
    check("the certificate is still valid meanwhile",
          q("SELECT status FROM certificates WHERE id = ?", new_cert_id)[0][0] != "revoked")
    as_user(BOB)
    client.post(f"/api/approvals/{rev_req}/approve", json={})
    row = q("SELECT status, revoked_reason_code FROM certificates WHERE id = ?", new_cert_id)[0]
    check("approval performs the revocation", row["status"] == "revoked", row["status"])
    check("with the requested reason code", row["revoked_reason_code"] == "key_compromise", str(row["revoked_reason_code"]))

    print("\n── rejection and withdrawal ──")
    as_user(ALICE)
    req2 = client.post("/api/certificates/issue", json={
        "common_name": "rejected.example.com", "sans": [], "ca_id": ca_id, "template_id": tpl_id,
    }).json()["request_id"]
    as_user(BOB)
    r = client.post(f"/api/approvals/{req2}/reject", json={"note": "wrong environment"})
    check("a request can be rejected", r.status_code == 200 and r.json()["status"] == "rejected", r.text[:160])
    check("rejection issues nothing",
          len(q("SELECT id FROM certificates WHERE common_name = 'rejected.example.com'")) == 0)

    as_user(ALICE)
    req3 = client.post("/api/certificates/issue", json={
        "common_name": "withdrawn.example.com", "sans": [], "ca_id": ca_id, "template_id": tpl_id,
    }).json()["request_id"]
    r = client.post(f"/api/approvals/{req3}/cancel")
    check("a requester can withdraw their own request",
          r.status_code == 200 and r.json()["status"] == "cancelled", r.text[:160])
    check("withdrawal issues nothing",
          len(q("SELECT id FROM certificates WHERE common_name = 'withdrawn.example.com'")) == 0)

    print("\n── turning it back off ──")
    await set_setting("require_issuance_approval", False)
    await set_setting("require_revocation_approval", False)
    r = client.post("/api/certificates/issue", json={
        "common_name": "afteroff.example.com", "sans": [], "ca_id": ca_id, "template_id": tpl_id,
    })
    check("issuance is immediate again", r.status_code == 201, f"HTTP {r.status_code}")
    check("history of past requests is kept", len(q("SELECT id FROM cert_requests")) >= 4)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
