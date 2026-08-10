#!/usr/bin/env python3
"""
Certificate renewal tests.

Standalone script — run from the repo root:
    python3 tests/test_renewal.py

Renewal is the bulk of real certificate lifecycle work: a service is issued a
certificate once and renewed every year of its life. pktCert could previously
only issue and revoke, so replacing an expiring certificate meant issuing a
fresh one by hand and remembering yourself that it superseded something.

Covers:
  * renewal reissues the same subject and SANs from the same CA and template
  * the new certificate gets a NEW key and a new serial — never a re-signed
    copy of the old public key
  * the old certificate is superseded, not revoked (the running service must
    keep working until someone installs the replacement)
  * the generations are linked in both directions
  * a superseded certificate stops raising expiry alerts
  * only pktCert-issued certificates can be renewed
  * auto-renewal fires inside its window, and not before
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

TMP = Path(tempfile.mkdtemp(prefix="pktcert-renewal-"))
(TMP / "config.yaml").write_text(
    f"install_dir: {TMP}\n"
    f"secret_key: {'a' * 64}\n"
    f"credential_key: {Fernet.generate_key().decode()}\n"
    f"suite_token: ''\n"
)
os.environ["PKTCERT_CONFIG"] = str(TMP / "config.yaml")
os.environ["PKTCERT_INSTALL_DIR"] = str(TMP)
sys.path.insert(0, str(REPO_ROOT))

from cryptography import x509                       # noqa: E402
from fastapi.testclient import TestClient           # noqa: E402

from app.cert import renewal                        # noqa: E402
from app.cert.alert_engine import AlertEngine       # noqa: E402
from app.database import init_db                    # noqa: E402
from app.dependencies import get_current_user       # noqa: E402
from app.main import app                            # noqa: E402

DB = TMP / "pktcert.db"
FAILURES: list[str] = []


def check(label: str, passed: bool, detail: str = "") -> None:
    print(f"{'PASS' if passed else 'FAIL'}  {label}" + (f"  — {detail}" if detail and not passed else ""))
    if not passed:
        FAILURES.append(label)


def q(sql: str, *params):
    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def stored_cert(cert_id: int) -> x509.Certificate:
    row = q("SELECT cert_pem FROM certificates WHERE id = ?", cert_id)[0]
    return x509.load_pem_x509_certificate(row["cert_pem"].encode())


async def main() -> int:
    await init_db()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 1, "username": "admin", "email": "admin@test", "role": "admin", "is_active": True,
    }
    client = TestClient(app)

    ca_id = client.post("/api/cas/generate", json={
        "name": "Renewal Root CA", "ca_type": "root",
        "key_algorithm": "ec", "key_size": 2048, "validity_days": 3650,
    }).json()["id"]
    tpl_id = client.post("/api/templates", json={
        "name": "EC Short", "key_algorithm": "ec", "key_size": 2048, "validity_days": 90,
        "key_usage": ["digital_signature"], "extended_key_usage": ["server_auth"],
    }).json()["id"]

    print("\n── manual renewal ──")
    original = client.post("/api/certificates/issue", json={
        "common_name": "renew.example.com", "sans": ["alt.renew.example.com"],
        "ca_id": ca_id, "template_id": tpl_id,
    }).json()
    r = client.post(f"/api/certificates/{original['id']}/renew", json={})
    check("renewal succeeds", r.status_code == 201, r.text[:200])
    renewed = r.json()

    old_cert, new_cert = stored_cert(original["id"]), stored_cert(renewed["id"])
    check("subject is preserved", renewed["common_name"] == "renew.example.com", renewed["common_name"])
    check("SANs are preserved", set(renewed["san"]) == set(original["san"]),
          f"{original['san']} -> {renewed['san']}")
    check("same CA and template", renewed["ca_id"] == ca_id and renewed["template_id"] == tpl_id)
    check("serial number is new", new_cert.serial_number != old_cert.serial_number)
    check(
        "public key is new — not a re-signed copy of the old one",
        new_cert.public_key().public_numbers() != old_cert.public_key().public_numbers(),
    )
    check("new private key returned once", bool(renewed.get("private_key_pem")))

    rows = q("SELECT id, status, renewed_from_id, renewed_to_id FROM certificates ORDER BY id")
    old_row = {r["id"]: r for r in rows}[original["id"]]
    new_row = {r["id"]: r for r in rows}[renewed["id"]]
    check("old certificate is superseded", old_row["status"] == "superseded", old_row["status"])
    check("old certificate is NOT revoked", old_row["status"] != "revoked")
    check("forward link recorded", old_row["renewed_to_id"] == renewed["id"])
    check("back link recorded", new_row["renewed_from_id"] == original["id"])

    r = client.post(f"/api/certificates/{original['id']}/renew", json={})
    check("renewing an already-renewed certificate is refused", r.status_code == 400, f"HTTP {r.status_code}")

    print("\n── superseded certificates stop nagging ──")
    # Push both certificates into the expiry window, then evaluate.
    conn = sqlite3.connect(str(DB))
    conn.execute("UPDATE certificates SET not_after = datetime('now', '+5 days')")
    conn.commit()
    conn.close()
    client.post("/api/alerts/rules", json={
        "name": "Expiring", "condition_type": "cert_expiring", "threshold": 30,
        "severity": "warning", "enabled": True, "cooldown_min": 0, "channels": ["inapp"],
    })
    engine = AlertEngine()
    engine._db_path = str(DB)
    await engine._refresh_statuses()
    await engine._evaluate()

    alerted = {r["certificate_id"] for r in q("SELECT certificate_id FROM alert_events WHERE active = 1")}
    check("the replacement raises an expiry alert", renewed["id"] in alerted, str(alerted))
    check("the superseded certificate does not", original["id"] not in alerted, str(alerted))
    check("superseded status survives the status refresh",
          q("SELECT status FROM certificates WHERE id = ?", original["id"])[0]["status"] == "superseded")

    print("\n── what cannot be renewed ──")
    conn = sqlite3.connect(str(DB))
    conn.execute(
        """INSERT INTO certificates (common_name, san_json, issuer, subject, serial_number,
           fingerprint_sha256, not_after, status, source)
           VALUES ('scanned.example.com', '[]', 'CN=Other', 'CN=scanned.example.com', 'ff',
                   'fp-scanned', datetime('now', '+5 days'), 'valid', 'scan')"""
    )
    conn.commit()
    scanned_id = conn.execute("SELECT id FROM certificates WHERE source='scan'").fetchone()[0]
    conn.close()
    r = client.post(f"/api/certificates/{scanned_id}/renew", json={})
    check("a discovered certificate cannot be renewed", r.status_code == 400, f"HTTP {r.status_code}")
    r = client.patch(f"/api/certificates/{scanned_id}/auto-renew", json={"auto_renew": True})
    check("a discovered certificate cannot be auto-renewed", r.status_code == 400, f"HTTP {r.status_code}")

    print("\n── auto-renewal ──")
    target = client.post("/api/certificates/issue", json={
        "common_name": "auto.example.com", "sans": [], "ca_id": ca_id, "template_id": tpl_id,
    }).json()
    r = client.patch(f"/api/certificates/{target['id']}/auto-renew",
                     json={"auto_renew": True, "auto_renew_days": 30})
    check("auto-renew can be enabled", r.status_code == 200 and r.json()["auto_renew"], r.text[:160])

    result = await renewal.run_once(str(DB))
    check("nothing renews outside the window", result["renewed"] == [], str(result))

    conn = sqlite3.connect(str(DB))
    conn.execute("UPDATE certificates SET not_after = datetime('now', '+10 days') WHERE id = ?", (target["id"],))
    conn.commit()
    conn.close()

    result = await renewal.run_once(str(DB))
    check("auto-renewal fires inside the window", len(result["renewed"]) == 1, str(result))
    if result["renewed"]:
        auto_new = result["renewed"][0]
        row = q("SELECT status, renewed_to_id, auto_renew FROM certificates WHERE id = ?", target["id"])[0]
        check("auto-renewed original is superseded", row["status"] == "superseded", row["status"])
        check("auto-renewed original links forward", row["renewed_to_id"] == auto_new)
        new_row = q("SELECT auto_renew, source, ca_id FROM certificates WHERE id = ?", auto_new)[0]
        check("the replacement inherits auto-renew", bool(new_row["auto_renew"]))
        check("the replacement is a normal issued cert", new_row["source"] == "issued" and new_row["ca_id"] == ca_id)
        cdp = [
            str(n.value)
            for dp in stored_cert(auto_new).extensions
                .get_extension_for_class(x509.CRLDistributionPoints).value
            for n in (dp.full_name or [])
        ]
        check("auto-renewed cert still carries a CRL Distribution Point",
              cdp == [f"http://localhost:8763/crl/{ca_id}.crl"], str(cdp))

    result = await renewal.run_once(str(DB))
    check("a renewed certificate is not renewed again", result["renewed"] == [], str(result))

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
