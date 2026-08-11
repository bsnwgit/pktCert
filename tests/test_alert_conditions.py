#!/usr/bin/env python3
"""
Configurable alert condition tests.

Standalone script — run from the repo root:
    python3 tests/test_alert_conditions.py

Alert rules had exactly one adjustable number between them — `threshold`,
meaning "days" for the two expiry conditions and nothing at all for the other
three. Everything you might actually want to watch for on a certificate had
either no rule or no way to say what the limit was here.

The two properties worth proving, beyond that each condition fires:

  * a parameter genuinely changes the outcome (setting a minimum key size of
    4096 must catch a 2048-bit key that the 2048 default lets past), and
  * scope genuinely narrows (a rule limited to one CA must ignore an identical
    problem on another).

Plus the one that protects existing installs: rules written before parameters
existed keep working, reading their old `threshold` column.
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

TMP = Path(tempfile.mkdtemp(prefix="pktcert-alertcond-"))
(TMP / "config.yaml").write_text(
    f"install_dir: {TMP}\n"
    f"secret_key: {'a' * 64}\n"
    f"credential_key: {Fernet.generate_key().decode()}\n"
    f"suite_token: ''\n"
)
os.environ["PKTCERT_CONFIG"] = str(TMP / "config.yaml")
os.environ["PKTCERT_INSTALL_DIR"] = str(TMP)
sys.path.insert(0, str(REPO_ROOT))

import aiosqlite                                   # noqa: E402
from fastapi.testclient import TestClient          # noqa: E402

from app.cert.alert_engine import AlertEngine      # noqa: E402
from app.database import init_db                   # noqa: E402
from app.dependencies import get_current_user      # noqa: E402
from app.main import app                           # noqa: E402

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


async def seed_cert(**kw) -> int:
    """Insert a certificate directly — these tests are about the conditions,
    not about how a certificate got into the inventory."""
    defaults = dict(
        common_name="host.example.com", san_json="[]", issuer="CN=Some CA", subject="CN=host.example.com",
        serial_number=os.urandom(6).hex(), fingerprint_sha256=os.urandom(16).hex(),
        not_before="datetime('now', '-10 days')", not_after="datetime('now', '+400 days')",
        key_algorithm="rsa", key_size=2048, signature_algorithm="sha256",
        status="valid", source="scan", host=None, ca_id=None,
    )
    defaults.update(kw)
    async with aiosqlite.connect(str(DB)) as db:
        cur = await db.execute(
            f"""INSERT INTO certificates
               (common_name, san_json, issuer, subject, serial_number, fingerprint_sha256,
                not_before, not_after, key_algorithm, key_size, signature_algorithm,
                status, source, host, ca_id)
               VALUES (?, ?, ?, ?, ?, ?, {defaults['not_before']}, {defaults['not_after']},
                       ?, ?, ?, ?, ?, ?, ?) RETURNING id""",
            (defaults["common_name"], defaults["san_json"], defaults["issuer"], defaults["subject"],
             defaults["serial_number"], defaults["fingerprint_sha256"],
             defaults["key_algorithm"], defaults["key_size"], defaults["signature_algorithm"],
             defaults["status"], defaults["source"], defaults["host"], defaults["ca_id"]),
        )
        row = await cur.fetchone()
        await db.commit()
        return row[0]


async def tick() -> None:
    engine = AlertEngine()
    engine._db_path = str(DB)
    await engine._evaluate()


def alerts_for(rule_id: int) -> list[sqlite3.Row]:
    return q("SELECT * FROM alert_events WHERE rule_id = ? AND active = 1", rule_id)


async def main() -> int:
    await init_db()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 1, "username": "admin", "email": "a@t", "role": "admin", "is_active": True,
    }
    client = TestClient(app)

    def make_rule(name, condition, params=None, scope=None, **kw):
        r = client.post("/api/alerts/rules", json={
            "name": name, "condition_type": condition, "severity": "warning",
            "enabled": True, "cooldown_min": 0, "channels": ["inapp"],
            "params": params or {}, "scope": scope or {}, **kw,
        })
        assert r.status_code == 201, r.text
        return r.json()["id"]

    print("\n── the condition registry drives everything ──")
    conditions = client.get("/api/alerts/conditions").json()
    check("conditions are discoverable", len(conditions) >= 15, str(len(conditions)))
    by_key = {c["key"]: c for c in conditions}
    check("each declares its parameters",
          by_key["weak_key"]["params"][0]["key"] == "min_rsa_bits", str(by_key["weak_key"]["params"]))
    check("parameters carry defaults the UI can render",
          by_key["cert_expiring"]["params"][0]["default"] == 30, str(by_key["cert_expiring"]["params"]))
    check("conditions say what they apply to",
          by_key["ca_expiring"]["target"] == "ca" and by_key["weak_key"]["target"] == "certificate")
    r = client.post("/api/alerts/rules", json={
        "name": "Nope", "condition_type": "not_a_condition", "channels": ["inapp"],
    })
    check("an unknown condition is rejected", r.status_code == 400, f"HTTP {r.status_code}")

    print("\n── a parameter actually changes the outcome ──")
    weak_id = await seed_cert(common_name="weak.example.com", key_size=1024)
    ok_id = await seed_cert(common_name="fine.example.com", key_size=2048)

    rule_default = make_rule("Weak keys (default)", "weak_key")
    await tick()
    flagged = {a["certificate_id"] for a in alerts_for(rule_default)}
    check("the default minimum catches a 1024-bit key", weak_id in flagged, str(flagged))
    check("and leaves a 2048-bit key alone", ok_id not in flagged, str(flagged))

    rule_strict = make_rule("Weak keys (strict)", "weak_key", params={"min_rsa_bits": 4096})
    await tick()
    flagged_strict = {a["certificate_id"] for a in alerts_for(rule_strict)}
    check("raising the minimum to 4096 now catches the 2048-bit key too",
          ok_id in flagged_strict and weak_id in flagged_strict, str(flagged_strict))

    print("\n── scope narrows a rule ──")
    ca_id = client.post("/api/cas/generate", json={
        "name": "Scope CA", "ca_type": "root", "key_algorithm": "ec", "key_size": 2048, "validity_days": 3650,
    }).json()["id"]
    mine = await seed_cert(common_name="mine.example.com", key_size=1024, source="issued", ca_id=ca_id)
    theirs = await seed_cert(common_name="theirs.example.com", key_size=1024, source="scan")

    scoped = make_rule("Weak keys on our CA only", "weak_key", scope={"ca_id": ca_id})
    await tick()
    scoped_hits = {a["certificate_id"] for a in alerts_for(scoped)}
    check("the scoped rule catches the in-scope certificate", mine in scoped_hits, str(scoped_hits))
    check("and ignores the identical problem out of scope", theirs not in scoped_hits, str(scoped_hits))

    by_name = make_rule("Weak keys matching a name", "weak_key", scope={"name_like": "theirs"})
    await tick()
    name_hits = {a["certificate_id"] for a in alerts_for(by_name)}
    check("scoping by name works too", theirs in name_hits and mine not in name_hits, str(name_hits))

    print("\n── the new conditions ──")
    sha1 = await seed_cert(common_name="old.example.com", signature_algorithm="sha1")
    rule = make_rule("Weak signatures", "weak_signature")
    await tick()
    check("weak_signature catches SHA-1",
          sha1 in {a["certificate_id"] for a in alerts_for(rule)})

    selfsigned = await seed_cert(common_name="self.example.com",
                                 issuer="CN=self.example.com", subject="CN=self.example.com")
    rule = make_rule("Self-signed", "self_signed")
    await tick()
    check("self_signed catches issuer == subject",
          selfsigned in {a["certificate_id"] for a in alerts_for(rule)})

    rule = make_rule("Validity too long", "long_validity", params={"max_days": 90})
    await tick()
    check("long_validity uses the configured ceiling",
          len(alerts_for(rule)) > 0, "nothing flagged with max_days=90")
    rule_lenient = make_rule("Validity very long", "long_validity", params={"max_days": 3650})
    await tick()
    check("and a generous ceiling flags nothing", len(alerts_for(rule_lenient)) == 0,
          str(len(alerts_for(rule_lenient))))

    wildcard = await seed_cert(common_name="*.example.com")
    rule = make_rule("Wildcards", "wildcard_certificate")
    await tick()
    check("wildcard_certificate catches a wildcard CN",
          wildcard in {a["certificate_id"] for a in alerts_for(rule)})

    rule = make_rule("Foreign issuers", "untrusted_issuer")
    await tick()
    check("untrusted_issuer flags certificates from CAs we don't hold",
          len(alerts_for(rule)) > 0)

    rule = make_rule("New discoveries", "newly_discovered", params={"within_hours": 24})
    await tick()
    check("newly_discovered picks up freshly seen certificates", len(alerts_for(rule)) > 0)

    async with aiosqlite.connect(str(DB)) as db:
        await db.execute(
            """INSERT INTO enrollment_log (protocol, operation, client_ip, outcome)
               VALUES ('est', 'simpleenroll', '10.1.1.9', 'denied')"""
        )
        for _ in range(4):
            await db.execute(
                """INSERT INTO enrollment_log (protocol, operation, client_ip, outcome)
                   VALUES ('est', 'simpleenroll', '10.1.1.9', 'denied')"""
            )
        await db.commit()
    rule = make_rule("Enrolment guessing", "enrollment_failures",
                     params={"count": 5, "window_minutes": 60})
    await tick()
    check("enrollment_failures fires on repeated refusals from one address",
          len(alerts_for(rule)) == 1, str(len(alerts_for(rule))))
    rule_high = make_rule("Enrolment guessing (tolerant)", "enrollment_failures",
                          params={"count": 50, "window_minutes": 60})
    await tick()
    check("and a higher threshold stays quiet", len(alerts_for(rule_high)) == 0)

    print("\n── existing rules keep working ──")
    # A rule as it would have been written before parameters existed: the days
    # value in the old `threshold` column and nothing in params.
    legacy = make_rule("Legacy expiry rule", "cert_expiring", threshold=500)
    async with aiosqlite.connect(str(DB)) as db:
        await db.execute("UPDATE alert_rules SET params_json = '{}' WHERE id = ?", (legacy,))
        await db.commit()
    await tick()
    check("a pre-parameters rule still reads its threshold as days",
          len(alerts_for(legacy)) > 0, "legacy rule matched nothing")

    print("\n── resolution ──")
    async with aiosqlite.connect(str(DB)) as db:
        await db.execute("UPDATE certificates SET key_size = 4096 WHERE id = ?", (weak_id,))
        await db.commit()
    await tick()
    check("fixing the underlying problem auto-resolves the alert",
          weak_id not in {a["certificate_id"] for a in alerts_for(rule_default)})
    check("and it is recorded as resolved, not deleted",
          len(q("SELECT id FROM alert_events WHERE certificate_id = ? AND resolved = 1", weak_id)) > 0)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
