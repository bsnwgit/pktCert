#!/usr/bin/env python3
"""
Certificate Transparency validation tests (crt.sh).

Standalone script — run from the repo root:
    python3 tests/test_ct_check.py

crt.sh itself is never contacted: `ct_search._crtsh_query` is replaced with a
canned answer, so these test our reading of the log, not the service.

Covers:
  * a certificate present in the log is reported as logged, matched by serial
    and issuer — however the serial is zero-padded and however the issuer's
    fields are ordered
  * an absent certificate is "not logged" only when crt.sh actually answered
  * an unreachable crt.sh is "unavailable" / "inconclusive", never "not logged"
  * unexpired certificates from another issuer, and not in the inventory, are
    flagged; expired ones, inventory ones and same-issuer ones are not
  * names that cannot be public are never sent to crt.sh
  * the endpoint needs analyst or higher, 404s an unknown certificate, and
    leaves an audit event
  * a certificate that is not in the inventory can be checked from a PEM
    (analyst) or fetched from a host (admin only), is never stored, and bad
    input is refused
  * every check is recorded in a history all roles can read, with who ran it,
    and the history never holds a PEM
"""
from __future__ import annotations

import asyncio
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

REPO_ROOT = Path(__file__).resolve().parents[1]

TMP = Path(tempfile.mkdtemp(prefix="pktcert-ctcheck-"))
(TMP / "config.yaml").write_text(
    f"install_dir: {TMP}\n"
    f"secret_key: {'a' * 64}\n"
    f"credential_key: {Fernet.generate_key().decode()}\n"
    f"suite_token: ''\n"
)
os.environ["PKTCERT_CONFIG"] = str(TMP / "config.yaml")
os.environ["PKTCERT_INSTALL_DIR"] = str(TMP)
sys.path.insert(0, str(REPO_ROOT))

from datetime import datetime, timedelta, timezone  # noqa: E402

from cryptography import x509                       # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID           # noqa: E402
from fastapi.testclient import TestClient           # noqa: E402

from app.cert import ct_search, x509_utils          # noqa: E402
from app.database import init_db                    # noqa: E402
from app.dependencies import get_current_user       # noqa: E402
from app.main import app                            # noqa: E402

DB = TMP / "pktcert.db"
FAILURES: list[str] = []


def check(label: str, passed: bool, detail: str = "") -> None:
    print(f"{'PASS' if passed else 'FAIL'}  {label}" + (f"  — {detail}" if detail and not passed else ""))
    if not passed:
        FAILURES.append(label)


def row(id_, serial, issuer, names, not_after="2099-01-01T00:00:00"):
    return {
        "id": id_, "serial_number": serial, "issuer_name": issuer, "issuer_ca_id": hash(issuer) % 1000,
        "common_name": names[0], "name_value": "\n".join(names),
        "not_before": "2026-01-01T00:00:00", "not_after": not_after,
        "entry_timestamp": "2026-01-02T03:04:05.678",
    }


# Our rows hold RFC 4514; crt.sh holds the same issuer in the opposite order.
OUR_ISSUER = "CN=Example Issuing CA,O=Example Org,C=US"
CT_ISSUER = "C=US, O=Example Org, CN=Example Issuing CA"
OTHER_ISSUER = "C=US, O=Somebody Else, CN=Rogue CA"

CERT = {
    "common_name": "www.example.com", "san": ["www.example.com", "api.example.com"],
    "serial_number": "abc123", "issuer": OUR_ISSUER, "fingerprint_sha256": "ab" * 32,
}

SENT: list[str] = []
ANSWER = {"rows": [], "fail": set()}


async def fake_query(name: str):
    SENT.append(name)
    if name in ANSWER["fail"]:
        raise ct_search.CrtshUnavailable("crt.sh returned HTTP 502")
    return ANSWER["rows"]


ct_search._crtsh_query = fake_query


def run(cert=CERT, known=frozenset()):
    SENT.clear()
    return asyncio.run(ct_search.validate_against_crtsh(cert, set(known)))


def main() -> int:
    print("\n── logged ──")
    ANSWER.update(rows=[row(1, "0abc123", CT_ISSUER, ["www.example.com"])], fail=set())
    r = run()
    check("matched by serial and issuer despite padding and field order", r["verdict"] == "logged", r["verdict"])
    check("log entry carried through", r["logged_entry"]["crtsh_id"] == 1)
    check("logged is True", r["logged"] is True)
    check("link to crt.sh by fingerprint", r["crtsh_url"].endswith("ab" * 32))

    print("\n── not logged ──")
    ANSWER.update(rows=[], fail=set())
    r = run()
    check("empty answer from crt.sh is 'not_logged'", r["verdict"] == "not_logged", r["verdict"])
    check("logged is False", r["logged"] is False)

    ANSWER.update(rows=[row(2, "abc123", OTHER_ISSUER, ["www.example.com"])], fail=set())
    r = run()
    check("same serial from a different issuer is not our certificate", r["logged"] is False, str(r["logged"]))

    print("\n── crt.sh unavailable ──")
    ANSWER.update(rows=[], fail={"www.example.com", "api.example.com"})
    r = run()
    check("every name failing is 'unavailable'", r["verdict"] == "unavailable", r["verdict"])
    check("logged is None, not False", r["logged"] is None, str(r["logged"]))
    check("the failures are reported", len(r["errors"]) == 2, str(r["errors"]))

    ANSWER.update(rows=[], fail={"api.example.com"})
    r = run()
    check("one name failing and nothing found is 'inconclusive'", r["verdict"] == "inconclusive", r["verdict"])
    check("…and still not claimed as not-logged", r["logged"] is None, str(r["logged"]))

    ANSWER.update(rows=[row(1, "abc123", CT_ISSUER, ["www.example.com"])], fail={"api.example.com"})
    r = run()
    check("found on one name is 'logged' even if another failed", r["verdict"] == "logged", r["verdict"])

    print("\n── audit for unexpected certificates ──")
    ANSWER.update(rows=[
        row(1, "abc123", CT_ISSUER, ["www.example.com"]),
        row(10, "ffff01", OTHER_ISSUER, ["www.example.com"]),                              # unexpected
        row(11, "ffff02", OTHER_ISSUER, ["www.example.com"], not_after="2001-01-01T00:00:00"),  # expired
        row(12, "ffff03", OTHER_ISSUER, ["www.example.com"]),                              # in inventory
        row(13, "ffff04", CT_ISSUER, ["www.example.com"]),                                 # same issuer
    ], fail=set())
    r = run(known={"ffff03"})
    check("verdict is unexpected_found", r["verdict"] == "unexpected_found", r["verdict"])
    ids = sorted(e["crtsh_id"] for e in r["unexpected"])
    check("only the unexpired, unknown, foreign-issuer certificate is flagged", ids == [10], str(ids))
    check("same-issuer extra is listed separately", [e["crtsh_id"] for e in r["same_issuer"]] == [13])
    check("flagging does not hide that ours is logged", r["logged"] is True)

    ANSWER.update(rows=[row(10, "ffff01", OTHER_ISSUER, ["www.example.com"])] * 2, fail=set())
    r = run()
    check("duplicate log entries are listed once", len(r["unexpected"]) == 1, str(len(r["unexpected"])))

    print("\n── private names are never sent ──")
    ANSWER.update(rows=[], fail=set())
    r = run({**CERT, "common_name": "host.example.test",
             "san": ["host.example.test", "10.0.0.3", "printer", "router.example", "ok.example.com", "*.wild.example.com"]})
    check("only public names were sent", sorted(SENT) == ["*.wild.example.com", "ok.example.com"], str(SENT))
    check("the rest are reported as skipped",
          sorted(r["names_skipped"]) == ["10.0.0.3", "host.example.test", "printer", "router.example"], str(r["names_skipped"]))

    r = run({**CERT, "common_name": "host.example.test", "san": ["10.0.0.3"]})
    check("nothing public means nothing sent", SENT == [] and r["verdict"] == "not_applicable", f"{SENT} {r['verdict']}")

    r = run({**CERT, "san": [f"h{i}.example.com" for i in range(15)]})
    check("at most 10 names are searched", len(SENT) == 10, str(len(SENT)))
    check("the overflow is reported", len(r["names_over_limit"]) == 6, str(r["names_over_limit"]))

    print("\n── endpoint ──")
    asyncio.run(init_db())
    conn = sqlite3.connect(str(DB))
    conn.execute(
        "INSERT INTO certificates (common_name, san_json, issuer, subject, serial_number, fingerprint_sha256, "
        "not_before, not_after, status, source) VALUES "
        "('www.example.com', '[\"www.example.com\"]', ?, 'CN=www.example.com', 'abc123', ?, "
        "'2026-01-01T00:00:00', '2099-01-01T00:00:00', 'valid', 'external')",
        (OUR_ISSUER, "ab" * 32),
    )
    conn.commit()
    cert_id = conn.execute("SELECT id FROM certificates").fetchone()[0]
    conn.close()

    role = {"v": "viewer"}
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 1, "username": "someone", "email": "x@test", "role": role["v"], "is_active": True,
    }
    client = TestClient(app)
    ANSWER.update(rows=[row(1, "abc123", CT_ISSUER, ["www.example.com"])], fail=set())

    check("a viewer is refused", client.post(f"/api/certificates/{cert_id}/ct-check").status_code == 403)
    role["v"] = "analyst"
    r = client.post(f"/api/certificates/{cert_id}/ct-check")
    check("an analyst may run it", r.status_code == 200, r.text[:200])
    check("endpoint reports logged", r.json().get("verdict") == "logged", r.text[:200])
    check("unknown certificate is 404", client.post("/api/certificates/99999/ct-check").status_code == 404)

    conn = sqlite3.connect(str(DB))
    ev = conn.execute("SELECT message FROM cert_events WHERE event_type = 'ct_checked'").fetchall()
    conn.close()
    check("the check is audit-logged with who ran it", len(ev) == 1 and "someone" in ev[0][0], str(ev))


    print("\n── a certificate that is not in the inventory ──")
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "adhoc.example.com")])
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Any Issuer")])
    adhoc = (
        x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name)
        .public_key(key.public_key()).serial_number(0x1234ABCD)
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("adhoc.example.com")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    adhoc_pem = adhoc.public_bytes(serialization.Encoding.PEM).decode()
    ANSWER.update(rows=[row(7, "1234abcd", "CN=Any Issuer", ["adhoc.example.com"])], fail=set())

    def count(sql):
        c = sqlite3.connect(str(DB))
        try:
            return c.execute(sql).fetchone()[0]
        finally:
            c.close()

    certs_before = count("SELECT COUNT(*) FROM certificates")
    events_before = count("SELECT COUNT(*) FROM cert_events")

    role["v"] = "viewer"
    check("a viewer is refused", client.post("/api/certificates/ct-check", json={"pem": adhoc_pem}).status_code == 403)
    role["v"] = "analyst"
    r = client.post("/api/certificates/ct-check", json={"pem": adhoc_pem})
    check("an analyst may check a pasted PEM", r.status_code == 200, r.text[:200])
    body = r.json()
    check("it is found in the log", body.get("verdict") == "logged", str(body.get("verdict")))
    check("it says what it checked", body["certificate"]["common_name"] == "adhoc.example.com"
          and body["certificate"]["fetched_from"] is None, str(body.get("certificate")))
    check("it is reported as not in the inventory", body["in_inventory_id"] is None, str(body["in_inventory_id"]))
    check("nothing is stored", count("SELECT COUNT(*) FROM certificates") == certs_before)
    check("no audit event for a certificate with no record", count("SELECT COUNT(*) FROM cert_events") == events_before)

    check("garbage is not a certificate", client.post("/api/certificates/ct-check", json={"pem": "nope"}).status_code == 400)
    check("neither input is refused", client.post("/api/certificates/ct-check", json={}).status_code == 400)
    check("both inputs are refused",
          client.post("/api/certificates/ct-check", json={"pem": adhoc_pem, "host": "x.example.com"}).status_code == 400)

    check("an analyst cannot make the server fetch from a host",
          client.post("/api/certificates/ct-check", json={"host": "adhoc.example.com"}).status_code == 403)

    fetched: list[tuple] = []

    def fake_fetch(host, port, timeout=5.0):
        fetched.append((host, port))
        return adhoc_pem, adhoc_pem

    real_fetch = x509_utils.fetch_cert_chain
    x509_utils.fetch_cert_chain = fake_fetch
    try:
        role["v"] = "admin"
        r = client.post("/api/certificates/ct-check", json={"host": "adhoc.example.com", "port": 8443})
        check("an admin may fetch from a host", r.status_code == 200, r.text[:200])
        check("the host and port were used", fetched == [("adhoc.example.com", 8443)], str(fetched))
        check("the source is reported", r.json()["certificate"]["fetched_from"] == "adhoc.example.com:8443")
        check("a host with odd characters is refused before any connection",
              client.post("/api/certificates/ct-check", json={"host": "a b;c"}).status_code == 400
              and len(fetched) == 1, str(fetched))
        check("an out-of-range port is refused",
              client.post("/api/certificates/ct-check", json={"host": "adhoc.example.com", "port": 70000}).status_code == 422)

        def broken_fetch(host, port, timeout=5.0):
            raise OSError("connection refused")
        x509_utils.fetch_cert_chain = broken_fetch
        r = client.post("/api/certificates/ct-check", json={"host": "adhoc.example.com"})
        check("a host that cannot be reached is a 502, not a crash", r.status_code == 502, f"HTTP {r.status_code}")
    finally:
        x509_utils.fetch_cert_chain = real_fetch

    # The same certificate once it IS in the inventory gets its audit trail.
    conn = sqlite3.connect(str(DB))
    conn.execute(
        "INSERT INTO certificates (common_name, san_json, issuer, subject, serial_number, fingerprint_sha256, "
        "not_before, not_after, status, source) VALUES ('adhoc.example.com', '[]', 'CN=Any Issuer', "
        "'CN=adhoc.example.com', ?, ?, '2026-01-01T00:00:00', '2099-01-01T00:00:00', 'valid', 'external')",
        (format(0x1234ABCD, "x"), "cd" * 32),
    )
    conn.commit()
    conn.close()
    role["v"] = "analyst"
    r = client.post("/api/certificates/ct-check", json={"pem": adhoc_pem}).json()
    check("a certificate already in the inventory is recognised", bool(r["in_inventory_id"]), str(r["in_inventory_id"]))
    check("and its audit trail gets the event", count("SELECT COUNT(*) FROM cert_events") == events_before + 1)


    print("\n── history ──")
    role["v"] = "viewer"
    rows_v = client.get("/api/ct-checks")
    check("a viewer can read the history", rows_v.status_code == 200, f"HTTP {rows_v.status_code}")
    hist = rows_v.json()
    by_source = {h["source"] for h in hist}
    check("inventory, pasted and fetched checks are all recorded", by_source == {"inventory", "pem", "host"}, str(by_source))
    check("the failed fetch and the refused input left no row",
          len(hist) == 4, f"{len(hist)} rows: {[h['source'] for h in hist]}")
    check("newest first", hist[0]["id"] > hist[-1]["id"])
    check("who ran each check is recorded", {h["checked_by"] for h in hist} == {"someone"}, str({h["checked_by"] for h in hist}))
    check("a host check records where it was fetched from",
          any(h["fetched_from"] == "adhoc.example.com:8443" for h in hist), str([h["fetched_from"] for h in hist]))
    check("an inventory check links its certificate", any(h["certificate_id"] == cert_id for h in hist if h["source"] == "inventory"))
    check("the verdict is stored", all(h["verdict"] in ("logged", "unexpected_found") for h in hist), str([h["verdict"] for h in hist]))

    one = client.get(f"/api/ct-checks/{hist[0]['id']}")
    check("a viewer can open one check", one.status_code == 200 and "result" in one.json(), one.text[:150])
    check("an unknown check is 404", client.get("/api/ct-checks/99999").status_code == 404)
    check("an unknown verdict filter is refused", client.get("/api/ct-checks?verdict=bogus").status_code == 400)
    check("filtering by verdict works",
          all(h["verdict"] == "logged" for h in client.get("/api/ct-checks?verdict=logged").json()))
    check("searching by who ran it works",
          len(client.get("/api/ct-checks?search=someone").json()) == 4
          and client.get("/api/ct-checks?search=nobody-here").json() == [])

    conn = sqlite3.connect(str(DB))
    dump = " ".join(str(v) for r in conn.execute("SELECT * FROM ct_checks").fetchall() for v in r)
    conn.close()
    check("no PEM is ever stored in the history", "BEGIN CERTIFICATE" not in dump)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
