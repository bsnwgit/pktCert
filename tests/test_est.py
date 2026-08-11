#!/usr/bin/env python3
"""
EST (RFC 7030) enrolment tests.

Standalone script — run from the repo root:
    python3 tests/test_est.py

Issuance previously required a human at a keyboard: open the UI, fill a form,
copy the certificate and key onto the box. That doesn't scale past a handful
of servers and doesn't work at all for network gear — which is most of what
this suite manages. EST lets a device enrol itself.

The details matter more than usual here, because EST clients are embedded and
unforgiving: they expect PKCS#7 certs-only, base64-encoded, with
Content-Transfer-Encoding set. Returning a bare PEM certificate is the classic
way to make one fail with no useful diagnostic at all.
"""
from __future__ import annotations

import asyncio
import base64
import os
import sys
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

REPO_ROOT = Path(__file__).resolve().parents[1]

TMP = Path(tempfile.mkdtemp(prefix="pktcert-est-"))
(TMP / "config.yaml").write_text(
    f"install_dir: {TMP}\n"
    f"secret_key: {'a' * 64}\n"
    f"credential_key: {Fernet.generate_key().decode()}\n"
    f"suite_token: ''\n"
)
os.environ["PKTCERT_CONFIG"] = str(TMP / "config.yaml")
os.environ["PKTCERT_INSTALL_DIR"] = str(TMP)
sys.path.insert(0, str(REPO_ROOT))

import json                                                       # noqa: E402
import sqlite3                                                    # noqa: E402
import aiosqlite                                                  # noqa: E402
from cryptography import x509                                     # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization   # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec           # noqa: E402
from cryptography.hazmat.primitives.serialization import pkcs7     # noqa: E402
from cryptography.x509.oid import NameOID                          # noqa: E402
from fastapi.testclient import TestClient                          # noqa: E402

from app.database import init_db                                   # noqa: E402
from app.dependencies import get_current_user                      # noqa: E402
from app.main import app                                           # noqa: E402

DB = TMP / "pktcert.db"
FAILURES: list[str] = []


def check(label: str, passed: bool, detail: str = "") -> None:
    print(f"{'PASS' if passed else 'FAIL'}  {label}" + (f"  — {detail}" if detail and not passed else ""))
    if not passed:
        FAILURES.append(label)


def basic(username: str, password: str) -> dict:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def device_csr(common_name: str, sans: list[str] | None = None) -> bytes:
    """A CSR as a device would produce it — the key never leaves the device,
    which here means it never leaves this function."""
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def b64(der: bytes) -> str:
    return base64.b64encode(der).decode()


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
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 1, "username": "admin", "email": "admin@test", "role": "admin", "is_active": True,
    }
    client = TestClient(app)

    root = client.post("/api/cas/generate", json={
        "name": "EST Root", "ca_type": "root",
        "key_algorithm": "ec", "key_size": 2048, "validity_days": 3650,
    }).json()
    inter = client.post("/api/cas/generate", json={
        "name": "EST Intermediate", "ca_type": "intermediate", "parent_ca_id": root["id"],
        "key_algorithm": "ec", "key_size": 2048, "validity_days": 1825,
    }).json()
    tpl_id = client.post("/api/templates", json={
        "name": "Device", "key_algorithm": "ec", "key_size": 2048, "validity_days": 365,
        "key_usage": ["digital_signature"], "extended_key_usage": ["client_auth"],
    }).json()["id"]

    print("\n── transport ──")
    r = client.post("/.well-known/est/simpleenroll", headers=basic("dev", "x"), content=b64(device_csr("a.example.com")))
    check("plain HTTP enrolment is refused by default", r.status_code == 421, f"HTTP {r.status_code}")
    check("and explains that EST needs TLS", "TLS" in r.text, r.text[:160])

    r = client.post("/.well-known/est/simpleenroll", headers={
        **basic("dev", "x"), "X-Forwarded-Proto": "https",
    }, content=b64(device_csr("a.example.com")))
    check("TLS terminated at a proxy is accepted", r.status_code != 421, f"HTTP {r.status_code}")

    # Everything below runs on an isolated lab network, the case the setting exists for.
    await set_setting("est_allow_insecure_http", True)

    print("\n── cacerts (unauthenticated by design) ──")
    r = client.get("/.well-known/est/cacerts")
    check("cacerts responds without credentials", r.status_code == 200, f"HTTP {r.status_code}")
    check("with the PKCS#7 certs-only content type",
          "application/pkcs7-mime" in r.headers.get("content-type", ""), r.headers.get("content-type", ""))
    check("and base64 transfer encoding",
          r.headers.get("content-transfer-encoding") == "base64", str(r.headers.get("content-transfer-encoding")))
    certs = pkcs7.load_der_pkcs7_certificates(base64.b64decode(r.text))
    check("it really is a parseable PKCS#7 bundle", len(certs) >= 1, str(len(certs)))
    subjects = [c.subject.rfc4514_string() for c in certs]
    check("and carries the whole chain, not just the leaf CA",
          any("EST Root" in s for s in subjects) and any("EST Intermediate" in s for s in subjects), str(subjects))

    print("\n── enrolment profile ──")
    r = client.post("/api/enrollment-profiles", json={
        "name": "Switch fleet", "protocol": "est", "ca_id": inter["id"], "template_id": tpl_id,
        "username": "switches", "allowed_name_suffix": ".corp.example.com", "max_certs": 2,
    })
    check("a profile can be created", r.status_code == 201, r.text[:200])
    secret = r.json()["secret"]
    check("the secret is returned once, at creation", bool(secret))
    check("but never listed afterwards", "secret" not in client.get("/api/enrollment-profiles").json()[0])
    stored = sqlite3.connect(str(DB)).execute("SELECT secret_enc FROM enrollment_profiles").fetchone()[0]
    check("and is encrypted at rest", stored != secret and len(stored) > len(secret), stored[:20])

    r = client.post("/api/enrollment-profiles", json={
        "name": "No username", "protocol": "est", "ca_id": inter["id"], "template_id": tpl_id,
    })
    check("an EST profile without a username is refused", r.status_code == 400, f"HTTP {r.status_code}")

    print("\n── enrolling ──")
    r = client.post("/.well-known/est/simpleenroll", headers=basic("switches", "wrong"),
                    content=b64(device_csr("sw1.corp.example.com")))
    check("a wrong secret is rejected", r.status_code == 401, f"HTTP {r.status_code}")
    r = client.post("/.well-known/est/simpleenroll", content=b64(device_csr("sw1.corp.example.com")))
    check("no credentials at all is rejected", r.status_code == 401, f"HTTP {r.status_code}")
    check("with a WWW-Authenticate challenge", "Basic" in r.headers.get("www-authenticate", ""),
          r.headers.get("www-authenticate", ""))

    r = client.post("/.well-known/est/simpleenroll", headers=basic("switches", secret),
                    content=b64(device_csr("sw1.corp.example.com")))
    check("a valid enrolment succeeds", r.status_code == 200, f"HTTP {r.status_code}: {r.text[:160]}")
    issued = pkcs7.load_der_pkcs7_certificates(base64.b64decode(r.text))
    check("the response is PKCS#7 with one certificate", len(issued) == 1, str(len(issued)))
    cert = issued[0]
    check("issued to the requested name",
          cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "sw1.corp.example.com")
    check("issued by the profile's CA", "EST Intermediate" in cert.issuer.rfc4514_string(),
          cert.issuer.rfc4514_string())
    cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    check("it carries a CRL distribution point like any other certificate", cdp is not None)
    aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
    check("and an AIA pointer", aia is not None)

    row = sqlite3.connect(str(DB)).execute(
        "SELECT source, private_key_enc FROM certificates WHERE common_name = 'sw1.corp.example.com'").fetchone()
    check("it lands in the inventory as an enrolled certificate", row[0] == "enrolled", str(row[0]))
    check("pktCert holds no private key for it — the device kept it", not row[1], repr(row[1])[:30])

    print("\n── profile policy ──")
    r = client.post("/.well-known/est/simpleenroll", headers=basic("switches", secret),
                    content=b64(device_csr("payroll.finance.example.com")))
    check("a name outside the profile's suffix is refused", r.status_code == 403, f"HTTP {r.status_code}")
    check("and names the restriction", "corp.example.com" in r.text, r.text[:200])

    r = client.post("/.well-known/est/simpleenroll", headers=basic("switches", secret),
                    content=b64(device_csr("sw2.corp.example.com", sans=["sw2.corp.example.com"])))
    check("a second valid enrolment succeeds", r.status_code == 200, f"HTTP {r.status_code}")
    r = client.post("/.well-known/est/simpleenroll", headers=basic("switches", secret),
                    content=b64(device_csr("sw3.corp.example.com")))
    check("the profile's certificate cap is enforced", r.status_code == 403, f"HTTP {r.status_code}")
    check("and says so", "limit" in r.text.lower(), r.text[:200])

    print("\n── audit and lifecycle ──")
    log = client.get("/api/enrollment-profiles/log").json()
    check("every attempt is logged", len(log) >= 5, str(len(log)))
    outcomes = {e["outcome"] for e in log}
    check("including the refusals", "denied" in outcomes and "issued" in outcomes, str(outcomes))
    check("with the subject recorded",
          any(e["subject"] and "sw1.corp.example.com" in e["subject"] for e in log))

    profile_id = client.get("/api/enrollment-profiles").json()[0]["id"]
    r = client.post(f"/api/enrollment-profiles/{profile_id}/rotate-secret")
    check("the secret can be rotated", r.status_code == 200 and r.json()["secret"] != secret)
    r = client.post("/.well-known/est/simpleenroll", headers=basic("switches", secret),
                    content=b64(device_csr("sw9.corp.example.com")))
    check("the old secret stops working immediately", r.status_code == 401, f"HTTP {r.status_code}")

    client.patch(f"/api/enrollment-profiles/{profile_id}", json={
        "name": "Switch fleet", "protocol": "est", "ca_id": inter["id"], "template_id": tpl_id,
        "username": "switches", "enabled": False, "max_certs": 100,
    })
    new_secret = client.post(f"/api/enrollment-profiles/{profile_id}/rotate-secret").json()["secret"]
    r = client.post("/.well-known/est/simpleenroll", headers=basic("switches", new_secret),
                    content=b64(device_csr("sw4.corp.example.com")))
    check("a disabled profile cannot enrol", r.status_code == 401, f"HTTP {r.status_code}")

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
