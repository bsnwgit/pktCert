#!/usr/bin/env python3
"""
PKI correctness regression tests.

Deliberately a standalone script rather than a pytest suite: pktCert has no
test dependency today, and these checks need nothing beyond what
requirements.txt already installs. Run it from the repo root:

    python3 tests/test_pki_correctness.py

It builds a throwaway config + database in a temp directory, drives the real
FastAPI routes through TestClient (with auth overridden to a synthetic admin),
and asserts the properties that make issued certificates and CRLs valid to a
relying party — the things a unit test of the helpers alone would miss,
because each of these bugs lived in how a route wired the helpers together.

Covers:
  * every issuance path stamps a CRL Distribution Point (a cert issued
    without one can be revoked here and no client can ever find out)
  * CSR signatures are verified before signing (proof of possession)
  * the CN always ends up in the SAN, including for externally-built CSRs
  * CRLNumber is monotonic, never reused, and identical across the admin
    route and the public distribution point — RFC 5280 §5.2.3
  * a database upgraded from before migration 006 continues past its old
    CRL number rather than replaying numbers it already published
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

# Config must exist in the environment before app.config is first imported.
TMP = Path(tempfile.mkdtemp(prefix="pktcert-tests-"))
(TMP / "config.yaml").write_text(
    f"install_dir: {TMP}\n"
    f"secret_key: {'a' * 64}\n"
    f"credential_key: {Fernet.generate_key().decode()}\n"
    f"suite_token: ''\n"
)
os.environ["PKTCERT_CONFIG"] = str(TMP / "config.yaml")
os.environ["PKTCERT_INSTALL_DIR"] = str(TMP)
sys.path.insert(0, str(REPO_ROOT))

from cryptography import x509                                    # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec          # noqa: E402
from cryptography.x509.oid import NameOID                         # noqa: E402
from fastapi.testclient import TestClient                         # noqa: E402

from app.database import init_db                                  # noqa: E402
from app.dependencies import get_current_user                     # noqa: E402
from app.main import app                                          # noqa: E402

DB = TMP / "pktcert.db"
FAILURES: list[str] = []


def check(label: str, passed: bool, detail: str = "") -> None:
    print(f"{'PASS' if passed else 'FAIL'}  {label}" + (f"  — {detail}" if detail and not passed else ""))
    if not passed:
        FAILURES.append(label)


def cdp_urls(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    except x509.ExtensionNotFound:
        return []
    return [str(n.value) for dp in ext.value for n in (dp.full_name or [])]


def sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return [str(getattr(entry, "value", entry)) for entry in ext.value]


def stored_cert(cert_id: int) -> x509.Certificate:
    """Read a stored PEM straight from the database — downloading it over the
    API requires step-up re-auth with a real password, which this synthetic
    admin doesn't have."""
    row = sqlite3.connect(str(DB)).execute(
        "SELECT cert_pem FROM certificates WHERE id = ?", (cert_id,)
    ).fetchone()
    return x509.load_pem_x509_certificate(row[0].encode())


def crl_number_of(der: bytes) -> int:
    crl = x509.load_der_x509_crl(der)
    return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number


def main() -> int:
    asyncio.run(init_db())
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 1, "username": "admin", "email": "admin@test", "role": "admin", "is_active": True,
    }
    client = TestClient(app)

    # EC keys throughout — same code paths as RSA, orders of magnitude faster.
    ca_id = client.post("/api/cas/generate", json={
        "name": "Test Root CA", "ca_type": "root",
        "key_algorithm": "ec", "key_size": 2048, "validity_days": 3650,
    }).json()["id"]
    tpl_id = client.post("/api/templates", json={
        "name": "EC Test", "key_algorithm": "ec", "key_size": 2048, "validity_days": 90,
        "key_usage": ["digital_signature"], "extended_key_usage": ["server_auth"],
    }).json()["id"]
    expected_cdp = [f"http://localhost:8763/crl/{ca_id}.crl"]

    print("\n── issuance: POST /api/certificates/issue ──")
    r = client.post("/api/certificates/issue", json={
        "common_name": "issued.example.com", "sans": ["alt.example.com"],
        "ca_id": ca_id, "template_id": tpl_id,
    })
    check("certificate is issued", r.status_code == 201, r.text[:160])
    issued = stored_cert(r.json()["id"])
    check("issued cert carries a CRL Distribution Point", cdp_urls(issued) == expected_cdp, str(cdp_urls(issued)))
    check("issued cert SAN contains the CN", "issued.example.com" in sans(issued), str(sans(issued)))

    print("\n── issuance: POST /api/certificates/csr ──")
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "csr.example.com")]))
        .sign(key, hashes.SHA256())
    )  # deliberately carries no SAN extension of its own
    r = client.post("/api/certificates/csr", json={
        "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(),
        "ca_id": ca_id, "template_id": tpl_id,
    })
    check("valid CSR is signed", r.status_code == 201, r.text[:160])
    csr_cert_id = r.json()["id"]
    csr_cert = stored_cert(csr_cert_id)
    check("CSR-signed cert carries a CRL Distribution Point", cdp_urls(csr_cert) == expected_cdp, str(cdp_urls(csr_cert)))
    check("CSR-signed cert SAN contains the CN", "csr.example.com" in sans(csr_cert), str(sans(csr_cert)))

    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0xFF  # corrupt the signature, leaving the structure parseable
    tampered = x509.load_der_x509_csr(bytes(der)).public_bytes(serialization.Encoding.PEM).decode()
    r = client.post("/api/certificates/csr", json={
        "csr_pem": tampered, "ca_id": ca_id, "template_id": tpl_id,
    })
    check("CSR with an invalid signature is refused", r.status_code == 400, f"HTTP {r.status_code}")
    check("refusal explains why", "signature is invalid" in r.text, r.text[:160])

    print("\n── CRL numbering (RFC 5280 §5.2.3) ──")
    first = client.get(f"/api/cas/{ca_id}/crl").json()["crl_number"]
    second = client.get(f"/api/cas/{ca_id}/crl").json()["crl_number"]
    check("merely viewing the CRL does not consume a number", first == second, f"{first} -> {second}")

    public_n = crl_number_of(client.get(f"/crl/{ca_id}.crl").content)
    check("public DP and admin route agree", public_n == first, f"admin={first} public={public_n}")

    client.post(f"/api/certificates/{csr_cert_id}/revoke", json={"reason": "regression test"})
    after_der = client.get(f"/crl/{ca_id}.crl").content
    after_n = crl_number_of(after_der)
    check("revoking issues exactly one new number", after_n == public_n + 1, f"{public_n} -> {after_n}")
    check(
        "revoked serial appears on the CRL",
        x509.load_der_x509_crl(after_der).get_revoked_certificate_by_serial_number(csr_cert.serial_number) is not None,
    )
    admin_n = client.get(f"/api/cas/{ca_id}/crl").json()["crl_number"]
    check("routes still agree after revocation", admin_n == after_n, f"admin={admin_n} public={after_n}")

    repeat_der = client.get(f"/crl/{ca_id}.crl").content
    check("an unchanged revoked set republishes nothing", repeat_der == after_der)

    print("\n── upgrade path from before migration 006 ──")
    legacy_id = client.post("/api/cas/generate", json={
        "name": "Legacy CA", "ca_type": "root",
        "key_algorithm": "ec", "key_size": 2048, "validity_days": 3650,
    }).json()["id"]
    # Simulate a live database where the old admin endpoint already handed out
    # CRL numbers 1..7 before this code existed.
    conn = sqlite3.connect(str(DB))
    conn.execute("UPDATE certificate_authorities SET crl_number = 7 WHERE id = ?", (legacy_id,))
    conn.commit()
    conn.close()
    legacy_admin_n = client.get(f"/api/cas/{legacy_id}/crl").json()["crl_number"]
    legacy_public_n = crl_number_of(client.get(f"/crl/{legacy_id}.crl").content)
    check(
        "first CRL after upgrade continues past the old counter",
        legacy_admin_n == 8 and legacy_public_n == 8,
        f"admin={legacy_admin_n} public={legacy_public_n}",
    )

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
