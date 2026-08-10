#!/usr/bin/env python3
"""
Chain-building, containment, and revocation-reason tests.

Standalone script — run from the repo root:
    python3 tests/test_chain_and_constraints.py

Three separate gaps, all about what a *relying party* can see and enforce
rather than what pktCert records internally:

  * AIA — issued certificates pointed at a CRL but named no way to fetch the
    issuing CA. A server that sends only its leaf (very common) was therefore
    unverifiable: the client had a certificate signed by an issuer it could
    not obtain.
  * Path length / name constraints — every CA was built unconstrained, so any
    intermediate could mint an unlimited chain of further sub-CAs for any name
    on the internet. A stolen intermediate key was as dangerous as the root.
  * Revocation reason codes — revoked_reason was free text that never reached
    the CRL, so every revocation published as an undifferentiated serial and
    a key compromise looked identical to a routine replacement.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

REPO_ROOT = Path(__file__).resolve().parents[1]

TMP = Path(tempfile.mkdtemp(prefix="pktcert-chain-"))
(TMP / "config.yaml").write_text(
    f"install_dir: {TMP}\n"
    f"secret_key: {'a' * 64}\n"
    f"credential_key: {Fernet.generate_key().decode()}\n"
    f"suite_token: ''\n"
)
os.environ["PKTCERT_CONFIG"] = str(TMP / "config.yaml")
os.environ["PKTCERT_INSTALL_DIR"] = str(TMP)
sys.path.insert(0, str(REPO_ROOT))

import sqlite3                                    # noqa: E402
from cryptography import x509                     # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.x509.oid import AuthorityInformationAccessOID  # noqa: E402
from fastapi.testclient import TestClient         # noqa: E402

from app.database import init_db                  # noqa: E402
from app.dependencies import get_current_user     # noqa: E402
from app.main import app                          # noqa: E402

DB = TMP / "pktcert.db"
FAILURES: list[str] = []


def check(label: str, passed: bool, detail: str = "") -> None:
    print(f"{'PASS' if passed else 'FAIL'}  {label}" + (f"  — {detail}" if detail and not passed else ""))
    if not passed:
        FAILURES.append(label)


def stored_cert(cert_id: int) -> x509.Certificate:
    row = sqlite3.connect(str(DB)).execute(
        "SELECT cert_pem FROM certificates WHERE id = ?", (cert_id,)
    ).fetchone()
    return x509.load_pem_x509_certificate(row[0].encode())


def aia_urls(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
    except x509.ExtensionNotFound:
        return []
    return [
        str(d.access_location.value) for d in ext.value
        if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS
    ]


async def main() -> int:
    await init_db()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 1, "username": "admin", "email": "admin@test", "role": "admin", "is_active": True,
    }
    client = TestClient(app)

    root = client.post("/api/cas/generate", json={
        "name": "Constrained Root", "ca_type": "root",
        "key_algorithm": "ec", "key_size": 2048, "validity_days": 3650,
        "permitted_dns": [".corp.example.com"], "permitted_ip": ["10.0.0.0/8"],
    }).json()
    tpl_id = client.post("/api/templates", json={
        "name": "EC", "key_algorithm": "ec", "key_size": 2048, "validity_days": 90,
        "key_usage": ["digital_signature"], "extended_key_usage": ["server_auth"],
    }).json()["id"]

    print("\n── name constraints and path length ──")
    root_cert = x509.load_pem_x509_certificate(root["cert_pem"].encode())
    nc = root_cert.extensions.get_extension_for_class(x509.NameConstraints)
    permitted = [str(getattr(g, "value", g)) for g in (nc.value.permitted_subtrees or [])]
    check("root carries NameConstraints", ".corp.example.com" in permitted, str(permitted))
    check("name constraints are critical", nc.critical)
    check("permitted IP range is included", any("10.0.0.0/8" in p for p in permitted), str(permitted))
    check("constraints are reported by the API", root["name_constraints"] is not None)

    inter = client.post("/api/cas/generate", json={
        "name": "Issuing Intermediate", "ca_type": "intermediate", "parent_ca_id": root["id"],
        "key_algorithm": "ec", "key_size": 2048, "validity_days": 1825,
    }).json()
    inter_cert = x509.load_pem_x509_certificate(inter["cert_pem"].encode())
    bc = inter_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    check("intermediate defaults to path length 0", bc.value.path_length == 0, str(bc.value.path_length))
    check("intermediate is still a CA", bc.value.ca)
    root_bc = root_cert.extensions.get_extension_for_class(x509.BasicConstraints)
    check("root stays unconstrained by default", root_bc.value.path_length is None, str(root_bc.value.path_length))

    explicit = client.post("/api/cas/generate", json={
        "name": "Two Deep", "ca_type": "intermediate", "parent_ca_id": root["id"],
        "key_algorithm": "ec", "key_size": 2048, "validity_days": 1825, "path_length": 1,
    }).json()
    explicit_bc = x509.load_pem_x509_certificate(explicit["cert_pem"].encode()) \
        .extensions.get_extension_for_class(x509.BasicConstraints)
    check("an explicit path length is honoured", explicit_bc.value.path_length == 1,
          str(explicit_bc.value.path_length))

    print("\n── AIA: finding the issuer ──")
    check("intermediate points at its parent",
          aia_urls(inter_cert) == [f"http://localhost:8763/aia/{root['id']}.crt"], str(aia_urls(inter_cert)))
    check("a root has no issuer to point at", aia_urls(root_cert) == [], str(aia_urls(root_cert)))

    leaf = client.post("/api/certificates/issue", json={
        "common_name": "host.corp.example.com", "sans": [],
        "ca_id": inter["id"], "template_id": tpl_id,
    }).json()
    leaf_cert = stored_cert(leaf["id"])
    check("issued certificate points at its issuing CA",
          aia_urls(leaf_cert) == [f"http://localhost:8763/aia/{inter['id']}.crt"], str(aia_urls(leaf_cert)))

    r = client.get(f"/aia/{inter['id']}.crt")
    check("the AIA URL actually serves the CA", r.status_code == 200, f"HTTP {r.status_code}")
    check("served as DER", r.headers["content-type"] == "application/pkix-cert", r.headers.get("content-type", ""))
    fetched = x509.load_der_x509_certificate(r.content)
    check("and it is the right certificate",
          fetched.fingerprint(hashes.SHA256()) == inter_cert.fingerprint(hashes.SHA256()))
    check("the fetched CA is the leaf's actual issuer", fetched.subject == leaf_cert.issuer)
    r_pem = client.get(f"/aia/{inter['id']}.crt?format=pem")
    check("PEM form is available for humans", "-----BEGIN CERTIFICATE-----" in r_pem.text)
    check("unknown CA returns 404", client.get("/aia/99999.crt").status_code == 404)

    print("\n── revocation reason codes ──")
    r = client.post(f"/api/certificates/{leaf['id']}/revoke",
                    json={"reason": "rebuilt the host", "reason_code": "key_compromise"})
    check("revocation accepts a reason code", r.status_code == 200, r.text[:160])

    crl = x509.load_der_x509_crl(client.get(f"/crl/{inter['id']}.crl").content)
    entry = crl.get_revoked_certificate_by_serial_number(leaf_cert.serial_number)
    check("the revoked serial is on the CRL", entry is not None)
    if entry is not None:
        reason = entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
        check("the CRL carries keyCompromise", reason == x509.ReasonFlags.key_compromise, str(reason))

    detail = client.get(f"/api/certificates/{leaf['id']}").json()
    check("the reason code is reported by the API", detail["revoked_reason_code"] == "key_compromise",
          str(detail.get("revoked_reason_code")))
    check("the free-text note is kept alongside it", detail["revoked_reason"] == "rebuilt the host")

    other = client.post("/api/certificates/issue", json={
        "common_name": "other.corp.example.com", "sans": [],
        "ca_id": inter["id"], "template_id": tpl_id,
    }).json()
    client.post(f"/api/certificates/{other['id']}/revoke", json={"reason_code": "unspecified"})
    crl2 = x509.load_der_x509_crl(client.get(f"/crl/{inter['id']}.crl").content)
    entry2 = crl2.get_revoked_certificate_by_serial_number(stored_cert(other["id"]).serial_number)
    has_reason_ext = True
    try:
        entry2.extensions.get_extension_for_class(x509.CRLReason)
    except x509.ExtensionNotFound:
        has_reason_ext = False
    # RFC 5280 §5.3.1: reasonCode SHOULD be absent rather than present-and-
    # unspecified, since an explicit "unspecified" says nothing extra.
    check("'unspecified' omits the extension entirely", not has_reason_ext)

    r = client.post(f"/api/certificates/{other['id']}/revoke", json={"reason_code": "not_a_real_reason"})
    check("an invalid reason code is rejected", r.status_code == 400, f"HTTP {r.status_code}")

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
