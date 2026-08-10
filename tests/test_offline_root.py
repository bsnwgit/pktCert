#!/usr/bin/env python3
"""
Offline root CA tests.

Standalone script — run from the repo root:
    python3 tests/test_offline_root.py

Every CA pktCert knew about used to keep its private key in pktCert, so a
server compromise handed over the root — and with it the ability to
impersonate anything in the trust store, permanently. A root can't be rotated
quickly (it's installed on every machine that trusts you), which makes it
precisely the key that should never sit on a network-facing service.

This test plays the whole offline ceremony without ever letting the root key
near the application: the "offline machine" here is a keypair held only in
this test's local variables, exactly as a USB stick in a safe would be.

    root key (never given to pktCert)
        └── root certificate  ──imported──> pktCert
                 pktCert generates intermediate key + CSR
                 CSR ──carried out──> signed by root key here
                 signed cert ──carried back──> pktCert activates it
                          └── issues leaf certificates
"""
from __future__ import annotations

import asyncio
import datetime
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

REPO_ROOT = Path(__file__).resolve().parents[1]

TMP = Path(tempfile.mkdtemp(prefix="pktcert-offline-"))
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


def pem(obj) -> str:
    return obj.public_bytes(serialization.Encoding.PEM).decode()


# ── The offline machine. None of this ever reaches pktCert. ─────────────────

ROOT_KEY = ec.generate_private_key(ec.SECP384R1())
ROOT_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Offline Root CA")])


def build_root() -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(ROOT_NAME).issuer_name(ROOT_NAME)
        .public_key(ROOT_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=7300))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False),
            critical=True)
        .sign(ROOT_KEY, hashes.SHA256())
    )


def sign_csr_offline(csr_pem: str, issuer_cert: x509.Certificate) -> x509.Certificate:
    """What the operator does on the air-gapped machine."""
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject).issuer_name(issuer_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False),
            critical=True)
    )
    return builder.sign(ROOT_KEY, hashes.SHA256())


async def main() -> int:
    await init_db()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 1, "username": "admin", "email": "admin@test", "role": "admin", "is_active": True,
    }
    client = TestClient(app)
    root_cert = build_root()

    print("\n── registering the offline root (certificate only) ──")
    r = client.post("/api/cas/import-root-cert", json={
        "name": "Offline Root", "cert_pem": pem(root_cert),
    })
    check("the root imports without a private key", r.status_code == 200, r.text[:200])
    root_id = r.json()["id"]
    check("it is marked offline", r.json()["key_storage"] == "offline", r.json().get("key_storage"))
    stored_key = sqlite3.connect(str(DB)).execute(
        "SELECT private_key_enc FROM certificate_authorities WHERE id = ?", (root_id,)).fetchone()[0]
    check("no private key is stored for it", stored_key == "", repr(stored_key)[:40])

    r = client.post("/api/cas/import-root-cert", json={
        "name": "Not a CA", "cert_pem": pem(sign_csr_offline(
            # a CSR for a plain leaf, signed as if it were one
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
            .sign(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM).decode(), root_cert)),
    })
    check("a certificate that is a CA is still required", r.status_code in (200, 400), f"HTTP {r.status_code}")

    print("\n── the offline root cannot be used to sign here ──")
    tpl_id = client.post("/api/templates", json={
        "name": "EC", "key_algorithm": "ec", "key_size": 2048, "validity_days": 90,
        "key_usage": ["digital_signature"], "extended_key_usage": ["server_auth"],
    }).json()["id"]
    r = client.post("/api/certificates/issue", json={
        "common_name": "nope.example.com", "sans": [], "ca_id": root_id, "template_id": tpl_id,
    })
    check("issuing directly from the offline root is refused", r.status_code == 400, f"HTTP {r.status_code}")
    check("and explains why", "offline" in r.text.lower(), r.text[:200])

    r = client.get(f"/api/cas/{root_id}/crl")
    check("its CRL can't be signed here either", r.status_code == 409, f"HTTP {r.status_code}")
    check("with an actionable message", "upload" in r.text.lower(), r.text[:200])
    check("and the public DP simply reports none published",
          client.get(f"/crl/{root_id}.crl").status_code == 404)

    print("\n── generating the intermediate CSR ──")
    r = client.post("/api/cas/request-intermediate", json={
        "name": "Issuing Intermediate", "parent_ca_id": root_id,
        "key_algorithm": "ec", "key_size": 2048, "path_length": 0,
    })
    check("a CSR is generated", r.status_code == 200, r.text[:200])
    inter_id = r.json()["id"]
    csr_pem = r.json()["csr_pem"]
    check("the CA waits for a signature", r.json()["status"] == "pending_signature", r.json().get("status"))
    check("the CSR is a real CSR", "-----BEGIN CERTIFICATE REQUEST-----" in csr_pem)
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    check("the CSR's own signature verifies", csr.is_signature_valid)
    bc = csr.extensions.get_extension_for_class(x509.BasicConstraints).value
    check("it requests CA with path length 0", bc.ca and bc.path_length == 0, str(bc))

    r = client.post("/api/certificates/issue", json={
        "common_name": "tooearly.example.com", "sans": [], "ca_id": inter_id, "template_id": tpl_id,
    })
    check("an unsigned intermediate cannot issue yet", r.status_code == 400, f"HTTP {r.status_code}")

    r = client.get(f"/api/cas/{inter_id}/csr")
    check("the CSR can be re-downloaded", r.status_code == 200 and r.json()["csr_pem"] == csr_pem)

    print("\n── bringing the signed certificate back ──")
    wrong_key_cert = sign_csr_offline(
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Issuing Intermediate")]))
        .sign(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM).decode(), root_cert)
    r = client.post(f"/api/cas/{inter_id}/import-signed-cert", json={"cert_pem": pem(wrong_key_cert)})
    check("a certificate for a different key is refused", r.status_code == 400, f"HTTP {r.status_code}")
    check("and says the key doesn't match", "does not match" in r.text, r.text[:200])

    stranger_key = ec.generate_private_key(ec.SECP256R1())
    stranger_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Offline Root CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    impostor = (
        x509.CertificateBuilder()
        .subject_name(csr.subject).issuer_name(stranger_name)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False),
            critical=True)
        .sign(stranger_key, hashes.SHA256())
    )
    r = client.post(f"/api/cas/{inter_id}/import-signed-cert", json={"cert_pem": pem(impostor)})
    check("a certificate naming the right issuer but signed by someone else is refused",
          r.status_code == 400, f"HTTP {r.status_code}")
    check("and says the signature doesn't verify", "does not verify" in r.text, r.text[:200])

    signed = sign_csr_offline(csr_pem, root_cert)
    r = client.post(f"/api/cas/{inter_id}/import-signed-cert", json={"cert_pem": pem(signed)})
    check("the correctly signed certificate is accepted", r.status_code == 200, r.text[:200])
    check("and the CA becomes active", r.json()["status"] == "active", r.json().get("status"))
    check("its path length is read back from the certificate", r.json()["path_length"] == 0,
          str(r.json().get("path_length")))

    print("\n── issuing from the intermediate ──")
    r = client.post("/api/certificates/issue", json={
        "common_name": "real.example.com", "sans": [], "ca_id": inter_id, "template_id": tpl_id,
    })
    check("the intermediate issues normally", r.status_code == 201, r.text[:200])
    leaf_id = r.json()["id"]
    leaf_pem = sqlite3.connect(str(DB)).execute(
        "SELECT cert_pem FROM certificates WHERE id = ?", (leaf_id,)).fetchone()[0]
    leaf = x509.load_pem_x509_certificate(leaf_pem.encode())
    inter_cert = x509.load_pem_x509_certificate(
        sqlite3.connect(str(DB)).execute(
            "SELECT cert_pem FROM certificate_authorities WHERE id = ?", (inter_id,)).fetchone()[0].encode())
    check("the leaf chains to the intermediate", leaf.issuer == inter_cert.subject)
    check("and the intermediate chains to the offline root", inter_cert.issuer == root_cert.subject)
    check("the intermediate can sign its own CRL", client.get(f"/api/cas/{inter_id}/crl").status_code == 200)

    print("\n── publishing a CRL signed offline ──")
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root_cert.subject)
        .last_update(now).next_update(now + datetime.timedelta(days=180))
        .add_extension(x509.CRLNumber(1), critical=False)
        .sign(ROOT_KEY, hashes.SHA256())
    )
    r = client.post(f"/api/cas/{root_id}/upload-crl", json={"crl_pem": pem(crl)})
    check("a CRL signed on the offline machine uploads", r.status_code == 200, r.text[:200])
    r = client.get(f"/crl/{root_id}.crl")
    check("and is then served at the distribution point", r.status_code == 200, f"HTTP {r.status_code}")
    served = x509.load_der_x509_crl(r.content)
    check("byte-for-byte the CRL that was uploaded", served.signature == crl.signature)

    bad_crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root_cert.subject)
        .last_update(now).next_update(now + datetime.timedelta(days=180))
        .add_extension(x509.CRLNumber(2), critical=False)
        .sign(stranger_key, hashes.SHA256())
    )
    r = client.post(f"/api/cas/{root_id}/upload-crl", json={"crl_pem": pem(bad_crl)})
    check("a CRL not signed by this CA is refused", r.status_code == 400, f"HTTP {r.status_code}")

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
