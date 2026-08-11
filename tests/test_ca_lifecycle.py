#!/usr/bin/env python3
"""
CA import validation and CA retirement tests.

Standalone script — run from the repo root:
    python3 tests/test_ca_lifecycle.py

Import used to accept anything that parsed. A leaf certificate imported as a
"CA", or a certificate paired with somebody else's private key, was stored
without complaint — and the failure then surfaced far away from the mistake,
at signing time or at every relying party trying to verify something it had
issued. A passphrase-protected key, which is how any properly stored CA key
is kept, couldn't be imported at all.

Deletion was the mirror image: it was allowed once no *non-revoked*
certificates remained, which is precisely backwards. Revoked certificates are
the ones that most need their CA, because deleting it destroys the only key
that can sign the CRL carrying their revocations — while those certificates
are still deployed and still trusted.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

REPO_ROOT = Path(__file__).resolve().parents[1]

TMP = Path(tempfile.mkdtemp(prefix="pktcert-califecycle-"))
(TMP / "config.yaml").write_text(
    f"install_dir: {TMP}\n"
    f"secret_key: {'a' * 64}\n"
    f"credential_key: {Fernet.generate_key().decode()}\n"
    f"suite_token: ''\n"
)
os.environ["PKTCERT_CONFIG"] = str(TMP / "config.yaml")
os.environ["PKTCERT_INSTALL_DIR"] = str(TMP)
sys.path.insert(0, str(REPO_ROOT))

import datetime                                   # noqa: E402
from cryptography import x509                     # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec          # noqa: E402
from cryptography.x509.oid import NameOID          # noqa: E402
from fastapi.testclient import TestClient          # noqa: E402

from app.database import init_db                   # noqa: E402
from app.dependencies import get_current_user      # noqa: E402
from app.main import app                           # noqa: E402

FAILURES: list[str] = []


def check(label: str, passed: bool, detail: str = "") -> None:
    print(f"{'PASS' if passed else 'FAIL'}  {label}" + (f"  — {detail}" if detail and not passed else ""))
    if not passed:
        FAILURES.append(label)


def make_pair(is_ca: bool, key_cert_sign: bool = True):
    """Build a self-signed certificate + its key, CA or leaf."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "imported.example.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                key_cert_sign=key_cert_sign, crl_sign=is_ca,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    )
    cert = builder.sign(key, hashes.SHA256())
    return cert, key


def pem_cert(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def pem_key(key, passphrase: str | None = None) -> str:
    enc = (serialization.BestAvailableEncryption(passphrase.encode())
           if passphrase else serialization.NoEncryption())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    ).decode()


async def main() -> int:
    await init_db()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 1, "username": "admin", "email": "admin@test", "role": "admin", "is_active": True,
    }
    client = TestClient(app)

    print("\n── import validation ──")
    ca_cert, ca_key = make_pair(is_ca=True)
    _other_cert, other_key = make_pair(is_ca=True)

    r = client.post("/api/cas/import", json={
        "name": "Mismatched", "cert_pem": pem_cert(ca_cert), "private_key_pem": pem_key(other_key),
    })
    check("a key that doesn't match the certificate is refused", r.status_code == 400, f"HTTP {r.status_code}")
    check("and says so plainly", "does not match" in r.text, r.text[:160])

    leaf_cert, leaf_key = make_pair(is_ca=False, key_cert_sign=False)
    r = client.post("/api/cas/import", json={
        "name": "Not a CA", "cert_pem": pem_cert(leaf_cert), "private_key_pem": pem_key(leaf_key),
    })
    check("a leaf certificate is refused as a CA", r.status_code == 400, f"HTTP {r.status_code}")
    check("and explains why", "cannot act as a CA" in r.text, r.text[:200])

    no_sign_cert, no_sign_key = make_pair(is_ca=True, key_cert_sign=False)
    r = client.post("/api/cas/import", json={
        "name": "No keyCertSign", "cert_pem": pem_cert(no_sign_cert), "private_key_pem": pem_key(no_sign_key),
    })
    check("a CA without keyCertSign is refused", r.status_code == 400, f"HTTP {r.status_code}")

    r = client.post("/api/cas/import", json={
        "name": "Encrypted key, no passphrase", "cert_pem": pem_cert(ca_cert),
        "private_key_pem": pem_key(ca_key, "s3cret"),
    })
    check("an encrypted key without its passphrase is refused", r.status_code == 400, f"HTTP {r.status_code}")
    check("and asks for the passphrase", "passphrase" in r.text.lower(), r.text[:200])

    r = client.post("/api/cas/import", json={
        "name": "Encrypted Root", "cert_pem": pem_cert(ca_cert),
        "private_key_pem": pem_key(ca_key, "s3cret"), "key_passphrase": "s3cret",
    })
    check("a passphrase-protected CA key imports with its passphrase", r.status_code == 200, r.text[:200])
    imported_id = r.json()["id"] if r.status_code == 200 else None

    print("\n── the imported CA actually works ──")
    if imported_id:
        tpl_id = client.post("/api/templates", json={
            "name": "EC", "key_algorithm": "ec", "key_size": 2048, "validity_days": 30,
            "key_usage": ["digital_signature"], "extended_key_usage": ["server_auth"],
        }).json()["id"]
        r = client.post("/api/certificates/issue", json={
            "common_name": "signed-by-import.example.com", "sans": [],
            "ca_id": imported_id, "template_id": tpl_id,
        })
        check("it can sign a certificate", r.status_code == 201, r.text[:200])
        issued_id = r.json()["id"] if r.status_code == 201 else None

    print("\n── retiring a CA ──")
    r = client.patch(f"/api/cas/{imported_id}/status", json={"status": "disabled"})
    check("a CA can be disabled", r.status_code == 200 and r.json()["status"] == "disabled", r.text[:160])

    r = client.post("/api/certificates/issue", json={
        "common_name": "should-fail.example.com", "sans": [],
        "ca_id": imported_id, "template_id": tpl_id,
    })
    check("a disabled CA cannot issue", r.status_code == 400, f"HTTP {r.status_code}")

    r = client.get(f"/crl/{imported_id}.crl")
    check("a disabled CA still publishes its CRL", r.status_code == 200, f"HTTP {r.status_code}")
    r = client.get(f"/aia/{imported_id}.crt")
    check("a disabled CA is still fetchable for chain building", r.status_code == 200, f"HTTP {r.status_code}")

    r = client.delete(f"/api/cas/{imported_id}")
    check("a CA that has issued certificates cannot be deleted", r.status_code == 400, f"HTTP {r.status_code}")
    check("and the refusal explains the CRL consequence", "unrevocable" in r.text or "CRL" in r.text, r.text[:200])

    # Revoking everything must NOT make it deletable — that was the old rule,
    # and it's exactly backwards.
    if issued_id:
        client.post(f"/api/certificates/{issued_id}/revoke", json={"reason_code": "superseded"})
    r = client.delete(f"/api/cas/{imported_id}")
    check("revoking its certificates does not make it deletable", r.status_code == 400, f"HTTP {r.status_code}")

    r = client.patch(f"/api/cas/{imported_id}/status", json={"status": "active"})
    check("a disabled CA can be re-enabled", r.status_code == 200 and r.json()["status"] == "active", r.text[:160])

    unused = client.post("/api/cas/generate", json={
        "name": "Never Used", "ca_type": "root",
        "key_algorithm": "ec", "key_size": 2048, "validity_days": 365,
    }).json()
    r = client.delete(f"/api/cas/{unused['id']}")
    check("a CA that never issued anything can still be deleted", r.status_code == 204, f"HTTP {r.status_code}")

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
