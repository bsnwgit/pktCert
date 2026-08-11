#!/usr/bin/env python3
"""
SCEP (RFC 8894) enrolment tests.

Standalone script — run from the repo root:
    python3 tests/test_scep.py

SCEP is the protocol network equipment actually speaks: Cisco IOS and ASA,
Juniper, Palo Alto, Fortinet, and every MDM pushing certificates to laptops
and phones. EST is better in every respect, but on kit more than a few years
old SCEP is often the only option present.

It also predates every convenience. A request is PKCS#7 SignedData whose
content is PKCS#7 EnvelopedData encrypted to the CA, with the PKCS#10 inside
that, and the protocol itself rides in custom authenticated attributes on the
signature. This test acts as a real SCEP client — building that structure by
hand and parsing the response the same way a device would — because a
half-formed message is exactly what a device would send, and nothing else
would catch a mistake in the wire format.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import sys
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

REPO_ROOT = Path(__file__).resolve().parents[1]

TMP = Path(tempfile.mkdtemp(prefix="pktcert-scep-"))
(TMP / "config.yaml").write_text(
    f"install_dir: {TMP}\n"
    f"secret_key: {'a' * 64}\n"
    f"credential_key: {Fernet.generate_key().decode()}\n"
    f"suite_token: ''\n"
)
os.environ["PKTCERT_CONFIG"] = str(TMP / "config.yaml")
os.environ["PKTCERT_INSTALL_DIR"] = str(TMP)
sys.path.insert(0, str(REPO_ROOT))

import datetime                                                    # noqa: E402
import sqlite3                                                     # noqa: E402
from asn1crypto import cms, x509 as asn1_x509                       # noqa: E402
from cryptography import x509                                       # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization     # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa   # noqa: E402
from cryptography.hazmat.primitives.serialization import pkcs7       # noqa: E402
from cryptography.x509.oid import NameOID                            # noqa: E402
from fastapi.testclient import TestClient                            # noqa: E402

from app.cert import scep_messages as sm                             # noqa: E402
from app.database import init_db                                     # noqa: E402
from app.dependencies import get_current_user                        # noqa: E402
from app.main import app                                             # noqa: E402

DB = TMP / "pktcert.db"
FAILURES: list[str] = []


def check(label: str, passed: bool, detail: str = "") -> None:
    print(f"{'PASS' if passed else 'FAIL'}  {label}" + (f"  — {detail}" if detail and not passed else ""))
    if not passed:
        FAILURES.append(label)


# ── A device, doing what a device does ──────────────────────────────────────

class Device:
    """Builds real SCEP requests and reads real SCEP responses."""

    def __init__(self, common_name: str) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.cn = common_name
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.datetime.now(datetime.timezone.utc)
        # A device has no certificate yet, so it signs with one it makes itself.
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(self.key, hashes.SHA256())
        )
        self.transaction_id = base64.b16encode(os.urandom(8)).decode()
        self.nonce = os.urandom(16)

    def csr(self, challenge: str | None) -> bytes:
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.cn)])
        )
        if challenge is not None:
            builder = builder.add_attribute(
                x509.ObjectIdentifier("1.2.840.113549.1.9.7"), challenge.encode()
            )
        return builder.sign(self.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def pkcs_req(self, ca_cert: x509.Certificate, challenge: str | None) -> bytes:
        envelope = (
            pkcs7.PKCS7EnvelopeBuilder()
            .set_data(self.csr(challenge))
            .add_recipient(ca_cert)
            .encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
        )

        def attr(oid, value):
            return cms.CMSAttribute({"type": oid, "values": [value]})

        attrs = cms.CMSAttributes([
            attr("content_type", "data"),
            attr("message_digest", hashlib.sha256(envelope).digest()),
            attr(sm.OID_MESSAGE_TYPE, sm.MESSAGE_TYPE_PKCS_REQ),
            attr(sm.OID_TRANSACTION_ID, self.transaction_id),
            attr(sm.OID_SENDER_NONCE, self.nonce),
        ])
        signature = self.key.sign(attrs.dump(), padding.PKCS1v15(), hashes.SHA256())
        cert_asn1 = asn1_x509.Certificate.load(self.cert.public_bytes(serialization.Encoding.DER))
        signer = cms.SignerInfo({
            "version": "v1",
            "sid": cms.SignerIdentifier({"issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": cert_asn1["tbs_certificate"]["issuer"],
                "serial_number": cert_asn1["tbs_certificate"]["serial_number"],
            })}),
            "digest_algorithm": {"algorithm": "sha256"},
            "signed_attrs": attrs,
            "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
            "signature": signature,
        })
        return cms.ContentInfo({"content_type": "signed_data", "content": cms.SignedData({
            "version": "v1",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": {"content_type": "data", "content": envelope},
            "certificates": [cert_asn1],
            "signer_infos": [signer],
        })}).dump()

    def read_response(self, der: bytes) -> dict:
        signed = cms.ContentInfo.load(der)["content"]
        attrs = signed["signer_infos"][0]["signed_attrs"]

        def value(oid):
            for a in attrs:
                if a["type"].dotted == oid:
                    return a["values"][0].native
            return None

        out = {
            "message_type": value(sm.OID_MESSAGE_TYPE),
            "pki_status": value(sm.OID_PKI_STATUS),
            "fail_info": value(sm.OID_FAIL_INFO),
            "transaction_id": value(sm.OID_TRANSACTION_ID),
            "recipient_nonce": value(sm.OID_RECIPIENT_NONCE),
            "certs": [],
        }
        content = signed["encap_content_info"]["content"].native
        if content:
            inner = pkcs7.pkcs7_decrypt_der(content, self.cert, self.key, options=[])
            out["certs"] = pkcs7.load_der_pkcs7_certificates(inner)
        return out


async def main() -> int:
    await init_db()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 1, "username": "admin", "email": "admin@test", "role": "admin", "is_active": True,
    }
    client = TestClient(app)

    # SCEP envelopes use RSA key transport, so the CA has to be RSA.
    ca = client.post("/api/cas/generate", json={
        "name": "SCEP Root", "ca_type": "root",
        "key_algorithm": "rsa", "key_size": 2048, "validity_days": 3650,
    }).json()
    tpl_id = client.post("/api/templates", json={
        "name": "Device", "key_algorithm": "rsa", "key_size": 2048, "validity_days": 365,
        "key_usage": ["digital_signature"], "extended_key_usage": ["client_auth"],
    }).json()["id"]
    ca_cert = x509.load_pem_x509_certificate(ca["cert_pem"].encode())

    print("\n── before any profile exists ──")
    r = client.get("/scep?operation=GetCACert")
    check("GetCACert reports there's nothing configured yet", r.status_code == 503, f"HTTP {r.status_code}")

    r = client.post("/api/enrollment-profiles", json={
        "name": "Switches (SCEP)", "protocol": "scep", "ca_id": ca["id"], "template_id": tpl_id,
        "allowed_name_suffix": ".corp.example.com", "max_certs": 2,
    })
    check("a SCEP profile can be created", r.status_code == 201, r.text[:200])
    challenge = r.json()["secret"]

    print("\n── the operations a device performs first ──")
    r = client.get("/scep?operation=GetCACaps")
    check("GetCACaps responds", r.status_code == 200, f"HTTP {r.status_code}")
    caps = r.text.split()
    check("it advertises POSTPKIOperation", "POSTPKIOperation" in caps, r.text)
    check("and SHA-256", "SHA-256" in caps, r.text)

    r = client.get("/scep?operation=GetCACert")
    check("GetCACert returns the CA", r.status_code == 200, f"HTTP {r.status_code}")
    check("with the content type devices expect",
          r.headers["content-type"].startswith("application/x-x509-ca"), r.headers.get("content-type", ""))
    fetched = x509.load_der_x509_certificate(r.content)
    check("and it really is the CA",
          fetched.fingerprint(hashes.SHA256()) == ca_cert.fingerprint(hashes.SHA256()))

    r = client.get("/scep?operation=Nonsense")
    check("an unknown operation is refused", r.status_code == 400, f"HTTP {r.status_code}")

    print("\n── enrolling ──")
    device = Device("sw1.corp.example.com")
    r = client.post("/scep?operation=PKIOperation", content=device.pkcs_req(ca_cert, challenge))
    check("the request is accepted", r.status_code == 200, f"HTTP {r.status_code}: {r.text[:120]}")
    check("answered as a PKI message",
          r.headers["content-type"] == "application/x-pki-message", r.headers.get("content-type", ""))

    resp = device.read_response(r.content)
    check("it is a CertRep", resp["message_type"] == sm.MESSAGE_TYPE_CERT_REP, str(resp["message_type"]))
    check("pkiStatus is SUCCESS", resp["pki_status"] == sm.PKI_STATUS_SUCCESS, str(resp["pki_status"]))
    check("the transactionID is echoed", resp["transaction_id"] == device.transaction_id)
    check("the senderNonce comes back as recipientNonce", resp["recipient_nonce"] == device.nonce)
    check("a certificate was returned", len(resp["certs"]) >= 1, str(len(resp["certs"])))

    issued = [c for c in resp["certs"]
              if c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "sw1.corp.example.com"]
    check("issued for the requested name", len(issued) == 1, str([c.subject.rfc4514_string() for c in resp["certs"]]))
    if issued:
        check("issued by the profile's CA", issued[0].issuer == ca_cert.subject)
        check("with a CRL distribution point",
              issued[0].extensions.get_extension_for_class(x509.CRLDistributionPoints) is not None)
    check("the CA chain is included so the device can trust it", len(resp["certs"]) >= 2,
          str(len(resp["certs"])))

    row = sqlite3.connect(str(DB)).execute(
        "SELECT source, private_key_enc FROM certificates WHERE common_name = 'sw1.corp.example.com'"
    ).fetchone()
    check("recorded in the inventory as enrolled", row and row[0] == "enrolled", str(row[0]) if row else "missing")
    check("and pktCert holds no private key — the device kept it", not (row and row[1]))

    print("\n── failures come back as SCEP, not HTTP errors ──")
    # A device largely ignores HTTP status codes; one that gets a bare 403 with
    # no CertRep typically just retries forever.
    bad = Device("sw2.corp.example.com")
    r = client.post("/scep?operation=PKIOperation", content=bad.pkcs_req(ca_cert, "wrong-challenge"))
    check("a wrong challenge still returns HTTP 200", r.status_code == 200, f"HTTP {r.status_code}")
    resp = bad.read_response(r.content)
    check("with pkiStatus FAILURE", resp["pki_status"] == sm.PKI_STATUS_FAILURE, str(resp["pki_status"]))
    check("and failInfo badIdentity", resp["fail_info"] == sm.FAIL_INFO_BAD_IDENTITY, str(resp["fail_info"]))
    check("its transactionID is still echoed", resp["transaction_id"] == bad.transaction_id)

    nopass = Device("sw3.corp.example.com")
    r = client.post("/scep?operation=PKIOperation", content=nopass.pkcs_req(ca_cert, None))
    check("a request with no challenge password fails cleanly",
          nopass.read_response(r.content)["pki_status"] == sm.PKI_STATUS_FAILURE)

    outside = Device("payroll.finance.example.com")
    r = client.post("/scep?operation=PKIOperation", content=outside.pkcs_req(ca_cert, challenge))
    resp = outside.read_response(r.content)
    check("a name outside the profile's suffix is refused",
          resp["pki_status"] == sm.PKI_STATUS_FAILURE, str(resp["pki_status"]))
    check("and pktCert issued nothing for it",
          sqlite3.connect(str(DB)).execute(
              "SELECT COUNT(*) FROM certificates WHERE common_name LIKE '%finance%'").fetchone()[0] == 0)

    print("\n── the GET form, for devices that can't POST ──")
    getdev = Device("sw4.corp.example.com")
    body = base64.b64encode(getdev.pkcs_req(ca_cert, challenge)).decode()
    r = client.get("/scep", params={"operation": "PKIOperation", "message": body})
    check("enrolment over GET works too", r.status_code == 200, f"HTTP {r.status_code}")
    check("and issues a certificate",
          getdev.read_response(r.content)["pki_status"] == sm.PKI_STATUS_SUCCESS)

    print("\n── the profile's limits apply here too ──")
    over = Device("sw5.corp.example.com")
    r = client.post("/scep?operation=PKIOperation", content=over.pkcs_req(ca_cert, challenge))
    check("the certificate cap is enforced",
          over.read_response(r.content)["pki_status"] == sm.PKI_STATUS_FAILURE)

    log = client.get("/api/enrollment-profiles/log").json()
    scep_entries = [e for e in log if e["protocol"] == "scep"]
    check("every attempt is logged", len(scep_entries) >= 6, str(len(scep_entries)))
    check("including the refusals", any(e["outcome"] == "denied" for e in scep_entries))

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
