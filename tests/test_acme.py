#!/usr/bin/env python3
"""
ACME (RFC 8555) enrolment tests.

Standalone script — run from the repo root:
    python3 tests/test_acme.py

Driven by a real ACME client built here: it signs its own flattened JWS, does
its own external account binding, and walks a full order from newAccount to
downloading the chain. Testing the endpoints with hand-written fixtures would
prove they return the right JSON without proving a client could ever use them,
and the protocol's sharp edges are all in the signing.

The one thing stubbed is the challenge fetch. http-01 is fixed at port 80 by
RFC 8555 §8.3, which a test cannot bind unprivileged, and adding a port
override to the product to make the test easier would ship a way to validate
against the wrong service. So the network call is replaced while everything
around it — the token, the key authorization, the state transitions — stays
real, and the validator's own address rules are checked directly.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

REPO_ROOT = Path(__file__).resolve().parents[1]

TMP = Path(tempfile.mkdtemp(prefix="pktcert-acme-"))
(TMP / "config.yaml").write_text(
    f"install_dir: {TMP}\n"
    f"secret_key: {'a' * 64}\n"
    f"credential_key: {Fernet.generate_key().decode()}\n"
    f"suite_token: ''\n"
)
os.environ["PKTCERT_CONFIG"] = str(TMP / "config.yaml")
os.environ["PKTCERT_INSTALL_DIR"] = str(TMP)
sys.path.insert(0, str(REPO_ROOT))

import sqlite3                                                      # noqa: E402
from cryptography import x509                                       # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization    # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec            # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import (       # noqa: E402
    decode_dss_signature,
)
from cryptography.x509.oid import NameOID                           # noqa: E402
from fastapi.testclient import TestClient                           # noqa: E402

from app.cert import acme_jws, acme_validation                      # noqa: E402
from app.database import init_db                                    # noqa: E402
from app.dependencies import get_current_user                       # noqa: E402
from app.main import app                                            # noqa: E402

DB = TMP / "pktcert.db"
FAILURES: list[str] = []


def check(label: str, passed: bool, detail: str = "") -> None:
    print(f"{'PASS' if passed else 'FAIL'}  {label}" + (f"  — {detail}" if detail and not passed else ""))
    if not passed:
        FAILURES.append(label)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ── a minimal ACME client ────────────────────────────────────────────────────

class AcmeClient:
    """Everything a real client does: an account key, JWS over every request,
    and a nonce carried forward from the previous response."""

    def __init__(self, http: TestClient, base: str) -> None:
        self.http = http
        self.base = base
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.kid: str | None = None
        self.nonce: str | None = None

    @property
    def jwk(self) -> dict:
        numbers = self.key.public_key().public_numbers()
        return {
            "kty": "EC", "crv": "P-256",
            "x": b64u(numbers.x.to_bytes(32, "big")),
            "y": b64u(numbers.y.to_bytes(32, "big")),
        }

    def thumbprint(self) -> str:
        canonical = json.dumps(
            {"crv": "P-256", "kty": "EC", "x": self.jwk["x"], "y": self.jwk["y"]},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return b64u(hashlib.sha256(canonical).digest())

    def fresh_nonce(self) -> str:
        if self.nonce:
            nonce, self.nonce = self.nonce, None
            return nonce
        return self.http.head("/acme/new-nonce").headers["replay-nonce"]

    def sign(self, url: str, payload, *, nonce: str | None = None,
             use_jwk: bool = False, alg: str = "ES256") -> dict:
        header = {"alg": alg, "nonce": nonce or self.fresh_nonce(), "url": url}
        if use_jwk or not self.kid:
            header["jwk"] = self.jwk
        else:
            header["kid"] = self.kid
        protected = b64u(json.dumps(header).encode())
        body = "" if payload is None else b64u(json.dumps(payload).encode())
        der = self.key.sign(f"{protected}.{body}".encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return {"protected": protected, "payload": body, "signature": b64u(raw)}

    def post(self, path: str, payload, **kwargs):
        response = self.http.post(path, json=self.sign(f"{self.base}{path}", payload, **kwargs),
                                  headers={"Content-Type": "application/jose+json"})
        if "replay-nonce" in response.headers:
            self.nonce = response.headers["replay-nonce"]
        return response

    def eab(self, kid: str, secret: str) -> dict:
        """External account binding: HS256 over the account key, keyed on the
        profile secret, exactly as a client configured with an EAB key pair
        would produce."""
        header = b64u(json.dumps({"alg": "HS256", "kid": kid,
                                  "url": f"{self.base}/acme/new-account"}).encode())
        payload = b64u(json.dumps(self.jwk).encode())
        mac_key = base64.urlsafe_b64decode(secret + "=" * ((-len(secret)) % 4))
        signature = hmac.new(mac_key, f"{header}.{payload}".encode(), hashlib.sha256).digest()
        return {"protected": header, "payload": payload, "signature": b64u(signature)}


def order_csr(names: list[str]) -> tuple[bytes, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER), key


async def main() -> int:
    await init_db()
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 1, "username": "admin", "email": "admin@test", "role": "admin", "is_active": True,
    }
    http = TestClient(app)

    root = http.post("/api/cas/generate", json={
        "name": "ACME Root", "ca_type": "root",
        "key_algorithm": "ec", "key_size": 2048, "validity_days": 3650,
    }).json()
    inter = http.post("/api/cas/generate", json={
        "name": "ACME Intermediate", "ca_type": "intermediate", "parent_ca_id": root["id"],
        "key_algorithm": "ec", "key_size": 2048, "validity_days": 1825,
    }).json()
    tpl_id = http.post("/api/templates", json={
        "name": "Server", "key_algorithm": "ec", "key_size": 2048, "validity_days": 90,
        "key_usage": ["digital_signature", "key_encipherment"],
        "extended_key_usage": ["server_auth"],
    }).json()["id"]

    print("\n── directory ──")
    r = http.get("/acme/directory")
    check("the directory responds without credentials", r.status_code == 200, f"HTTP {r.status_code}")
    directory = r.json()
    for field in ("newNonce", "newAccount", "newOrder", "revokeCert"):
        check(f"it advertises {field}", field in directory, str(sorted(directory)))
    check("and declares that external account binding is required",
          directory.get("meta", {}).get("externalAccountRequired") is True, str(directory.get("meta")))

    base = directory["newOrder"].rsplit("/acme/", 1)[0]
    r = http.head("/acme/new-nonce")
    check("new-nonce issues a nonce", bool(r.headers.get("replay-nonce")), str(r.headers))

    print("\n── profiles ──")
    r = http.post("/api/enrollment-profiles", json={
        "name": "Web servers", "protocol": "acme", "ca_id": inter["id"], "template_id": tpl_id,
        "allowed_name_suffix": "corp.example.com",
    })
    check("an ACME profile without a key id is refused", r.status_code == 400, f"HTTP {r.status_code}")

    r = http.post("/api/enrollment-profiles", json={
        "name": "Web servers", "protocol": "acme", "ca_id": inter["id"], "template_id": tpl_id,
        "username": "web-eab", "allowed_name_suffix": "corp.example.com",
    })
    check("an ACME profile can be created", r.status_code == 201, r.text[:200])
    secret = r.json()["secret"]
    check("wildcards are off by default", r.json()["allow_wildcard"] is False, str(r.json().get("allow_wildcard")))

    print("\n── account registration ──")
    client = AcmeClient(http, base)
    r = client.post("/acme/new-account", {"contact": ["mailto:ops@example.com"]}, use_jwk=True)
    check("registration without external account binding is refused",
          r.status_code == 403, f"HTTP {r.status_code}")
    check("and says binding is required",
          "externalAccountRequired" in r.text, r.text[:200])

    r = client.post("/acme/new-account", {
        "contact": ["mailto:ops@example.com"],
        "externalAccountBinding": client.eab("web-eab", b64u(b"a different key entirely")),
    }, use_jwk=True)
    check("a binding signed with the wrong secret is refused", r.status_code == 403, f"HTTP {r.status_code}")

    r = http.post("/api/enrollment-profiles", json={
        "name": "Bad secret", "protocol": "acme", "ca_id": inter["id"], "template_id": tpl_id,
        "username": "bad-eab", "secret": "not base64url at all!!",
    })
    check("a non-base64url ACME secret is refused at creation", r.status_code == 400, f"HTTP {r.status_code}")

    r = client.post("/acme/new-account", {
        "contact": ["mailto:ops@example.com"],
        "externalAccountBinding": client.eab("web-eab", secret),
    }, use_jwk=True)
    check("a correctly bound account registers", r.status_code == 201, f"HTTP {r.status_code}: {r.text[:200]}")
    client.kid = r.headers.get("location")
    check("and is given an account URL", bool(client.kid), str(r.headers.get("location")))

    print("\n── JWS hardening ──")
    stale = client.fresh_nonce()
    client.post("/acme/new-order", {"identifiers": [{"type": "dns", "value": "a.corp.example.com"}]},
                nonce=stale)
    r = client.post("/acme/new-order", {"identifiers": [{"type": "dns", "value": "b.corp.example.com"}]},
                    nonce=stale)
    check("a reused nonce is refused", r.status_code == 400, f"HTTP {r.status_code}")
    check("as badNonce", "badNonce" in r.text, r.text[:200])

    signed = client.sign(f"{base}/acme/new-order", {"identifiers": []})
    bad_header = json.loads(base64.urlsafe_b64decode(signed["protected"] + "=="))
    bad_header["alg"] = "none"
    signed["protected"] = b64u(json.dumps(bad_header).encode())
    r = http.post("/acme/new-order", json=signed)
    check("alg 'none' is refused", r.status_code == 400, f"HTTP {r.status_code}")

    signed = client.sign(f"{base}/acme/new-order", {"identifiers": []})
    bad_header = json.loads(base64.urlsafe_b64decode(signed["protected"] + "=="))
    bad_header["alg"] = "HS256"
    signed["protected"] = b64u(json.dumps(bad_header).encode())
    r = http.post("/acme/new-order", json=signed)
    check("a MAC algorithm is refused where a signature belongs",
          r.status_code == 400, f"HTTP {r.status_code}")

    r = http.post("/acme/new-order", json=client.sign(f"{base}/acme/revoke-cert", {"identifiers": []}))
    check("a JWS signed for a different endpoint is refused", r.status_code == 403, f"HTTP {r.status_code}")

    print("\n── order policy ──")
    r = client.post("/acme/new-order", {"identifiers": [{"type": "dns", "value": "payroll.example.com"}]})
    check("a name outside the profile's suffix is refused", r.status_code == 403, f"HTTP {r.status_code}")
    check("as rejectedIdentifier", "rejectedIdentifier" in r.text, r.text[:200])

    r = client.post("/acme/new-order", {"identifiers": [{"type": "dns", "value": "notcorp.example.com"}]})
    check("a name that clears a raw endswith but not a label boundary is refused",
          r.status_code == 403, f"HTTP {r.status_code}")

    r = client.post("/acme/new-order", {"identifiers": [{"type": "dns", "value": "*.corp.example.com"}]})
    check("a wildcard is refused on a profile that has not opted in",
          r.status_code == 403, f"HTTP {r.status_code}")
    check("and says so", "wildcard" in r.text.lower(), r.text[:200])

    print("\n── a full order ──")
    name = "www.corp.example.com"
    r = client.post("/acme/new-order", {"identifiers": [{"type": "dns", "value": name}]})
    check("an order is accepted", r.status_code == 201, f"HTTP {r.status_code}: {r.text[:200]}")
    order_url = r.headers["location"]
    order = r.json()
    check("it starts pending", order["status"] == "pending", order["status"])

    authz_url = order["authorizations"][0]
    r = client.post("/acme" + authz_url.split("/acme", 1)[1], None)
    check("the authorization fetches POST-as-GET", r.status_code == 200, f"HTTP {r.status_code}")
    authz = r.json()
    http_challenge = next(c for c in authz["challenges"] if c["type"] == "http-01")
    check("it offers http-01", bool(http_challenge["token"]), str(authz["challenges"]))

    expected_key_auth = f"{http_challenge['token']}.{client.thumbprint()}"
    served: dict = {"value": "the wrong thing entirely"}

    def fake_fetch(identifier, token, key_authorization):
        if served["value"] != key_authorization:
            raise acme_validation.ValidationFailed(
                "the challenge response did not match the expected key authorization")

    real_validate = acme_validation.validate_http_01
    acme_validation.validate_http_01 = fake_fetch
    try:
        chall_path = "/acme" + http_challenge["url"].split("/acme", 1)[1]
        r = client.post(chall_path, {})
        check("a challenge serving the wrong content fails", r.json()["status"] == "invalid",
              str(r.json().get("status")))

        # A fresh order, now answering correctly.
        r = client.post("/acme/new-order", {"identifiers": [{"type": "dns", "value": name}]})
        order_url = r.headers["location"]
        authz_url = r.json()["authorizations"][0]
        r = client.post("/acme" + authz_url.split("/acme", 1)[1], None)
        http_challenge = next(c for c in r.json()["challenges"] if c["type"] == "http-01")
        served["value"] = f"{http_challenge['token']}.{client.thumbprint()}"

        chall_path = "/acme" + http_challenge["url"].split("/acme", 1)[1]
        r = client.post(chall_path, {})
        check("a correctly served challenge validates", r.json()["status"] == "valid",
              str(r.json().get("status")))

        r = client.post("/acme" + order_url.split("/acme", 1)[1], None)
        check("the order becomes ready", r.json()["status"] == "ready", r.json()["status"])
        finalize_url = r.json()["finalize"]

        print("\n── finalize ──")
        der, _key = order_csr(["elsewhere.corp.example.com"])
        r = client.post("/acme" + finalize_url.split("/acme", 1)[1], {"csr": b64u(der)})
        check("a CSR naming an identifier the order did not authorize is refused",
              r.status_code == 400, f"HTTP {r.status_code}")
        check("as badCSR", "badCSR" in r.text, r.text[:200])

        # That refusal invalidated nothing, so the order is still finalizable.
        der, _key = order_csr([name])
        r = client.post("/acme" + finalize_url.split("/acme", 1)[1], {"csr": b64u(der)})
        check("the matching CSR finalizes", r.status_code == 200, f"HTTP {r.status_code}: {r.text[:200]}")
        check("and the order is valid", r.json()["status"] == "valid", r.json()["status"])
        cert_url = r.json().get("certificate")
        check("with a certificate URL", bool(cert_url), str(r.json()))

        print("\n── download ──")
        r = client.post("/acme" + cert_url.split("/acme", 1)[1], None)
        check("the chain downloads", r.status_code == 200, f"HTTP {r.status_code}")
        check("as a PEM chain",
              "application/pem-certificate-chain" in r.headers.get("content-type", ""),
              r.headers.get("content-type", ""))
        chain = [c for c in r.text.split("-----END CERTIFICATE-----") if "BEGIN" in c]
        check("carrying the leaf and its issuers, not just the leaf", len(chain) >= 2, str(len(chain)))

        leaf = x509.load_pem_x509_certificate(r.text.encode())
        check("issued for the ordered name",
              leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == name)
        check("by the profile's CA", "ACME Intermediate" in leaf.issuer.rfc4514_string(),
              leaf.issuer.rfc4514_string())
        cdp = leaf.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        check("with a CRL distribution point like any other issuance", cdp is not None)

        row = sqlite3.connect(str(DB)).execute(
            "SELECT source, private_key_enc, acme_order_id FROM certificates "
            "WHERE common_name = ? ORDER BY id DESC LIMIT 1", (name,)).fetchone()
        check("it lands in the inventory as enrolled", row[0] == "enrolled", str(row[0]))
        check("pktCert holds no private key — the client kept it", not row[1], repr(row[1])[:30])
        check("linked to the order that produced it", row[2] is not None, str(row[2]))

        print("\n── renewal supersedes rather than duplicating ──")
        r = client.post("/acme/new-order", {"identifiers": [{"type": "dns", "value": name}]})
        order_url = r.headers["location"]
        authz_url = r.json()["authorizations"][0]
        r = client.post("/acme" + authz_url.split("/acme", 1)[1], None)
        http_challenge = next(c for c in r.json()["challenges"] if c["type"] == "http-01")
        served["value"] = f"{http_challenge['token']}.{client.thumbprint()}"
        client.post("/acme" + http_challenge["url"].split("/acme", 1)[1], {})
        r = client.post("/acme" + order_url.split("/acme", 1)[1], None)
        der, _key = order_csr([name])
        r = client.post("/acme" + r.json()["finalize"].split("/acme", 1)[1], {"csr": b64u(der)})
        check("a second order for the same name issues again", r.status_code == 200,
              f"HTTP {r.status_code}: {r.text[:200]}")

        rows = sqlite3.connect(str(DB)).execute(
            "SELECT id, status, renewed_to_id FROM certificates WHERE common_name = ? ORDER BY id",
            (name,)).fetchall()
        check("the previous generation is marked superseded",
              any(x[1] == "superseded" for x in rows), str(rows))
        check("and links forward to its replacement",
              any(x[2] is not None for x in rows), str(rows))
    finally:
        acme_validation.validate_http_01 = real_validate

    print("\n── revocation ──")
    cert_der = leaf.public_bytes(serialization.Encoding.DER)
    stranger = AcmeClient(http, base)
    r = stranger.post("/acme/new-account", {
        "externalAccountBinding": stranger.eab("web-eab", secret)}, use_jwk=True)
    stranger.kid = r.headers.get("location")
    r = stranger.post("/acme/revoke-cert", {"certificate": b64u(cert_der)})
    check("an account that did not order the certificate cannot revoke it",
          r.status_code == 403, f"HTTP {r.status_code}")

    r = client.post("/acme/revoke-cert", {"certificate": b64u(cert_der), "reason": 1})
    check("the ordering account can revoke it", r.status_code == 200, f"HTTP {r.status_code}: {r.text[:200]}")
    row = sqlite3.connect(str(DB)).execute(
        "SELECT status FROM certificates WHERE id = ?", (rows[0][0],)).fetchone()
    check("and the inventory records the revocation", row[0] == "revoked", str(row[0]))

    print("\n── validation address rules ──")
    # 169.254.169.254 is the case that matters: link-local is where cloud
    # instance metadata lives, and it is the one address worth crossing the
    # network to reach on someone else's behalf. Private ranges stay allowed
    # because validating internal hosts is the entire point.
    for address, allowed in [("10.0.0.5", True), ("192.168.1.20", True), ("127.0.0.1", True),
                             ("169.254.169.254", False), ("0.0.0.0", False)]:
        try:
            acme_validation._check_address(address)
            got = True
        except acme_validation.ValidationFailed:
            got = False
        check(f"{address} is {'usable' if allowed else 'refused'} for a challenge", got == allowed)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
