"""
app/cert/acme_jws.py
---------------------
The JWS layer under the ACME server (RFC 8555 §6), plus nonce handling.

Every ACME request except the directory, the nonce endpoint and renewal
information is a signed JWS, and this module is the only thing standing between
a request and the CA's signing key. It is written directly on `cryptography`
rather than through `python-jose`: ACME uses flattened JSON serialisation with
protected headers (`nonce`, `url`, `kid`) that a JWT library has no notion of,
and a signature-verification boundary is the last place to be bending a library
into a shape it wasn't built for.

Three checks here matter more than the signature itself, because a valid
signature over the wrong thing is still valid:

  * `url` must match the endpoint actually being requested — otherwise a
    request signed for one endpoint can be replayed against another
  * the nonce must be one this server issued and has not seen used
  * exactly one of `jwk` and `kid` may be present — both, or neither, is
    malformed, and accepting both invites confusion over which key was checked
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Optional

import aiosqlite
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# How long an unused nonce stays good. Long enough for a slow client to finish
# a request, short enough that the table stays small.
NONCE_TTL_SECONDS = 3600

# Signature algorithms accepted on the outer JWS. HS* is deliberately absent:
# a MAC where a signature belongs means the sender is claiming a key it shares
# with us, which for an account key it never does. 'none' likewise.
_ALGS: dict[str, tuple[str, object]] = {
    "RS256": ("rsa", hashes.SHA256()),
    "RS384": ("rsa", hashes.SHA384()),
    "RS512": ("rsa", hashes.SHA512()),
    "ES256": ("ec", hashes.SHA256()),
    "ES384": ("ec", hashes.SHA384()),
    "ES512": ("ec", hashes.SHA512()),
}

_EC_CURVES = {
    "P-256": (ec.SECP256R1, 32),
    "P-384": (ec.SECP384R1, 48),
    "P-521": (ec.SECP521R1, 66),
}


# The HTTP status each error kind carries when the raising code doesn't say.
# Kept here rather than repeated at every raise: an authorisation failure
# answered with 400 reads to a client as "your request was malformed, fix it
# and retry", which is the opposite of what it should do.
_DEFAULT_STATUS = {
    "unauthorized": 403,
    "rejectedIdentifier": 403,
    "externalAccountRequired": 403,
    "orderNotReady": 403,
    "rateLimited": 429,
}


class AcmeError(Exception):
    """An ACME problem document (RFC 8555 §6.7). `kind` is the bare error name;
    the router prefixes it with the urn namespace."""

    def __init__(self, kind: str, detail: str, status: Optional[int] = None) -> None:
        super().__init__(detail)
        self.kind = kind
        self.detail = detail
        self.status = status if status is not None else _DEFAULT_STATUS.get(kind, 400)


# ── base64url ────────────────────────────────────────────────────────────────

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(value: str) -> bytes:
    """Decode unpadded base64url. ACME never pads; clients occasionally do."""
    if not isinstance(value, str):
        raise AcmeError("malformed", "expected a base64url string")
    padding_needed = (-len(value)) % 4
    try:
        return base64.urlsafe_b64decode(value + ("=" * padding_needed))
    except (ValueError, TypeError):
        raise AcmeError("malformed", "value is not valid base64url")


def _int_to_bytes(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


# ── JWK ──────────────────────────────────────────────────────────────────────

def public_key_from_jwk(jwk: dict):
    """Rebuild a public key from its JWK. Raises AcmeError on anything we don't
    accept, rather than returning something half-understood."""
    if not isinstance(jwk, dict):
        raise AcmeError("malformed", "jwk must be an object")
    kty = jwk.get("kty")
    if kty == "RSA":
        try:
            n = int.from_bytes(b64u_decode(jwk["n"]), "big")
            e = int.from_bytes(b64u_decode(jwk["e"]), "big")
        except KeyError:
            raise AcmeError("malformed", "RSA jwk needs both 'n' and 'e'")
        key = rsa.RSAPublicNumbers(e, n).public_key()
        if key.key_size < 2048:
            raise AcmeError("badPublicKey", f"account RSA key is {key.key_size}-bit; the minimum is 2048")
        return key
    if kty == "EC":
        curve_entry = _EC_CURVES.get(jwk.get("crv", ""))
        if not curve_entry:
            raise AcmeError("badPublicKey", f"unsupported EC curve: {jwk.get('crv')!r}")
        curve_cls, _size = curve_entry
        try:
            x = int.from_bytes(b64u_decode(jwk["x"]), "big")
            y = int.from_bytes(b64u_decode(jwk["y"]), "big")
        except KeyError:
            raise AcmeError("malformed", "EC jwk needs both 'x' and 'y'")
        return ec.EllipticCurvePublicNumbers(x, y, curve_cls()).public_key()
    raise AcmeError("badPublicKey", f"unsupported key type: {kty!r}")


def jwk_from_public_key(key) -> dict:
    if isinstance(key, rsa.RSAPublicKey):
        numbers = key.public_numbers()
        size = (key.key_size + 7) // 8
        return {
            "kty": "RSA",
            "n": b64u(_int_to_bytes(numbers.n, size)),
            "e": b64u(_int_to_bytes(numbers.e, (numbers.e.bit_length() + 7) // 8)),
        }
    if isinstance(key, ec.EllipticCurvePublicKey):
        numbers = key.public_numbers()
        for name, (curve_cls, size) in _EC_CURVES.items():
            if isinstance(key.curve, curve_cls):
                return {
                    "kty": "EC", "crv": name,
                    "x": b64u(_int_to_bytes(numbers.x, size)),
                    "y": b64u(_int_to_bytes(numbers.y, size)),
                }
    raise AcmeError("badPublicKey", "unsupported key type")


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint — the canonical identity of an account key.

    Only the required members, lexicographically ordered, no whitespace. Any
    other serialisation gives a different digest for the same key, which shows
    up as a client that can register but never authenticate again.
    """
    kty = jwk.get("kty")
    if kty == "RSA":
        required = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif kty == "EC":
        required = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    else:
        raise AcmeError("badPublicKey", f"unsupported key type: {kty!r}")
    canonical = json.dumps(required, sort_keys=True, separators=(",", ":")).encode()
    return b64u(hashlib.sha256(canonical).digest())


# ── the JWS itself ───────────────────────────────────────────────────────────

@dataclass
class Jws:
    protected_b64: str
    payload_b64: str
    signature: bytes
    header: dict
    payload: Optional[dict]     # None for POST-as-GET, whose payload is ""
    alg: str
    nonce: str
    url: str
    jwk: Optional[dict]
    kid: Optional[str]


def parse_jws(body: dict, expected_url: str) -> Jws:
    """Structural checks on a flattened JWS. Does not verify the signature —
    the key for that may need a database lookup by kid."""
    if not isinstance(body, dict):
        raise AcmeError("malformed", "request body must be a JSON object")
    for field in ("protected", "payload", "signature"):
        if field not in body or not isinstance(body[field], str):
            raise AcmeError("malformed", f"JWS is missing '{field}'")

    try:
        header = json.loads(b64u_decode(body["protected"]))
    except ValueError:
        raise AcmeError("malformed", "protected header is not JSON")
    if not isinstance(header, dict):
        raise AcmeError("malformed", "protected header must be an object")

    alg = header.get("alg")
    if alg not in _ALGS:
        # Naming the accepted set is a genuine aid to a client author and
        # reveals nothing: the list is in the RFC.
        raise AcmeError("badSignatureAlgorithm",
                        f"unsupported signature algorithm {alg!r}; accepted: {', '.join(sorted(_ALGS))}")

    jwk, kid = header.get("jwk"), header.get("kid")
    if (jwk is None) == (kid is None):
        raise AcmeError("malformed", "the protected header needs exactly one of 'jwk' and 'kid'")

    url = header.get("url")
    if not isinstance(url, str) or not url:
        raise AcmeError("malformed", "the protected header needs a 'url'")
    # Compared on path rather than the whole URL: the client sees whatever
    # scheme and host the directory advertised, which is not necessarily how
    # the request reaches this process once a reverse proxy is involved.
    if url.split("?")[0].rstrip("/").split("//")[-1].partition("/")[2] != \
            expected_url.rstrip("/").split("//")[-1].partition("/")[2]:
        raise AcmeError("unauthorized",
                        "the JWS 'url' header does not match the endpoint it was sent to")

    nonce = header.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise AcmeError("badNonce", "the protected header needs a 'nonce'")

    payload: Optional[dict] = None
    if body["payload"] != "":
        try:
            payload = json.loads(b64u_decode(body["payload"]))
        except ValueError:
            raise AcmeError("malformed", "payload is not JSON")
        if not isinstance(payload, dict):
            raise AcmeError("malformed", "payload must be a JSON object")

    return Jws(
        protected_b64=body["protected"], payload_b64=body["payload"],
        signature=b64u_decode(body["signature"]), header=header, payload=payload,
        alg=alg, nonce=nonce, url=url, jwk=jwk, kid=kid,
    )


def verify_signature(jws: Jws, public_key) -> None:
    """Verify the JWS signature, or raise. The signing input is the two
    base64url segments joined by a dot, exactly as received — re-encoding
    either of them would verify something the client never signed."""
    signing_input = f"{jws.protected_b64}.{jws.payload_b64}".encode()
    kind, algorithm = _ALGS[jws.alg]

    try:
        if kind == "rsa":
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise AcmeError("malformed", f"{jws.alg} does not match the account key type")
            public_key.verify(jws.signature, signing_input, padding.PKCS1v15(), algorithm)
        else:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise AcmeError("malformed", f"{jws.alg} does not match the account key type")
            # JWS carries r and s as fixed-width halves; `cryptography` wants
            # them DER-encoded.
            half = len(jws.signature) // 2
            if half == 0 or len(jws.signature) % 2:
                raise InvalidSignature()
            r = int.from_bytes(jws.signature[:half], "big")
            s = int.from_bytes(jws.signature[half:], "big")
            public_key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(algorithm))
    except InvalidSignature:
        raise AcmeError("unauthorized", "JWS signature verification failed")


def verify_eab(eab: dict, account_jwk: dict, mac_key: bytes, expected_url: str) -> None:
    """External Account Binding (RFC 8555 §7.3.4).

    The inner JWS is MAC'd with a key issued out of band — here, the enrolment
    profile's secret — over the account key being registered. That is what ties
    a new ACME account to a profile, and therefore to a CA, a template and a
    name constraint. Without it the server is an open CA for anything that can
    reach it.
    """
    if not isinstance(eab, dict):
        raise AcmeError("externalAccountRequired", "externalAccountBinding must be an object")
    for field in ("protected", "payload", "signature"):
        if field not in eab or not isinstance(eab[field], str):
            raise AcmeError("malformed", f"externalAccountBinding is missing '{field}'")

    try:
        header = json.loads(b64u_decode(eab["protected"]))
    except ValueError:
        raise AcmeError("malformed", "externalAccountBinding protected header is not JSON")
    if header.get("alg") != "HS256":
        raise AcmeError("malformed", "externalAccountBinding must use HS256")
    if header.get("url", "").rstrip("/").split("//")[-1].partition("/")[2] != \
            expected_url.rstrip("/").split("//")[-1].partition("/")[2]:
        raise AcmeError("unauthorized", "externalAccountBinding 'url' does not match this endpoint")

    expected = hmac.new(
        mac_key, f"{eab['protected']}.{eab['payload']}".encode(), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(expected, b64u_decode(eab["signature"])):
        raise AcmeError("unauthorized", "externalAccountBinding signature does not verify")

    # The payload is the account key being bound. If it is any other key, the
    # binding proves possession of the secret but says nothing about the key
    # actually registering — which is the whole point of the check.
    try:
        bound = json.loads(b64u_decode(eab["payload"]))
    except ValueError:
        raise AcmeError("malformed", "externalAccountBinding payload is not JSON")
    if jwk_thumbprint(bound) != jwk_thumbprint(account_jwk):
        raise AcmeError("unauthorized",
                        "externalAccountBinding is bound to a different key than the one registering")


def key_authorization(token: str, account_jwk: dict) -> str:
    """`<token>.<thumbprint>` — what a challenge response must contain."""
    return f"{token}.{jwk_thumbprint(account_jwk)}"


def dns_challenge_value(token: str, account_jwk: dict) -> str:
    """The TXT record body for dns-01: base64url(SHA256(key authorization))."""
    return b64u(hashlib.sha256(key_authorization(token, account_jwk).encode()).digest())


# ── nonces ───────────────────────────────────────────────────────────────────

async def issue_nonce(db: aiosqlite.Connection) -> str:
    nonce = b64u(secrets.token_bytes(24))
    await db.execute(
        "INSERT INTO acme_nonces (nonce, expires_at) VALUES (?, datetime('now', ?))",
        (nonce, f"+{NONCE_TTL_SECONDS} seconds"),
    )
    await db.commit()
    return nonce


async def consume_nonce(db: aiosqlite.Connection, nonce: str) -> None:
    """Spend a nonce, or raise badNonce.

    The DELETE is the check: it either removed a row or it didn't, so two
    requests racing on the same nonce cannot both succeed. Checking first and
    deleting after would let them.
    """
    cur = await db.execute(
        "DELETE FROM acme_nonces WHERE nonce = ? AND expires_at > datetime('now')", (nonce,)
    )
    await db.commit()
    if cur.rowcount != 1:
        # badNonce is a normal part of the protocol — every client retries on
        # it with a fresh nonce — so this is not an error worth logging loudly.
        raise AcmeError("badNonce", "the nonce was unrecognised, expired or already used")


async def purge_expired_nonces(db: aiosqlite.Connection) -> int:
    cur = await db.execute("DELETE FROM acme_nonces WHERE expires_at <= datetime('now')")
    await db.commit()
    return cur.rowcount or 0
