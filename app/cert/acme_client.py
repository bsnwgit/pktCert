"""
app/cert/acme_client.py
------------------------
pktCert as an ACME *client* — obtaining certificates from a publicly-trusted
CA, so that the result is trusted natively by anyone, with nothing to install.

This is the mirror of app/api/acme.py. That serves the protocol so internal
hosts can enrol against the internal CA; this speaks it outward so pktCert can
hold certificates from a CA that is already in every browser and OS trust
store. They share a wire format and nothing else — an internal root cannot be
publicly trusted, and no protocol changes that.

Nothing here is specific to one CA. The directory URL is configuration:
Let's Encrypt staging and production, ZeroSSL, Google Trust Services, Buypass
and an internal step-ca all differ only by that URL and by whether they demand
external account binding, which is why EAB is carried as optional fields
rather than assumed absent.

Validation is dns-01 through a pluggable provider (app/cert/dns/), because it
is the only challenge that works for a host the public internet cannot reach,
and the only one that can produce a wildcard.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from app.cert import dns as dns_registry
from app.cert import x509_utils
from app.cert.acme_jws import b64u, dns_challenge_value, jwk_from_public_key

log = logging.getLogger("pktcert.acme.client")

_TIMEOUT = 30.0
# How long to wait for an authorization or order to leave a transitional state.
# The CA does the work asynchronously; a slow validation is normal.
_POLL_TIMEOUT = 180.0
_POLL_INTERVAL = 3.0

_USER_AGENT = "pktCert ACME client"


class AcmeClientError(Exception):
    """A public-CA operation failed. The message is shown to an operator, so it
    carries the CA's own problem detail where there is one — that is usually
    the only place the actual reason appears."""


def _problem(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    detail = payload.get("detail") or payload.get("type") or f"HTTP {response.status_code}"
    # Sub-problems carry the per-identifier reason, which is where "this name
    # is not allowed" actually lives on a multi-name order.
    for sub in payload.get("subproblems") or []:
        name = (sub.get("identifier") or {}).get("value", "")
        detail += f" [{name}: {sub.get('detail', '')}]"
    return str(detail)


class AcmeClient:
    """One conversation with one CA, on one account key."""

    def __init__(self, directory_url: str, account_key_pem: str,
                 account_url: Optional[str] = None) -> None:
        self.directory_url = directory_url.strip()
        self.account_key = serialization.load_pem_private_key(account_key_pem.encode(), password=None)
        if not isinstance(self.account_key, ec.EllipticCurvePrivateKey):
            raise AcmeClientError("the ACME account key must be an EC key")
        self.account_url = account_url
        self._directory: dict = {}
        self._nonce: Optional[str] = None
        self._http: Optional[httpx.AsyncClient] = None

    # ── plumbing ─────────────────────────────────────────────────────────────

    async def __aenter__(self) -> "AcmeClient":
        self._http = httpx.AsyncClient(timeout=_TIMEOUT, headers={"User-Agent": _USER_AGENT})
        await self._load_directory()
        return self

    async def __aexit__(self, *_exc) -> None:
        if self._http:
            await self._http.aclose()

    async def _load_directory(self) -> None:
        try:
            response = await self._http.get(self.directory_url)
        except httpx.HTTPError as e:
            raise AcmeClientError(f"could not reach the CA directory ({type(e).__name__})")
        if response.status_code != 200:
            raise AcmeClientError(f"the CA directory returned {_problem(response)}")
        self._directory = response.json()

    @property
    def terms_of_service(self) -> str:
        return str((self._directory.get("meta") or {}).get("termsOfService", ""))

    @property
    def external_account_required(self) -> bool:
        return bool((self._directory.get("meta") or {}).get("externalAccountRequired"))

    async def _fresh_nonce(self) -> str:
        if self._nonce:
            nonce, self._nonce = self._nonce, None
            return nonce
        response = await self._http.head(self._directory["newNonce"])
        nonce = response.headers.get("replay-nonce")
        if not nonce:
            raise AcmeClientError("the CA did not issue a nonce")
        return nonce

    def _sign(self, url: str, payload, nonce: str, *, embed_jwk: bool = False) -> dict:
        header = {"alg": "ES256", "nonce": nonce, "url": url}
        if embed_jwk or not self.account_url:
            header["jwk"] = jwk_from_public_key(self.account_key.public_key())
        else:
            header["kid"] = self.account_url
        protected = b64u(json.dumps(header, separators=(",", ":")).encode())
        body = "" if payload is None else b64u(json.dumps(payload, separators=(",", ":")).encode())
        der = self.account_key.sign(f"{protected}.{body}".encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return {"protected": protected, "payload": body, "signature": b64u(signature)}

    async def _post(self, url: str, payload, *, embed_jwk: bool = False,
                    retry_bad_nonce: bool = True) -> httpx.Response:
        """One signed request. `payload=None` is POST-as-GET.

        badNonce is retried once rather than surfaced: it is a normal part of
        the protocol, not a failure, and every CA expects clients to handle it.
        """
        body = self._sign(url, payload, await self._fresh_nonce(), embed_jwk=embed_jwk)
        try:
            response = await self._http.post(
                url, json=body, headers={"Content-Type": "application/jose+json"})
        except httpx.HTTPError as e:
            raise AcmeClientError(f"the CA was unreachable ({type(e).__name__})")

        if "replay-nonce" in response.headers:
            self._nonce = response.headers["replay-nonce"]

        if response.status_code >= 400:
            try:
                kind = response.json().get("type", "")
            except ValueError:
                kind = ""
            if kind.endswith(":badNonce") and retry_bad_nonce:
                return await self._post(url, payload, embed_jwk=embed_jwk, retry_bad_nonce=False)
        return response

    # ── account ──────────────────────────────────────────────────────────────

    async def register(self, contact_emails: list[str], *, eab_kid: str = "",
                       eab_hmac: str = "") -> str:
        """Create or recover the account, returning its URL.

        Re-registering an existing key returns the same account, which is how a
        client recovers its own URL after losing it — so this is safe to call
        again and is not an error path.
        """
        payload: dict = {
            "termsOfServiceAgreed": True,
            "contact": [f"mailto:{e}" for e in contact_emails if e.strip()],
        }
        if eab_kid and eab_hmac:
            payload["externalAccountBinding"] = self._build_eab(eab_kid, eab_hmac)
        elif self.external_account_required:
            raise AcmeClientError(
                "this CA requires external account binding — supply the key id and HMAC key it gave you")

        response = await self._post(self._directory["newAccount"], payload, embed_jwk=True)
        if response.status_code not in (200, 201):
            raise AcmeClientError(f"registration failed: {_problem(response)}")
        self.account_url = response.headers.get("location", self.account_url)
        if not self.account_url:
            raise AcmeClientError("the CA did not return an account URL")
        return self.account_url

    def _build_eab(self, kid: str, hmac_key: str) -> dict:
        import base64
        import hmac as _hmac
        import hashlib

        url = self._directory["newAccount"]
        header = b64u(json.dumps({"alg": "HS256", "kid": kid, "url": url},
                                 separators=(",", ":")).encode())
        payload = b64u(json.dumps(jwk_from_public_key(self.account_key.public_key()),
                                  separators=(",", ":")).encode())
        key = base64.urlsafe_b64decode(hmac_key + "=" * ((-len(hmac_key)) % 4))
        signature = _hmac.new(key, f"{header}.{payload}".encode(), hashlib.sha256).digest()
        return {"protected": header, "payload": payload, "signature": b64u(signature)}

    # ── issuance ─────────────────────────────────────────────────────────────

    async def _poll(self, url: str, done: set[str], what: str) -> dict:
        waited = 0.0
        while waited < _POLL_TIMEOUT:
            response = await self._post(url, None)
            if response.status_code >= 400:
                raise AcmeClientError(f"could not read the {what}: {_problem(response)}")
            payload = response.json()
            if payload.get("status") in done:
                return payload
            await asyncio.sleep(_POLL_INTERVAL)
            waited += _POLL_INTERVAL
        raise AcmeClientError(f"the {what} did not settle within {int(_POLL_TIMEOUT)}s")

    async def obtain(self, identifiers: list[str], provider_name: str, credential: str,
                     key_algorithm: str = "ec", key_size: int = 256) -> tuple[str, str]:
        """Run a full order and return (certificate chain PEM, private key PEM).

        The key is generated here and never leaves pktCert, which is what makes
        these renewable without anyone present — unlike the server side, where
        the client holds the key and pktCert can only notice that it should
        have renewed.
        """
        if not self.account_url:
            raise AcmeClientError("register the account before ordering")

        provider = dns_registry.get_provider(provider_name, credential)

        response = await self._post(self._directory["newOrder"],
                                    {"identifiers": [{"type": "dns", "value": i} for i in identifiers]})
        if response.status_code != 201:
            raise AcmeClientError(f"the CA refused the order: {_problem(response)}")
        order_url = response.headers.get("location", "")
        order = response.json()

        for authz_url in order.get("authorizations", []):
            await self._satisfy(authz_url, provider)

        order = await self._poll(order_url, {"ready", "invalid"}, "order")
        if order["status"] != "ready":
            raise AcmeClientError(f"the order did not become ready: {json.dumps(order.get('error', {}))}")

        leaf_key = x509_utils.generate_private_key(key_algorithm, key_size)
        csr = x509_utils.generate_csr(identifiers[0], identifiers, leaf_key)
        der = csr.public_bytes(serialization.Encoding.DER)

        response = await self._post(order["finalize"], {"csr": b64u(der)})
        if response.status_code >= 400:
            raise AcmeClientError(f"the CA refused the CSR: {_problem(response)}")

        order = await self._poll(order_url, {"valid", "invalid"}, "order")
        if order["status"] != "valid":
            raise AcmeClientError(f"issuance failed: {json.dumps(order.get('error', {}))}")

        response = await self._post(order["certificate"], None)
        if response.status_code != 200:
            raise AcmeClientError(f"could not download the certificate: {_problem(response)}")
        return response.text, x509_utils.key_to_pem(leaf_key, None)

    async def _satisfy(self, authz_url: str, provider) -> None:
        response = await self._post(authz_url, None)
        if response.status_code >= 400:
            raise AcmeClientError(f"could not read the authorization: {_problem(response)}")
        authz = response.json()
        if authz.get("status") == "valid":
            # Authorizations are cached by the CA for a while, so a repeat
            # order for a recently-proved name has nothing to do.
            return

        identifier = authz["identifier"]["value"]
        if authz.get("wildcard"):
            identifier = f"*.{identifier}"

        challenge = next((c for c in authz.get("challenges", []) if c.get("type") == "dns-01"), None)
        if not challenge:
            raise AcmeClientError(
                f"the CA offered no dns-01 challenge for {identifier} — "
                "it is the only challenge pktCert can answer for a name it does not serve")

        value = dns_challenge_value(challenge["token"], jwk_from_public_key(self.account_key.public_key()))
        async with dns_registry.ChallengeRecord(provider, identifier, value):
            response = await self._post(challenge["url"], {})
            if response.status_code >= 400:
                raise AcmeClientError(f"the CA rejected the challenge response: {_problem(response)}")
            authz = await self._poll(authz_url, {"valid", "invalid"}, f"authorization for {identifier}")

        if authz["status"] != "valid":
            reason = ""
            for c in authz.get("challenges", []):
                if c.get("error"):
                    reason = c["error"].get("detail", "")
            raise AcmeClientError(f"{identifier} was not validated: {reason or 'no reason given'}")

    # ── revocation ───────────────────────────────────────────────────────────

    async def revoke(self, certificate_pem: str, reason: int = 0) -> None:
        """Revoke through the account that ordered it."""
        url = self._directory.get("revokeCert")
        if not url:
            raise AcmeClientError("this CA does not advertise a revocation endpoint")
        cert = x509_utils.cert_from_pem(certificate_pem)
        response = await self._post(
            url, {"certificate": b64u(cert.public_bytes(serialization.Encoding.DER)),
                  "reason": int(reason)})
        if response.status_code not in (200, 201):
            # An already-revoked certificate is the desired end state, not a
            # failure worth surfacing as one.
            try:
                if response.json().get("type", "").endswith(":alreadyRevoked"):
                    return
            except ValueError:
                pass
            raise AcmeClientError(f"revocation failed: {_problem(response)}")


def generate_account_key_pem() -> str:
    """A fresh account key. P-256 because every CA accepts ES256, and an
    account key is an identity rather than a performance decision."""
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
