"""
app/cert/acme_validation.py
----------------------------
Challenge validation for the ACME server — the part that actually goes and
checks a client controls the name it is asking for.

`http-01` fetches `http://<identifier>/.well-known/acme-challenge/<token>` on
port 80 and expects the key authorization back. That works here in a way it
never does publicly: Let's Encrypt cannot reach a host on a private range,
which is why public ACME on internal names is impossible and everyone falls
back to DNS. pktCert is already inside the network, so it can simply connect.

That also makes this the one place in the app that issues outbound HTTP to a
host named by whoever holds an enrolment secret, and reports the result. The
containment:

  * the address is resolved and checked first, then connected to *by address*
    with a Host header — so a name that resolves twice cannot resolve to
    something allowed and then to something else
  * link-local is refused, which is where cloud instance metadata lives.
    RFC 1918 is deliberately allowed: internal hosts are the entire point
  * port 80 and a fixed path only — there is no shape of request here that
    reaches an arbitrary URL
  * the body read is bounded, and never appears in an error. A validation
    failure says what was expected, not what was returned, because the latter
    turns a challenge into a way to read internal endpoints
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Optional

import httpx

log = logging.getLogger("pktcert.acme.validation")

_TIMEOUT_SECONDS = 10.0
_MAX_BODY_BYTES = 4096
_MAX_REDIRECTS = 2
# RFC 8555 §8.3 fixes http-01 at port 80. A challenge answered anywhere else
# proves control of a service, not of the name.
_CHALLENGE_PORT = 80
_CHALLENGE_PATH = "/.well-known/acme-challenge/"


class ValidationFailed(Exception):
    """Why a challenge did not validate. The message is returned to the client
    in the challenge's error field, so it must describe the expectation rather
    than the response."""


def _check_address(raw: str) -> ipaddress._BaseAddress:
    """Refuse addresses a challenge has no business being served from.

    Private and loopback ranges stay allowed — an internal CA validating
    internal hosts is the entire use case, and refusing them would leave only
    dns-01, which is exactly the corner public ACME is stuck in.
    """
    address = ipaddress.ip_address(raw)
    if address.is_link_local:
        # 169.254.0.0/16 and fe80::/10. Cloud instance metadata lives at
        # 169.254.169.254, and it is the one address worth crossing the network
        # to reach on someone else's behalf.
        raise ValidationFailed("the name resolves to a link-local address, which is not validatable")
    if address.is_multicast or address.is_reserved or address.is_unspecified:
        raise ValidationFailed("the name resolves to an address that cannot host a challenge")
    return address


def _resolve(host: str) -> list[str]:
    """Every address the identifier resolves to that we are willing to use."""
    try:
        infos = socket.getaddrinfo(host, _CHALLENGE_PORT, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise ValidationFailed(f"the name did not resolve ({e.strerror or 'DNS failure'})")

    allowed, refusals = [], []
    for info in infos:
        raw = info[4][0]
        try:
            _check_address(raw)
        except ValidationFailed as e:
            refusals.append(str(e))
            continue
        allowed.append(raw)
    if not allowed:
        raise ValidationFailed(refusals[0] if refusals else "the name did not resolve to a usable address")
    return allowed


def _fetch(address: str, host: str, path: str) -> tuple[int, str, Optional[str]]:
    """One plain HTTP GET to a checked address, carrying the identifier as Host.

    Returns (status, body, location). Connecting by address rather than by name
    is what makes the check above meaningful — resolving once for the check and
    again for the connection would let the second answer differ from the first.
    """
    literal = f"[{address}]" if ":" in address else address
    url = f"http://{literal}:{_CHALLENGE_PORT}{path}"
    try:
        with httpx.Client(timeout=_TIMEOUT_SECONDS, follow_redirects=False) as client:
            response = client.get(url, headers={"Host": host, "Accept": "*/*"})
            body = response.read()[:_MAX_BODY_BYTES].decode("utf-8", "replace")
            return response.status_code, body, response.headers.get("location")
    except httpx.HTTPError as e:
        raise ValidationFailed(f"the challenge could not be fetched ({type(e).__name__})")


def validate_http_01(identifier: str, token: str, key_authorization: str) -> None:
    """Fetch and check one http-01 challenge. Returns on success, raises
    ValidationFailed with a client-safe reason otherwise."""
    host = identifier
    path = _CHALLENGE_PATH + token

    for hop in range(_MAX_REDIRECTS + 1):
        address = _resolve(host)[0]
        status, body, location = _fetch(address, host, path)

        if status in (301, 302, 307, 308) and location and hop < _MAX_REDIRECTS:
            # Redirects are permitted by RFC 8555, and are common where port 80
            # only exists to bounce traffic to TLS. Each hop is re-resolved and
            # re-checked; nothing is trusted because the previous hop was fine.
            try:
                target = httpx.URL(location)
            except httpx.InvalidURL:
                raise ValidationFailed("the challenge redirected to an unusable location")
            if target.scheme and target.scheme not in ("http", "https"):
                raise ValidationFailed(f"the challenge redirected to an unsupported scheme ({target.scheme})")
            host = target.host or host
            path = target.path or path
            continue

        if status != 200:
            raise ValidationFailed(f"the challenge URL returned HTTP {status}; 200 was expected")

        # Trailing whitespace is explicitly tolerated: plenty of clients write
        # the token with a newline, and refusing that is a support ticket, not
        # a security control.
        if body.strip() != key_authorization:
            raise ValidationFailed(
                "the challenge response did not match the expected key authorization"
            )
        return

    raise ValidationFailed("the challenge redirected too many times")
