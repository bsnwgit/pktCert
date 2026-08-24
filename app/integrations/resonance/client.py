"""
HTTP client for resonance's /embed/session endpoint.

One call, one job: hand resonance the app's key plus the identity of the user
who is asking, and get back a short-lived single-use code the browser can spend
on /embed?c=<code>. The key never leaves the server; resonance never sees the
app's own credentials.

TLS verification is always on — there is no verify=False for browsers loading
embed.js, so switching it off here would only hide a problem every user is about
to hit as a blank frame. What is configurable is which roots to trust, because
httpx verifies against its bundled certifi roots rather than the operating
system store: a certificate signed by an internal CA is trusted by every browser
on the network and still rejected here. Pass ca_bundle to use the system store
instead.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from . import APP_SLUG
from .errors import ResonanceNotConfigured, ResonanceUnreachable, for_status

log = logging.getLogger("pktcert.resonance.client")

# Resonance normalises user.id to 64 chars and drops the whole user object if it
# is missing — so a long login must be truncated here, not silently discarded
# there. Roles are capped at 16 entries of 32 chars on their side; matching the
# caps locally keeps what we send equal to what gets recorded.
MAX_ID_LEN = 64
MAX_ROLE_LEN = 32
MAX_ROLES = 16
# No published cap for name; held to the same 64 as id, which is the length
# resonance is known to normalise an identity field to.
MAX_NAME_LEN = 64

DEFAULT_TIMEOUT = 10.0


def build_user_id(username: str) -> str:
    """'pktcert-alice' — app and login together, so resonance's logs show both.

    The prefix comes from the vendored APP_SLUG constant rather than a setting:
    an admin must not be able to make their install report itself as a different
    pkt app in a shared audit trail.
    """
    return f"{APP_SLUG}-{username}"[:MAX_ID_LEN]


def _clean_roles(roles: list[str] | None) -> list[str]:
    if not roles:
        return []
    out = [str(r).strip()[:MAX_ROLE_LEN] for r in roles if str(r).strip()]
    return out[:MAX_ROLES]


class ResonanceClient:
    def __init__(self, base_url: str, key: str, *, timeout: float = DEFAULT_TIMEOUT,
                 ca_bundle: str = ""):
        self.base_url = (base_url or "").rstrip("/")
        self.key = (key or "").strip()
        self.timeout = timeout
        self.ca_bundle = (ca_bundle or "").strip()

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.key)

    async def create_session(self, username: str, roles: list[str] | None = None) -> dict[str, Any]:
        """POST /embed/session. Returns resonance's 200 body verbatim:
        code, src, code_expires_in, expires_in, parts, cap.

        The full body is passed through rather than reduced to the code, because
        the Settings panel renders what the key actually grants — ask/mic/speak,
        the rate limits, the session TTL — from a real call instead of asking an
        admin to retype it from the resonance side.
        """
        if not self.configured:
            raise ResonanceNotConfigured()

        # id / name / roles, matching resonance's reference implementation. The
        # id is prefixed so a shared audit trail shows which pkt app is calling;
        # name is the bare login, because that is what a person reading
        # resonance's own records expects to see next to it. An app with no
        # separate display-name field sends the two differing only by the prefix.
        payload = {
            "key": self.key,
            "user": {
                "id": build_user_id(username),
                "name": (username or "").strip()[:MAX_NAME_LEN],
                "roles": _clean_roles(roles),
            },
        }

        try:
            verify = self.ca_bundle or True
            async with httpx.AsyncClient(timeout=self.timeout, verify=verify) as client:
                resp = await client.post(f"{self.base_url}/embed/session", json=payload)
        except httpx.TimeoutException as exc:
            raise ResonanceUnreachable(f"timed out after {self.timeout}s") from exc
        except httpx.ConnectError as exc:
            # httpx folds name resolution, refused connections and certificate
            # failures into one exception type. They have completely different
            # fixes, and the DNS one is easy to miss because the browser resolves
            # names this host cannot — an internal domain plus a public resolver
            # on the server makes every key look wrong.
            text = str(exc).lower()
            if "name or service not known" in text or "nodename nor servname" in text \
                    or "temporary failure in name resolution" in text or "getaddrinfo" in text:
                admin_message = (
                    "Could not resolve the resonance server's name from this host. "
                    "The browser resolving it is not enough — this app calls resonance "
                    "directly. Check this server's DNS, or add a hosts entry."
                )
            elif "certificate" in text or "ssl" in text or "tls" in text:
                admin_message = (
                    "Reached the resonance server, but its certificate was not trusted "
                    "by this host."
                )
            else:
                admin_message = (
                    "Could not reach the resonance server — the address resolves, but "
                    "nothing accepted a connection there."
                )
            raise ResonanceUnreachable(f"{exc}", admin_message=admin_message) from exc
        except httpx.HTTPError as exc:
            raise ResonanceUnreachable(str(exc)) from exc

        if resp.status_code != 200:
            detail = ""
            try:
                detail = (resp.json() or {}).get("error", "")
            except Exception:
                detail = (resp.text or "")[:200]
            raise for_status(resp.status_code, detail)

        try:
            body = resp.json()
        except Exception as exc:
            raise ResonanceUnreachable("resonance returned a non-JSON 200") from exc

        if not body.get("code"):
            raise ResonanceUnreachable("resonance returned no code")

        return body
