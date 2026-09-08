"""
app/cert/dns/cloudflare.py
---------------------------
Cloudflare DNS, for dns-01.

Needs an API token scoped Zone:DNS:Edit on the zones being certified.
Cloudflare's older global API key would also work and is deliberately not
supported: it authorises everything on the account, and a certificate robot
has no business holding that.

Propagation is checked over DNS-over-HTTPS rather than a resolver library, so
this costs no dependency beyond httpx. It also sidesteps the usual failure
where the local resolver holds a stale negative answer while the CA, asking
the authoritative servers, sees something else.
"""
from __future__ import annotations

import logging

import httpx

from app.cert.dns.base import DnsError, DnsProvider, await_propagation, challenge_name

log = logging.getLogger("pktcert.dns.cloudflare")

_API = "https://api.cloudflare.com/client/v4"
_DOH = "https://cloudflare-dns.com/dns-query"
_TIMEOUT = 20.0
# Created and deleted inside one order, so it wants the shortest TTL
# Cloudflare accepts rather than anything cacheable.
_TXT_TTL = 60


async def _resolve_txt(record_name: str) -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            response = await client.get(
                _DOH, params={"name": record_name, "type": "TXT"},
                headers={"Accept": "application/dns-json"},
            )
            payload = response.json()
    except (httpx.HTTPError, ValueError):
        return []
    # Type 16 is TXT; DoH returns the data quoted. An answer may also be a
    # CNAME chain, which is how delegated challenges work, so anything that
    # isn't TXT is skipped rather than treated as a failure.
    return [str(answer.get("data", "")).strip('"')
            for answer in payload.get("Answer", []) if answer.get("type") == 16]


class CloudflareProvider(DnsProvider):
    name = "cloudflare"
    label = "Cloudflare"
    credential_help = (
        "An API token with Zone:DNS:Edit on the zones you want certificates for — "
        "use the 'Edit zone DNS' template. Create it under Manage account → Account "
        "API tokens (preferred, it survives the creator leaving) or My Profile → API "
        "Tokens. The legacy global API key is not accepted — it authorises the whole "
        "account and cannot be scoped."
    )

    def __init__(self, credential: str) -> None:
        super().__init__(credential)
        self._zones: dict[str, str] = {}

    def _check(self, payload: dict, what: str):
        if not payload.get("success"):
            errors = payload.get("errors") or []
            detail = "; ".join(str(e.get("message", e)) for e in errors) or "no reason given"
            raise DnsError(f"Cloudflare refused to {what}: {detail}")
        return payload.get("result")

    async def _request(self, method: str, path: str, **kwargs) -> dict:
        headers = {"Authorization": f"Bearer {self.credential}", "Content-Type": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                response = await client.request(method, f"{_API}{path}", headers=headers, **kwargs)
        except httpx.HTTPError as e:
            raise DnsError(f"Cloudflare was unreachable ({type(e).__name__})")
        if response.status_code in (401, 403):
            raise DnsError("Cloudflare rejected the API token — check it has Zone:DNS:Edit on this zone")
        try:
            return response.json()
        except ValueError:
            raise DnsError(f"Cloudflare returned an unreadable response (HTTP {response.status_code})")

    async def _zone_for(self, identifier: str) -> str:
        """The zone id owning this name.

        Walks up the labels rather than assuming the last two: a name under
        `example.co.uk` belongs to a three-label zone, and guessing wrongly
        produces a 'zone not found' that reads like a permissions problem.
        """
        base = identifier.lstrip("*.")
        if base in self._zones:
            return self._zones[base]
        labels = base.split(".")
        for start in range(len(labels) - 1):
            candidate = ".".join(labels[start:])
            result = self._check(await self._request("GET", "/zones", params={"name": candidate}),
                                 f"look up the zone {candidate}")
            if result:
                self._zones[base] = result[0]["id"]
                return result[0]["id"]
        raise DnsError(f"no Cloudflare zone found for '{base}' — is it in this account?")

    async def create_txt(self, identifier: str, value: str) -> str:
        zone_id = await self._zone_for(identifier)
        record_name = challenge_name(identifier)

        # Clear anything already sitting at the challenge name. A retried order
        # would otherwise stack a second TXT record, and the CA has to see its
        # own value among whatever else is published.
        existing = self._check(
            await self._request("GET", f"/zones/{zone_id}/dns_records",
                                params={"type": "TXT", "name": record_name}),
            f"list existing records at {record_name}",
        )
        for stale in existing or []:
            await self.delete_txt(identifier, stale["id"])

        result = self._check(
            await self._request("POST", f"/zones/{zone_id}/dns_records",
                                json={"type": "TXT", "name": record_name,
                                      "content": value, "ttl": _TXT_TTL}),
            f"create the TXT record {record_name}",
        )
        await await_propagation(_resolve_txt, record_name, value)
        return result["id"]

    async def delete_txt(self, identifier: str, handle: str) -> None:
        try:
            zone_id = await self._zone_for(identifier)
            await self._request("DELETE", f"/zones/{zone_id}/dns_records/{handle}")
        except DnsError as e:
            log.warning("Could not remove challenge record %s: %s", handle, e)

    async def check(self) -> str:
        result = self._check(await self._request("GET", "/zones", params={"per_page": 50}),
                             "list the zones this token can reach")
        zones = [z["name"] for z in (result or [])]
        if not zones:
            raise DnsError("the token is valid but can reach no zones — check its zone scope")
        return f"{len(zones)} zone(s): {', '.join(sorted(zones)[:10])}"
