"""
Certificate Transparency log search — crt.sh (free, no key) and Censys
(optional, per-user API key from the Cert Keys tab) as alternate discovery
sources alongside the active TLS scanner.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

log = logging.getLogger("pktcert.ct_search")

_CRTSH_URL = "https://crt.sh/"


async def search_crtsh(domain: str) -> list[dict[str, Any]]:
    """Query crt.sh's JSON API for certificates matching *.domain. Returns
    raw crt.sh rows (not yet normalized to our certificates schema) —
    caller fetches the live cert separately via x509_utils.fetch_cert_chain
    since crt.sh doesn't reliably return the full PEM for every entry."""
    params = {"q": f"%.{domain}", "output": "json"}
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(_CRTSH_URL, params=params)
    if resp.status_code != 200:
        log.warning(f"crt.sh returned HTTP {resp.status_code} for {domain}")
        return []
    try:
        return resp.json()
    except ValueError:
        return []


async def search_censys(domain: str, api_id: str, api_secret: str) -> list[dict[str, Any]]:
    """Query Censys's host search for the given domain. Requires a Censys
    API ID/Secret pair (Cert Keys -> Censys, stored as 'api_id:api_secret')."""
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(
            "https://search.censys.io/api/v2/hosts/search",
            params={"q": domain, "per_page": 50},
            auth=(api_id, api_secret),
        )
    if resp.status_code != 200:
        log.warning(f"Censys returned HTTP {resp.status_code} for {domain}")
        return []
    data = resp.json()
    return data.get("result", {}).get("hits", [])
