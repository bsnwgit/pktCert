"""
GET /api/ip-info/{ip} — combined IP intelligence (ipinfo.io, ipapi.is) +
reputation (AbuseIPDB) + DNS/blacklist intel (MXToolbox: ptr/asn/blacklist)
lookup for a single public IP, using the current user's own stored API keys
(see app/api/user_api_keys.py). Private/loopback/link-local addresses are
rejected — external providers have nothing useful to say about them.

GET /api/ip-info/internal/{ip} — the internal-IP counterpart. Looks the
address up in pktIPAM (subnet, DHCP lease, DNS records, ARP sightings) over
the Suite Integration channel (see app/integrations/suite_client.py).
Public addresses are rejected — pktIPAM has nothing to say about them.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
from urllib.parse import quote

import aiosqlite
import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.database import DB_PATH
from app.dependencies import CurrentUser
from app.integrations.suite_client import SuiteClient
from app.cert.crypto import decrypt_str

router = APIRouter()


class IpInfoResult(BaseModel):
    ip: str
    ipinfo: dict | None = None
    ipinfo_error: str | None = None
    ipinfo_enabled_fields: list[str] | None = None  # None = not customized, show everything
    ipinfo_enabled: bool = True  # show this provider's section in the modal at all
    ipapi_is: dict | None = None
    ipapi_is_error: str | None = None
    ipapi_is_enabled_fields: list[str] | None = None  # None = not customized, show everything
    ipapi_is_enabled: bool = True
    abuseipdb: dict | None = None
    abuseipdb_error: str | None = None
    abuseipdb_enabled: bool = True
    mxtoolbox: dict | None = None
    mxtoolbox_error: str | None = None
    mxtoolbox_enabled_fields: list[str] | None = None  # None = not customized, show everything
    mxtoolbox_enabled: bool = True
    ipqualityscore: dict | None = None
    ipqualityscore_error: str | None = None
    ipqualityscore_enabled: bool = True


class InternalIpInfoResult(BaseModel):
    ip: str
    configured: bool
    found: bool = False
    error: str | None = None
    subnet: dict | None = None
    ip_address: dict | None = None
    dhcp_leases: list[dict] = []
    dns_records: list[dict] = []
    arp_entries: list[dict] = []


async def _get_user_key(username: str, provider: str) -> str:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT api_key FROM user_api_keys WHERE username = ? AND provider = ?",
            (username, provider),
        ) as cur:
            row = await cur.fetchone()
    return decrypt_str(row[0]) if row else ""


async def _get_ipinfo_enabled_fields(username: str) -> list[str] | None:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT enabled_fields FROM user_api_keys WHERE username = ? AND provider = 'ipinfo'",
            (username,),
        ) as cur:
            row = await cur.fetchone()
    return json.loads(row[0]) if row and row[0] else None


async def _get_ipapi_is_enabled_fields(username: str) -> list[str] | None:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT enabled_fields FROM user_api_keys WHERE username = ? AND provider = 'ipapi_is'",
            (username,),
        ) as cur:
            row = await cur.fetchone()
    return json.loads(row[0]) if row and row[0] else None


async def _get_ipapi_is_free_tier(username: str) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT free_tier FROM user_api_keys WHERE username = ? AND provider = 'ipapi_is'",
            (username,),
        ) as cur:
            row = await cur.fetchone()
    return bool(row[0]) if row else False


async def _get_mxtoolbox_enabled_fields(username: str) -> list[str] | None:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT enabled_fields FROM user_api_keys WHERE username = ? AND provider = 'mxtoolbox'",
            (username,),
        ) as cur:
            row = await cur.fetchone()
    return json.loads(row[0]) if row and row[0] else None


async def _get_provider_enabled(username: str, provider: str) -> bool:
    """Whether to show this provider's section in the modal at all — no row
    yet means never configured/toggled, which defaults to shown."""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT enabled FROM user_api_keys WHERE username = ? AND provider = ?",
            (username, provider),
        ) as cur:
            row = await cur.fetchone()
    return bool(row[0]) if row is not None else True


async def _fetch_ipinfo(client: httpx.AsyncClient, ip: str, key: str, result: IpInfoResult) -> None:
    if not key:
        result.ipinfo_error = "No ipinfo.io key configured — add one in Settings → User Keys"
        return
    try:
        resp = await client.get(f"https://ipinfo.io/{ip}/json", params={"token": key})
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        if resp.status_code == 200 and "error" not in data:
            result.ipinfo = data
        else:
            result.ipinfo_error = data.get("error", {}).get("message") or f"ipinfo.io returned HTTP {resp.status_code}"
    except httpx.RequestError as exc:
        result.ipinfo_error = f"Request error: {exc}"


async def _fetch_ipapi_is(client: httpx.AsyncClient, ip: str, key: str, free_tier: bool, result: IpInfoResult) -> None:
    if not key and not free_tier:
        result.ipapi_is_error = "No ipapi.is key configured — add one in Settings → User Keys, or enable the free tier"
        return
    try:
        # Free tier deliberately omits the key param entirely rather than
        # sending an empty one — matches ipapi.is's own anonymous/no-key
        # usage (1,000 req/day, no signup) rather than an invalid-key call.
        params = {"q": ip} if free_tier else {"q": ip, "key": key}
        resp = await client.get("https://api.ipapi.is/", params=params)
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        if resp.status_code == 200 and not data.get("error"):
            result.ipapi_is = data
        else:
            result.ipapi_is_error = data.get("error") or f"ipapi.is returned HTTP {resp.status_code}"
    except httpx.RequestError as exc:
        result.ipapi_is_error = f"Request error: {exc}"


async def _fetch_ipqualityscore(client: httpx.AsyncClient, ip: str, key: str, result: IpInfoResult) -> None:
    if not key:
        result.ipqualityscore_error = "No IPQualityScore key configured — add one in Settings → User Keys"
        return
    try:
        resp = await client.get(f"https://ipqualityscore.com/api/json/ip/{quote(key, safe='')}/{ip}")
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        if resp.status_code == 200 and data.get("success"):
            result.ipqualityscore = data
        else:
            result.ipqualityscore_error = data.get("message") or f"IPQualityScore returned HTTP {resp.status_code}"
    except httpx.RequestError as exc:
        result.ipqualityscore_error = f"Request error: {exc}"


async def _fetch_abuseipdb(client: httpx.AsyncClient, ip: str, key: str, result: IpInfoResult) -> None:
    if not key:
        result.abuseipdb_error = "No AbuseIPDB key configured — add one in Settings → User Keys"
        return
    try:
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
        )
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        if resp.status_code == 200:
            result.abuseipdb = data.get("data")
        else:
            errors = data.get("errors") or []
            result.abuseipdb_error = (errors[0].get("detail") if errors else None) or f"AbuseIPDB returned HTTP {resp.status_code}"
    except httpx.RequestError as exc:
        result.abuseipdb_error = f"Request error: {exc}"


async def _mxtoolbox_call(client: httpx.AsyncClient, command: str, argument: str, key: str) -> tuple[dict | None, str | None]:
    """One MXToolbox `Lookup/{command}` call. Returns (data, error) — never raises."""
    try:
        resp = await client.get(
            f"https://api.mxtoolbox.com/api/v1/Lookup/{command}/",
            params={"argument": argument},
            headers={"Authorization": key, "Accept": "application/json"},
        )
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        if resp.status_code == 200:
            return data, None
        errors = data.get("Errors") if isinstance(data, dict) else None
        detail = errors[0].get("ErrorMessage") if isinstance(errors, list) and errors and isinstance(errors[0], dict) else None
        return None, detail or f"MXToolbox returned HTTP {resp.status_code}"
    except httpx.RequestError as exc:
        return None, f"Request error: {exc}"


async def _fetch_mxtoolbox(client: httpx.AsyncClient, ip: str, key: str, result: IpInfoResult) -> None:
    if not key:
        result.mxtoolbox_error = "No MXToolbox key configured — add one in Settings → User Keys"
        return
    (ptr, ptr_err), (asn, asn_err), (blacklist, blacklist_err) = await asyncio.gather(
        _mxtoolbox_call(client, "ptr", ip, key),
        _mxtoolbox_call(client, "asn", ip, key),
        _mxtoolbox_call(client, "blacklist", ip, key),
    )
    result.mxtoolbox = {
        "ptr": ptr, "ptr_error": ptr_err,
        "asn": asn, "asn_error": asn_err,
        "blacklist": blacklist, "blacklist_error": blacklist_err,
    }


@router.get("/{ip}", response_model=IpInfoResult)
async def get_ip_info(ip: str, user: CurrentUser):
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}")

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
        raise HTTPException(status_code=400, detail="IP info lookup is only available for public addresses")

    result = IpInfoResult(ip=ip)
    ipinfo_key = await _get_user_key(user["username"], "ipinfo")
    ipapi_is_key = await _get_user_key(user["username"], "ipapi_is")
    abuseipdb_key = await _get_user_key(user["username"], "abuseipdb")
    mxtoolbox_key = await _get_user_key(user["username"], "mxtoolbox")
    ipqualityscore_key = await _get_user_key(user["username"], "ipqualityscore")
    result.ipinfo_enabled_fields = await _get_ipinfo_enabled_fields(user["username"])
    result.ipapi_is_enabled_fields = await _get_ipapi_is_enabled_fields(user["username"])
    result.mxtoolbox_enabled_fields = await _get_mxtoolbox_enabled_fields(user["username"])
    ipapi_is_free_tier = await _get_ipapi_is_free_tier(user["username"])
    result.ipinfo_enabled = await _get_provider_enabled(user["username"], "ipinfo")
    result.ipapi_is_enabled = await _get_provider_enabled(user["username"], "ipapi_is")
    result.abuseipdb_enabled = await _get_provider_enabled(user["username"], "abuseipdb")
    result.mxtoolbox_enabled = await _get_provider_enabled(user["username"], "mxtoolbox")
    result.ipqualityscore_enabled = await _get_provider_enabled(user["username"], "ipqualityscore")

    async with httpx.AsyncClient(timeout=10) as client:
        tasks = []
        if result.ipinfo_enabled:
            tasks.append(_fetch_ipinfo(client, ip, ipinfo_key, result))
        if result.ipapi_is_enabled:
            tasks.append(_fetch_ipapi_is(client, ip, ipapi_is_key, ipapi_is_free_tier, result))
        if result.abuseipdb_enabled:
            tasks.append(_fetch_abuseipdb(client, ip, abuseipdb_key, result))
        if result.mxtoolbox_enabled:
            tasks.append(_fetch_mxtoolbox(client, ip, mxtoolbox_key, result))
        if result.ipqualityscore_enabled:
            tasks.append(_fetch_ipqualityscore(client, ip, ipqualityscore_key, result))
        if tasks:
            await asyncio.gather(*tasks)

    return result


async def _get_pktipam_integration() -> aiosqlite.Row | None:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM integrations WHERE app_name = 'pktipam' AND enabled = 1"
        ) as cur:
            return await cur.fetchone()


@router.get("/internal/{ip}", response_model=InternalIpInfoResult)
async def get_internal_ip_info(ip: str, user: CurrentUser):
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}")

    if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local):
        raise HTTPException(status_code=400, detail="Internal IP lookup is only available for private addresses")

    integration = await _get_pktipam_integration()
    if not integration or not integration["base_url"] or not integration["suite_token"]:
        return InternalIpInfoResult(ip=ip, configured=False, error="pktIPAM integration is not configured — add one in Settings → Integrations")

    client = SuiteClient(integration["base_url"], decrypt_str(integration["suite_token"]),
                         suite_user="pktcert", suite_role="admin")
    try:
        data = await client.get("/api/ip-addresses/lookup", params={"ip": ip})
    except httpx.HTTPStatusError as exc:
        return InternalIpInfoResult(ip=ip, configured=True, error=f"pktIPAM returned HTTP {exc.response.status_code}")
    except httpx.RequestError as exc:
        return InternalIpInfoResult(ip=ip, configured=True, error=f"Could not reach pktIPAM: {exc}")

    return InternalIpInfoResult(
        ip=ip,
        configured=True,
        found=data.get("found", False),
        subnet=data.get("subnet"),
        ip_address=data.get("ip_address"),
        dhcp_leases=data.get("dhcp_leases", []),
        dns_records=data.get("dns_records", []),
        arp_entries=data.get("arp_entries", []),
    )
