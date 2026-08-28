"""
GET/PUT /api/user-api-keys — per-user external API keys: the suite-wide IP
Info / Reputation Lookup providers (AbuseIPDB, ipinfo.io, ipapi.is,
MXToolbox, IPQualityScore — same set every pkt* app exposes, used to look
up any IP address that shows up in this app's data, e.g. a scanned
certificate's host) plus Censys, a pktCert-specific provider for
Certificate Transparency / cert search.

Every authenticated user manages only their own keys, scoped by username —
there is no admin-wide view or override here.
"""
from __future__ import annotations

import json
from urllib.parse import quote

import aiosqlite
import logging

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.database import DB_PATH
from app.dependencies import CurrentUser
from app.cert.crypto import decrypt_str, encrypt_str

# Public, harmless IP used to exercise each IP-reputation provider's lookup
# endpoint when testing a key — Google Public DNS, safe to query against
# any provider.
_TEST_IP = "8.8.8.8"  # sanitize: allow-public-ip
_TEST_DOMAIN = "example.com"

log = logging.getLogger("pktcert.api.user_api_keys")

router = APIRouter()

# Providers this app knows how to use.
SUPPORTED_PROVIDERS: dict[str, str] = {
    "abuseipdb":      "AbuseIPDB",
    "ipqualityscore": "IPQualityScore",
    "ipinfo":         "ipinfo.io",
    "ipapi_is":       "ipapi.is",
    "mxtoolbox":      "MXToolbox",
    # Censys credentials are entered as "api_id:api_secret" in the single
    # api_key field (split on first ':' when used) — keeps the same
    # one-textbox-per-provider shape as every other provider here instead
    # of inventing a two-field variant just for this one.
    "censys":         "Censys (CT log / certificate search)",
}

# The ipinfo.io response sections a user can individually show/hide in the IP
# Lookup modal. Display preference only — ipinfo.io always returns whatever
# the account's plan unlocks; this just controls what renders.
IPINFO_FIELDS = ["geolocation", "asn", "company", "privacy", "abuse", "domains"]

# Same idea for ipapi.is — its response sections a user can individually
# show/hide. "detection" covers the is_vpn/is_proxy/is_tor/is_datacenter/
# is_abuser/is_mobile/is_satellite/is_crawler/is_bogon flags plus the vpn{}
# detail object.
IPAPI_IS_FIELDS = ["geolocation", "asn", "company", "detection", "abuse"]

# MXToolbox only auto-wires 3 of its 21 commands into the IP Lookup modal
# (see app/api/ip_info.py) — the rest are domain/email record checks and
# active probes, reachable only via the generic /api/mxtoolbox/lookup
# endpoint, not this per-IP lookup. These 3 keys match the mxtoolbox
# result dict's own field names.
MXTOOLBOX_FIELDS = ["ptr", "asn", "blacklist"]

# The 5 providers with a section in the IP Lookup modal — AbuseIPDB and
# IPQualityScore have no per-field checkboxes (single score, not multiple
# sections) but still get the modal-section on/off toggle. Censys isn't
# part of the IP Lookup modal at all (it's a domain-search provider, not
# an IP-reputation one), so it's deliberately excluded here.
MODAL_PROVIDERS = ["ipinfo", "ipapi_is", "abuseipdb", "mxtoolbox", "ipqualityscore"]

FIELD_SETS: dict[str, list[str]] = {
    "ipinfo": IPINFO_FIELDS,
    "ipapi_is": IPAPI_IS_FIELDS,
    "mxtoolbox": MXTOOLBOX_FIELDS,
}


class ApiKeyOut(BaseModel):
    provider: str
    label:    str
    api_key:  str    # "" if not set
    updated_at: str | None = None
    enabled_fields: list[str] | None = None  # ipinfo/ipapi_is/mxtoolbox only; None = not customized (all shown)
    free_tier: bool = False  # ipapi_is only — use its keyless free tier instead of api_key
    enabled: bool = True  # modal-section providers only — show this provider's section in the IP Lookup modal at all


class ApiKeyIn(BaseModel):
    api_key: str


class FieldsIn(BaseModel):
    enabled_fields: list[str]


class FreeTierIn(BaseModel):
    free_tier: bool


class EnabledIn(BaseModel):
    enabled: bool


def _row_out(provider: str, row) -> ApiKeyOut:
    return ApiKeyOut(
        provider=provider,
        label=SUPPORTED_PROVIDERS[provider],
        api_key=decrypt_str(row["api_key"]) if row else "",
        updated_at=row["updated_at"] if row else None,
        enabled_fields=json.loads(row["enabled_fields"]) if row and row["enabled_fields"] else None,
        free_tier=bool(row["free_tier"]) if row else False,
        enabled=bool(row["enabled"]) if row is not None and row["enabled"] is not None else True,
    )


@router.get("", response_model=list[ApiKeyOut])
async def list_api_keys(user: CurrentUser):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM user_api_keys WHERE username = ?",
            (user["username"],),
        ) as cur:
            rows = {r["provider"]: r for r in await cur.fetchall()}

    return [_row_out(provider, rows.get(provider)) for provider in SUPPORTED_PROVIDERS]


async def _get_row(username: str, provider: str):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM user_api_keys WHERE username = ? AND provider = ?", (username, provider)
        ) as cur:
            return await cur.fetchone()


@router.put("/{provider}/enabled", response_model=ApiKeyOut)
async def set_provider_enabled(provider: str, body: EnabledIn, user: CurrentUser):
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=404, detail=f"Unknown provider: {provider}")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO user_api_keys (username, provider, enabled, updated_at)
               VALUES (?, ?, ?, datetime('now'))
               ON CONFLICT (username, provider)
               DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at""",
            (user["username"], provider, int(body.enabled)),
        )
        await db.commit()
    return _row_out(provider, await _get_row(user["username"], provider))


@router.put("/ipapi_is/free-tier", response_model=ApiKeyOut)
async def set_ipapi_is_free_tier(body: FreeTierIn, user: CurrentUser):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO user_api_keys (username, provider, free_tier, updated_at)
               VALUES (?, 'ipapi_is', ?, datetime('now'))
               ON CONFLICT (username, provider)
               DO UPDATE SET free_tier = excluded.free_tier, updated_at = excluded.updated_at""",
            (user["username"], int(body.free_tier)),
        )
        await db.commit()
    return _row_out("ipapi_is", await _get_row(user["username"], "ipapi_is"))


async def _set_fields(username: str, provider: str, fields: list[str], valid: list[str]) -> ApiKeyOut:
    unknown = [f for f in fields if f not in valid]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown field(s): {', '.join(unknown)}")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            f"""INSERT INTO user_api_keys (username, provider, enabled_fields, updated_at)
                VALUES (?, '{provider}', ?, datetime('now'))
                ON CONFLICT (username, provider)
                DO UPDATE SET enabled_fields = excluded.enabled_fields, updated_at = excluded.updated_at""",
            (username, json.dumps(fields)),
        )
        await db.commit()
    return _row_out(provider, await _get_row(username, provider))


@router.put("/ipinfo/fields", response_model=ApiKeyOut)
async def set_ipinfo_fields(body: FieldsIn, user: CurrentUser):
    return await _set_fields(user["username"], "ipinfo", body.enabled_fields, IPINFO_FIELDS)


@router.put("/ipapi_is/fields", response_model=ApiKeyOut)
async def set_ipapi_is_fields(body: FieldsIn, user: CurrentUser):
    return await _set_fields(user["username"], "ipapi_is", body.enabled_fields, IPAPI_IS_FIELDS)


@router.put("/mxtoolbox/fields", response_model=ApiKeyOut)
async def set_mxtoolbox_fields(body: FieldsIn, user: CurrentUser):
    return await _set_fields(user["username"], "mxtoolbox", body.enabled_fields, MXTOOLBOX_FIELDS)


@router.put("/{provider}", response_model=ApiKeyOut)
async def set_api_key(provider: str, body: ApiKeyIn, user: CurrentUser):
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=404, detail=f"Unknown provider: {provider}")

    key = body.api_key.strip()
    async with aiosqlite.connect(DB_PATH) as db:
        if key:
            await db.execute(
                """INSERT INTO user_api_keys (username, provider, api_key, updated_at)
                   VALUES (?, ?, ?, datetime('now'))
                   ON CONFLICT (username, provider)
                   DO UPDATE SET api_key = excluded.api_key, updated_at = excluded.updated_at""",
                (user["username"], provider, encrypt_str(key)),
            )
        else:
            # Empty key means "clear" the key — but keep the row (if it
            # exists) rather than deleting it outright, so any other stored
            # preference for this provider (enabled/enabled_fields/free_tier)
            # survives clearing/re-saving a blank key.
            await db.execute(
                """INSERT INTO user_api_keys (username, provider, api_key, updated_at)
                   VALUES (?, ?, '', datetime('now'))
                   ON CONFLICT (username, provider)
                   DO UPDATE SET api_key = '', updated_at = excluded.updated_at""",
                (user["username"], provider),
            )
        await db.commit()

    row = await _get_row(user["username"], provider)
    out = _row_out(provider, row)
    out.api_key = key
    return out


@router.post("/{provider}/test")
async def test_api_key(provider: str, body: ApiKeyIn, _: CurrentUser) -> dict:
    """Exercise the given key against the provider's real API with a harmless
    test target. Tests whatever key is passed in — not necessarily saved yet —
    so a user can validate before committing."""
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=404, detail=f"Unknown provider: {provider}")

    key = body.api_key.strip()
    if not key:
        return {"status": "skipped", "detail": "No API key entered"}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            if provider == "abuseipdb":
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": _TEST_IP, "maxAgeInDays": 90},
                    headers={"Key": key, "Accept": "application/json"},
                )
                if resp.status_code == 200:
                    return {"status": "ok", "detail": "Key is valid"}
                return {"status": "failed", "detail": f"AbuseIPDB returned HTTP {resp.status_code}: {resp.text[:200]}"}

            elif provider == "ipinfo":
                resp = await client.get(f"https://ipinfo.io/{_TEST_IP}/json", params={"token": key})
                data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                if resp.status_code == 200 and "error" not in data:
                    return {"status": "ok", "detail": "Key is valid"}
                return {"status": "failed", "detail": data.get("error", {}).get("message") or f"ipinfo.io returned HTTP {resp.status_code}: {resp.text[:200]}"}

            elif provider == "ipqualityscore":
                resp = await client.get(f"https://ipqualityscore.com/api/json/ip/{quote(key, safe='')}/{_TEST_IP}")
                data = resp.json() if resp.status_code == 200 else {}
                if resp.status_code == 200 and data.get("success"):
                    return {"status": "ok", "detail": "Key is valid"}
                return {"status": "failed", "detail": data.get("message") or f"IPQualityScore returned HTTP {resp.status_code}: {resp.text[:200]}"}

            elif provider == "mxtoolbox":
                resp = await client.get(
                    "https://api.mxtoolbox.com/api/v1/Lookup/ptr/",
                    params={"argument": _TEST_IP},
                    headers={"Authorization": key, "Accept": "application/json"},
                )
                if resp.status_code == 200:
                    return {"status": "ok", "detail": "Key is valid"}
                data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                errors = data.get("Errors") if isinstance(data, dict) else None
                detail = errors[0].get("ErrorMessage") if isinstance(errors, list) and errors and isinstance(errors[0], dict) else None
                return {"status": "failed", "detail": detail or f"MXToolbox returned HTTP {resp.status_code}: {resp.text[:200]}"}

            elif provider == "ipapi_is":
                resp = await client.get("https://api.ipapi.is/", params={"q": _TEST_IP, "key": key})
                data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                if resp.status_code == 200 and not data.get("error"):
                    return {"status": "ok", "detail": "Key is valid"}
                return {"status": "failed", "detail": data.get("error") or f"ipapi.is returned HTTP {resp.status_code}: {resp.text[:200]}"}

            elif provider == "censys":
                if ":" not in key:
                    return {"status": "skipped", "detail": "Enter credentials as api_id:api_secret"}
                api_id, api_secret = key.split(":", 1)
                resp = await client.get(
                    "https://search.censys.io/api/v2/hosts/search",
                    params={"q": _TEST_DOMAIN, "per_page": 1},
                    auth=(api_id, api_secret),
                )
                if resp.status_code == 200:
                    return {"status": "ok", "detail": "Key is valid"}
                return {"status": "failed", "detail": f"Censys returned HTTP {resp.status_code}: {resp.text[:200]}"}

    except httpx.RequestError:
        # httpx puts the full request URL in its exception text; that URL can
        # carry the key being tested, so it must not come back to the browser.
        log.exception("provider key check failed")
        return {"status": "failed", "detail": "Request error contacting the provider"}

    return {"status": "failed", "detail": "Unhandled provider"}
