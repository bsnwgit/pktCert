"""
POST /api/mxtoolbox/lookup — generic passthrough to any MXToolbox Lookup
command, using the current user's own stored MXToolbox key (see
app/api/user_api_keys.py). Covers every command MXToolbox's API supports,
not just the ptr/asn/blacklist subset auto-wired into GET /api/ip-info/{ip}:
DNS/email-record checks (a, aaaa, bimi, dkim, dmarc, dns, mta-sts, mx, soa,
spf, tlsrpt, txt) and active network probes that MXToolbox's own
infrastructure runs against the target (blacklist, http, https, ping, smtp,
tcp, trace) — these touch the argument host directly, unlike the DNS-record
commands. No response modeling — the frontend that will consume this
doesn't exist yet, so MXToolbox's raw JSON passes straight through.
"""
from __future__ import annotations

import aiosqlite
import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.database import DB_PATH
from app.dependencies import CurrentUser
from app.cert.crypto import decrypt_str

router = APIRouter()

# DNS-quota commands (free MXToolbox tier: 64/day) vs Network-quota commands
# (0 on free tier — needs a paid plan). See MXToolbox's own /Usage endpoint
# for a user's current consumption against each bucket.
DNS_COMMANDS = {"a", "aaaa", "asn", "bimi", "dkim", "dmarc", "dns", "mta-sts", "mx", "ptr", "soa", "spf", "tlsrpt", "txt"}
NETWORK_COMMANDS = {"blacklist", "http", "https", "ping", "smtp", "tcp", "trace"}
ALL_COMMANDS = DNS_COMMANDS | NETWORK_COMMANDS


class MxToolboxLookupRequest(BaseModel):
    command: str
    argument: str
    port: int | None = None  # required for "tcp"


async def _get_user_key(username: str, provider: str) -> str:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT api_key FROM user_api_keys WHERE username = ? AND provider = ?",
            (username, provider),
        ) as cur:
            row = await cur.fetchone()
    return decrypt_str(row[0]) if row else ""


@router.post("/lookup")
async def mxtoolbox_lookup(body: MxToolboxLookupRequest, user: CurrentUser):
    command = body.command.strip().lower()
    if command not in ALL_COMMANDS:
        raise HTTPException(status_code=400, detail=f"Unsupported MXToolbox command: {command}")

    argument = body.argument.strip()
    if not argument:
        raise HTTPException(status_code=400, detail="argument is required")
    if command == "dkim" and ":" not in argument:
        raise HTTPException(status_code=400, detail="dkim requires argument in 'domain:selector' format")
    if command == "tcp" and not body.port:
        raise HTTPException(status_code=400, detail="tcp requires a port")

    key = await _get_user_key(user["username"], "mxtoolbox")
    if not key:
        raise HTTPException(status_code=400, detail="No MXToolbox key configured — add one in Settings → User Keys")

    params: dict = {"argument": argument}
    if command == "tcp":
        params["port"] = body.port

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"https://api.mxtoolbox.com/api/v1/Lookup/{command}/",
                params=params,
                headers={"Authorization": key, "Accept": "application/json"},
            )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Request error: {exc}")

    data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"raw": resp.text[:2000]}
    if resp.status_code != 200:
        errors = data.get("Errors") if isinstance(data, dict) else None
        detail = errors[0].get("ErrorMessage") if isinstance(errors, list) and errors and isinstance(errors[0], dict) else None
        raise HTTPException(status_code=resp.status_code, detail=detail or f"MXToolbox returned HTTP {resp.status_code}")

    return data
