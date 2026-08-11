"""
app/api/suite.py — pktHub integration endpoints (inbound: pktHub calling into pktCert).

Token flow:
  1. pktCert generates a random suite_token on first call to GET /api/suite/token
  2. Admin copies the token from Settings -> Integrations -> Suite Integration
  3. Admin pastes the token into pktHub App Manager when registering this app
  4. pktHub stores it and sends it as X-Suite-Token on every proxied request

GET  /api/suite/token    — returns current token (generates one if not set)
POST /api/suite/register — stores a new token (manual override)
GET  /api/suite/whoami   — authenticated identity check; a sibling pkt* app's
                           "Test Connection" button calls this (not the public
                           /api/health) so a wrong/revoked token fails the test
                           instead of silently reporting a healthy connection.
"""
import json
import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

log = logging.getLogger("pktcert.api.suite")

from app.dependencies import AdminUser, CurrentUser

router = APIRouter()


@router.get("/token")
async def get_suite_token(request: Request, user: AdminUser):
    """Return the current suite token. Lazily generates one if not set.
    Admin-only: this token grants full inter-app suite access to this instance."""
    from app.config import get_settings
    import aiosqlite, secrets as _sec
    settings = get_settings()
    token = (settings.suite_token or "").strip()

    if not token:
        new_token = _sec.token_urlsafe(32)
        try:
            async with aiosqlite.connect(settings.db_path) as db:
                await db.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES ('suite_token', ?)",
                    (json.dumps(new_token),)
                )
                await db.commit()
            token = new_token
        except Exception:
            pass

    return JSONResponse({"suite_token": token, "has_token": bool(token)})


@router.post("/register")
async def suite_register(request: Request, user: AdminUser):
    """
    Manual token override — stores a new suite token.
    Admin-only: this token grants full inter-app suite access to this instance.
    Body: {"suite_token": "<new_token>"}
    """
    from app.config import get_settings
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)

    new_token = (body.get("suite_token") or "").strip()
    if not new_token:
        return JSONResponse({"error": "suite_token required"}, status_code=400)

    try:
        import aiosqlite
        settings = get_settings()
        async with aiosqlite.connect(settings.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('suite_token', ?)",
                (json.dumps(new_token),)
            )
            await db.commit()
        return JSONResponse({"status": "ok"})
    except Exception:
        # The exception text can carry the database path and internal SQL, and
        # this endpoint answers pktHub over the network — log it, don't return it.
        log.exception("suite endpoint failed")
        return JSONResponse({"error": "Internal error"}, status_code=500)


@router.post("/regenerate")
async def regenerate_suite_token(request: Request, user: AdminUser):
    """
    Replace the suite token with a freshly generated one.
    Admin-only: this token grants full inter-app suite access to this instance.
    Use when you need to revoke current pktHub access.
    After calling this, re-register the app in pktHub with the new token.
    """
    from app.config import get_settings
    import aiosqlite, secrets as _sec
    settings = get_settings()
    new_token = _sec.token_urlsafe(32)
    try:
        async with aiosqlite.connect(settings.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('suite_token', ?)",
                (json.dumps(new_token),)
            )
            await db.commit()
        return JSONResponse({"suite_token": new_token, "status": "regenerated"})
    except Exception:
        # The exception text can carry the database path and internal SQL, and
        # this endpoint answers pktHub over the network — log it, don't return it.
        log.exception("suite endpoint failed")
        return JSONResponse({"error": "Internal error"}, status_code=500)


@router.post("/settings-lock")
async def set_settings_lock(request: Request, user: CurrentUser):
    """
    Called by pktHub on register/deregister to flag whether this app's
    Settings page should show a "remotely managed" banner and disable local
    editing. Narrower than a whole-app direct-access lock — everything else
    in the app keeps working normally, only the Settings UI is affected.
    Body: {"locked": true|false}
    """
    from app.config import get_settings
    import aiosqlite
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)

    locked = bool(body.get("locked"))
    settings = get_settings()
    try:
        async with aiosqlite.connect(settings.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('hub_settings_managed', ?)",
                (json.dumps(locked),)
            )
            await db.commit()
    except Exception:
        # The exception text can carry the database path and internal SQL, and
        # this endpoint answers pktHub over the network — log it, don't return it.
        log.exception("suite endpoint failed")
        return JSONResponse({"error": "Internal error"}, status_code=500)

    return JSONResponse({"hub_settings_managed": locked})


@router.get("/whoami")
async def suite_whoami(user: CurrentUser):
    """
    Requires a valid X-Suite-Token (or a normal session) — used by callers to
    prove they can actually authenticate here, not just reach the port.
    """
    return {
        "authenticated": True,
        "app": "pktcert",
        "via_suite_token": bool(user.get("_via_suite")),
        "role": user["role"],
    }
