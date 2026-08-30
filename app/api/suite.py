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


# ── Managed mode ──────────────────────────────────────────────────────────────
# pktHub can lock this app so users reach it through the hub rather than
# directly. State lives in the settings table, not config.yaml, so a lock takes
# effect without a restart — and it carries a heartbeat, because a lock that
# only pktHub can lift strands the app if pktHub is the thing that broke. The
# expiry that lifts it lives in _direct_access_lock in app/main.py.


def _suite_token_ok(request: Request) -> bool:
    """Constant-time check of the caller's X-Suite-Token against ours."""
    from app.config import get_settings
    import secrets as _sec
    presented = request.headers.get("x-suite-token", "")
    # get_settings() re-reads SQLite, so a regenerated token applies at once.
    stored = (get_settings().suite_token or "").strip()
    if not presented or not stored:
        return False
    return _sec.compare_digest(presented, stored)


async def _read_lock_state() -> dict:
    """
    Current lock state. Values in this table are JSON-encoded, but the older
    rows written before that convention settled are bare strings — decode
    tolerantly, the same way app/config.py reads suite_token.
    """
    from app.config import get_settings
    import aiosqlite
    state = {"direct_ui_locked": False, "hub_redirect_url": ""}
    async with aiosqlite.connect(get_settings().db_path) as db:
        for key in ("direct_ui_locked", "hub_redirect_url"):
            async with db.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cur:
                row = await cur.fetchone()
            if not row or row[0] is None:
                continue
            try:
                value = json.loads(row[0])
            except (ValueError, TypeError):
                value = row[0]
            state[key] = value
    # "is True", not bool(): a value that failed to decode comes back as the raw
    # text, and bool("false") is True — which would report a lock that is off.
    return {
        "direct_ui_locked": state["direct_ui_locked"] is True,
        "hub_redirect_url": str(state["hub_redirect_url"] or ""),
    }


@router.get("/direct-access")
async def get_direct_access(request: Request):
    """
    Current lock state and redirect target. Auth: X-Suite-Token.

    pktHub calls this before enabling Managed mode, and again afterwards to
    confirm this app stored what it was sent.
    """
    if not _suite_token_ok(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    try:
        return JSONResponse(await _read_lock_state())
    except Exception:
        # The exception text carries the database path and internal SQL, and
        # this endpoint answers pktHub over the network — log it, don't return it.
        log.exception("suite endpoint failed")
        return JSONResponse({"error": "Internal error"}, status_code=500)


@router.post("/direct-access")
async def set_direct_access(request: Request):
    """
    Lock or unlock direct UI access. Auth: X-Suite-Token.
    Body: {"locked": true|false, "hub_redirect_url": "https://hub/app/13"}

    hub_redirect_url comes from pktHub, which is the only party able to build
    it: the address carries the hub's own hostname and this app's id in the
    hub's registry, and neither is visible from here.

    The heartbeat is written alongside the flag so a fresh lock starts fresh
    rather than inheriting an expiry from whenever pktHub last called.
    """
    if not _suite_token_ok(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)

    locked = bool(body.get("locked", False))
    redirect_url = (body.get("hub_redirect_url") or "").strip()
    # http/https only. This value arrives over the network, and once the lock is
    # on every visitor to this app follows it, so a "javascript:" target here
    # would be an XSS sink rather than a redirect.
    if redirect_url and not redirect_url.lower().startswith(("http://", "https://")):
        return JSONResponse(
            {"error": "hub_redirect_url must start with http:// or https://"},
            status_code=400,
        )

    from app.config import get_settings
    from datetime import datetime, timezone
    import aiosqlite
    try:
        async with aiosqlite.connect(get_settings().db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('direct_ui_locked', ?)",
                (json.dumps(locked),)
            )
            await db.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('lock_heartbeat_at', ?)",
                (json.dumps(datetime.now(timezone.utc).isoformat()),)
            )
            if redirect_url:
                await db.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES ('hub_redirect_url', ?)",
                    (json.dumps(redirect_url),)
                )
            await db.commit()
        return JSONResponse({
            "status": "ok",
            "direct_ui_locked": locked,
            "hub_redirect_url": redirect_url,
        })
    except Exception:
        # The exception text carries the database path and internal SQL, and
        # this endpoint answers pktHub over the network — log it, don't return it.
        log.exception("suite endpoint failed")
        return JSONResponse({"error": "Internal error"}, status_code=500)


@router.get("/mode")
async def get_mode():
    """
    Lock state, unauthenticated. This app's own pages read it to explain why
    they bounced the user to pktHub, and they hold no suite token. It exposes
    nothing a locked-out visitor cannot already see from the redirect itself.
    """
    try:
        return JSONResponse(await _read_lock_state())
    except Exception:
        log.exception("suite endpoint failed")
        return JSONResponse({"error": "Internal error"}, status_code=500)


@router.patch("/hub-redirect-url")
async def set_hub_redirect_url(request: Request, user: AdminUser):
    """
    Manual override for the redirect address. pktHub normally sets this when it
    locks the app, so this exists for an install running without a hub in front
    of it.

    Admin-only, and http/https only: once the lock is on, every visitor to this
    app follows this URL, so whoever can set it can redirect the whole user
    base. That is an admin decision, and a "javascript:" target would make it
    an XSS sink.
    """
    from app.config import get_settings
    import aiosqlite
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)

    url = (body.get("hub_redirect_url") or "").strip()
    if url and not url.lower().startswith(("http://", "https://")):
        return JSONResponse(
            {"error": "hub_redirect_url must start with http:// or https://"},
            status_code=400,
        )

    try:
        async with aiosqlite.connect(get_settings().db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('hub_redirect_url', ?)",
                (json.dumps(url),)
            )
            await db.commit()
        return JSONResponse({"status": "ok", "hub_redirect_url": url})
    except Exception:
        # The exception text carries the database path and internal SQL, and
        # this endpoint answers pktHub over the network — log it, don't return it.
        log.exception("suite endpoint failed")
        return JSONResponse({"error": "Internal error"}, status_code=500)
