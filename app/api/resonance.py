"""
app/api/resonance.py — the pkt* side of the resonance embed contract.

  GET  /api/resonance/config  — what the SPA needs to mount the widget. Never the key.
  GET  /api/resonance/code    — cookie-authenticated. embed.js calls this itself.
  POST /api/resonance/report  — a browser telling us the widget failed to load.
  POST /api/resonance/test    — admin. A real session call; renders what the key grants.
  GET  /api/resonance/status  — admin. Breaker state and recent load failures.
  GET  /api/resonance/docs    — suite-token. This app's documentation, for
                                resonance to hold as the assistant's knowledge.

Why /code authenticates by cookie when everything else here uses a Bearer token:
embed.js fetches data-code-url on its own, outside the SPA, with
credentials:'include'. The app's access token lives in memory by design, so there
is no way to attach it to a fetch this app does not make. The refresh cookie is
the only credential the browser will send — it is validated the same way
/api/auth/refresh validates it, and deliberately not rotated here.

That makes this the one cookie-authenticated route in the app, so it does not
rely on SameSite alone: Sec-Fetch-Site and Origin are both checked before the
cookie is honoured.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
from urllib.parse import urlsplit

from typing import Annotated, Optional

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from app.api.settings import read_secret
from app.auth.local import decode_refresh_token
from app.database import get_db
from app.dependencies import AdminUser, CurrentUser
from app.integrations.resonance import (
    DEFAULT_EXCLUDE_PATHS, DEFAULT_ROLE_LEVELS, RESONANCE_MODULE_VERSION,
)
from app.integrations.resonance import limiter, reports
from app.integrations.resonance.client import ResonanceClient, build_user_id
from app.integrations.resonance.errors import ResonanceError, ResonanceNotConfigured

log = logging.getLogger("pktcert.api.resonance")

router = APIRouter()

# Same scheme app/dependencies.py uses. Declared here so /docs can accept either
# a suite token or an admin session without get_current_user being called
# outside the dependency system, which would silently never see a Bearer header.
_bearer = HTTPBearer(auto_error=False)

# Reporting is browser-driven, so it gets its own cheap ceiling. A page that
# fails to load can only say so a handful of times before it stops being news.
REPORT_LIMIT = 5
REPORT_WINDOW_SECONDS = 3600

# Admin-driven, so this only has to stop a runaway UI, not a person.
TEST_LIMIT = 10
TEST_WINDOW_SECONDS = 600


# ── Settings access ───────────────────────────────────────────────────────────

async def _get(db: aiosqlite.Connection, key: str, default=None):
    async with db.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cur:
        row = await cur.fetchone()
    if not row or row[0] is None:
        return default
    try:
        return json.loads(row[0])
    except (json.JSONDecodeError, TypeError, ValueError):
        return row[0]


async def _embed_config(db: aiosqlite.Connection) -> dict:
    """Everything the SPA needs to mount, and nothing that identifies us to resonance."""
    excluded = await _get(db, "resonance_exclude_paths", None)
    if not isinstance(excluded, list):
        excluded = list(DEFAULT_EXCLUDE_PATHS)
    return {
        "base_url": (await _get(db, "resonance_base_url", "") or "").rstrip("/"),
        "style": await _get(db, "resonance_style", "bubble") or "bubble",
        "target": await _get(db, "resonance_target", "") or "",
        "label": await _get(db, "resonance_label", "") or "",
        "side": await _get(db, "resonance_side", "right") or "right",
        "width": await _get(db, "resonance_width", "") or "",
        "height": await _get(db, "resonance_height", "") or "",
        "open": bool(await _get(db, "resonance_open", False)),
        "exclude_paths": excluded,
    }


# What a role may do with the assistant. Ordered, so a comparison of rank is a
# comparison of permission: "write" implies "read", "none" implies nothing.
LEVEL_RANK = {"none": 0, "read": 1, "write": 2}


async def _role_levels(db: aiosqlite.Connection) -> dict[str, str]:
    """Level per role, falling back to the module default when unset.

    The fallback is not cosmetic: several pkt apps have no server-side defaults
    table, so this row does not exist until an admin saves the panel. Reading
    an empty dict there would leave every role locked out of a widget the
    admin had just switched on, with nothing on screen to explain it.
    """
    stored = await _get(db, "resonance_role_levels", None)
    if not isinstance(stored, dict) or not stored:
        return dict(DEFAULT_ROLE_LEVELS)
    return {str(role): str(level) for role, level in stored.items()}


async def role_level(db: aiosqlite.Connection, role: str) -> str:
    """This role's assistant level, defaulting closed for anything unrecognised."""
    level = (await _role_levels(db)).get(role, "none")
    return level if level in LEVEL_RANK else "none"


async def _allowed_roles(db: aiosqlite.Connection) -> list[str]:
    """Roles that may open the assistant at all — level above "none"."""
    return [role for role, level in (await _role_levels(db)).items()
            if LEVEL_RANK.get(level, 0) > 0]


async def _client(db: aiosqlite.Connection, base_url: str = "", key: str = "") -> ResonanceClient:
    """Build a client from stored settings, or from values supplied for a test."""
    if not base_url:
        base_url = await _get(db, "resonance_base_url", "") or ""
    if not key:
        key = await read_secret(db, "resonance_key")
    ca_bundle = await _get(db, "resonance_ca_bundle", "") or ""
    return ResonanceClient(base_url, key, ca_bundle=ca_bundle)


# ── Request-origin checks for the cookie route ────────────────────────────────

def _detected_origin(request: Request) -> str:
    """Best guess at the address a browser used to reach this app.

    uvicorn is not started with --proxy-headers, so request.url.scheme and the
    Host header describe the *internal* endpoint whenever a reverse proxy sits
    in front — an install reached at https://app.example.com over 443 reports
    itself as the internal scheme, host and port instead. X-Forwarded-* is read
    here because a guess
    that matches reality most of the time is more useful than one that is
    reliably wrong, but this is only ever a suggestion: it is displayed for an
    admin to confirm or replace, never trusted for a security decision.
    """
    proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    host = (request.headers.get("x-forwarded-host") or "").split(",")[0].strip()
    if not proto:
        proto = request.url.scheme
    if not host:
        host = request.headers.get("host", "")
    return f"{proto}://{host}" if host else ""


async def _effective_origin(db: aiosqlite.Connection, request: Request) -> str:
    """The configured origin if an admin set one, otherwise the detection."""
    override = (await _get(db, "resonance_origin", "") or "").strip().rstrip("/")
    return override or _detected_origin(request)


def _same_origin(request: Request) -> bool:
    """Reject anything that presents as cross-site before the cookie is used.

    SameSite=lax already stops a hostile page's fetch from carrying the refresh
    cookie. This is the second lock, because cors_origins is administrator
    controlled and a permissive value should not be all that stands between
    another site and a session code.
    """
    fetch_site = request.headers.get("sec-fetch-site", "")
    if fetch_site:
        # Browser-generated and not settable from page script, so where it exists
        # it is the whole answer. Every current browser sends it.
        return fetch_site in ("same-origin", "none")

    # Fallback for a client that does not send Sec-Fetch-Site. Comparing Origin
    # against Host is only meaningful when Host is the one the browser used —
    # a proxy that rewrites it to the internal address would otherwise make this
    # reject every legitimate request. Accept the forwarded host as well.
    origin = request.headers.get("origin", "")
    if not origin:
        return True

    seen = urlsplit(origin).netloc
    candidates = {
        request.headers.get("host", ""),
        (request.headers.get("x-forwarded-host") or "").split(",")[0].strip(),
    }
    return seen in {c for c in candidates if c}


async def _user_for_code(request: Request, db: aiosqlite.Connection) -> dict | None:
    """Identify the caller of /code without a Bearer token.

    Mirrors get_current_user's two paths: a pktHub-proxied request arrives with
    suite headers and no cookie of ours, everything else brings the refresh
    cookie. Returns None rather than raising so the caller can answer uniformly.
    """
    from app.config import get_settings
    import secrets as _secrets

    settings = get_settings()
    suite_token = request.headers.get("x-suite-token", "")
    if suite_token and settings.suite_token and _secrets.compare_digest(suite_token, settings.suite_token):
        # id 0 matches what get_current_user returns for a hub-proxied caller:
        # there is no local row for them, and anything recording who acted
        # stores that same synthetic id from either entry point.
        return {
            "id": 0,
            "username": request.headers.get("x-suite-user", "hub_user"),
            "role": request.headers.get("x-suite-role", "viewer"),
        }

    token = request.cookies.get("refresh_token")
    if not token:
        return None
    user_id = decode_refresh_token(token)
    if not user_id:
        return None

    async with db.execute(
        "SELECT username, role, is_active FROM users WHERE id = ?", (user_id,)
    ) as cur:
        row = await cur.fetchone()
    if not row or not row["is_active"]:
        return None
    return {"id": user_id, "username": row["username"], "role": row["role"]}


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/config")
async def resonance_config(user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    """Mount configuration for the SPA.

    Answers {"enabled": false} for every reason the widget should not appear —
    switched off, unconfigured, or this user's role is not on the list — so the
    frontend has exactly one thing to check and no way to infer whether a key
    exists from the shape of the response.
    """
    enabled = bool(await _get(db, "resonance_enabled", False))
    cfg = await _embed_config(db)
    if not enabled or not cfg["base_url"]:
        return {"enabled": False}

    if user.get("role") not in await _allowed_roles(db):
        return {"enabled": False}

    return {"enabled": True, **cfg}


@router.get("/code")
async def resonance_code(request: Request, db: aiosqlite.Connection = Depends(get_db)):
    """Mint a single-use embed code for the logged-in user. Called by embed.js."""
    if not _same_origin(request):
        raise HTTPException(status_code=403, detail="Cross-site request refused")

    user = await _user_for_code(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if not bool(await _get(db, "resonance_enabled", False)):
        raise HTTPException(status_code=404, detail="Resonance is not enabled")

    if user["role"] not in await _allowed_roles(db):
        raise HTTPException(status_code=403, detail="Not permitted to use resonance")

    try:
        await limiter.consume_for_user(db, user["username"])
        await limiter.assert_closed(db)
        client = await _client(db)
        body = await client.create_session(user["username"], [user["role"]])
    except ResonanceError as err:
        # Our own limiter and an open breaker are not resonance failures and must
        # not count towards opening it further.
        from app.integrations.resonance.errors import ResonanceBreakerOpen, ResonanceRateLimited

        if isinstance(err, ResonanceRateLimited):
            return JSONResponse({"error": err.admin_message}, status_code=429)
        if isinstance(err, ResonanceBreakerOpen):
            return JSONResponse({"error": err.admin_message}, status_code=503)

        await limiter.record_failure(db, err)
        log.warning("resonance session failed for %s: %s", user["username"], err)
        return JSONResponse({"error": err.admin_message}, status_code=502)

    await limiter.record_success(db)
    # embed.js reads .code; expires_in is passed through so the mount can time
    # its own watchdog against the same session the frame is using.
    return {"code": body["code"], "expires_in": body.get("expires_in")}


class ReportBody(BaseModel):
    reason: str


@router.post("/report")
async def resonance_report(
    body: ReportBody, user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)
):
    """A browser reporting that the widget did not load. See reports.py for why."""
    try:
        await limiter.consume(db, f"r:{user['username']}", REPORT_LIMIT, REPORT_WINDOW_SECONDS)
    except ResonanceError:
        # Nothing to tell the browser: it cannot act on this, and the failure is
        # already recorded from an earlier report in the same window.
        return {"recorded": False}

    recorded = await reports.record(db, user["username"], body.reason)
    return {"recorded": recorded}


class TestBody(BaseModel):
    base_url: str | None = None
    key: str | None = None


@router.post("/test")
async def resonance_test(
    body: TestBody, user: AdminUser, request: Request, db: aiosqlite.Connection = Depends(get_db)
):
    """Prove the configuration end to end, whether or not the feature is enabled.

    Deliberately independent of resonance_enabled: an admin has to be able to
    test a key before turning it on, and to diagnose one after turning it off.

    On success this returns what the key actually grants — parts, cap, session
    TTL — read back from resonance rather than retyped by an admin, so the panel
    can show that (for example) mic is off on this key instead of leaving the
    user to wonder why the button never appears.
    """
    base_url = (body.base_url or "").strip()
    key = (body.key or "").strip()
    # The UI sends the mask back when the stored key was not retyped.
    if key == "••••••••":
        key = ""

    client = await _client(db, base_url, key)
    origin = await _effective_origin(db, request)

    if not client.configured:
        return {
            "ok": False,
            "error": ResonanceNotConfigured().admin_message,
            "origin": origin,
        }

    # Deliberately capped, though this is admin-only: resonance backs off per
    # source IP after failed key attempts, so a panel stuck in a retry loop would
    # dig the whole install into that hole while the admin watched.
    try:
        await limiter.consume(db, f"t:{user['username']}", TEST_LIMIT, TEST_WINDOW_SECONDS)
    except ResonanceError as err:
        return {"ok": False, "error": err.admin_message, "origin": origin}

    try:
        result = await client.create_session(user["username"], [user["role"]])
    except ResonanceError as err:
        # A failed test must NOT open the breaker. The values under test are
        # often not the stored ones, and an admin trying a key that turns out to
        # be wrong would otherwise take down a working widget for every user.
        return {"ok": False, "error": err.admin_message, "detail": err.detail, "origin": origin}

    # A successful test does clear it: fixing the key and pressing Test is the
    # intended way back from a breaker opened by the broken one.
    await limiter.record_success(db)
    return {
        "ok": True,
        "origin": origin,
        "detected_origin": _detected_origin(request),
        "user_id_sent": build_user_id(user["username"]),
        "parts": result.get("parts", []),
        "cap": result.get("cap", {}),
        "expires_in": result.get("expires_in"),
        "code_expires_in": result.get("code_expires_in"),
    }


@router.get("/status")
async def resonance_status(
    user: AdminUser, request: Request, db: aiosqlite.Connection = Depends(get_db)
):
    """Panel diagnostics: breaker state, recent client-side load failures, origin."""
    await reports.prune(db)
    return {
        "module_version": RESONANCE_MODULE_VERSION,
        "origin": await _effective_origin(db, request),
        "detected_origin": _detected_origin(request),
        "breaker": await limiter.state(db),
        "load_failures": await reports.summary(db, days=7),
    }


# ── Documentation, published for the assistant's knowledge ───────────────────
#
# Topic guardrails cannot be enforced from this side: the input box lives in
# resonance's iframe, on resonance's origin, and nothing this app sends
# constrains what gets answered. Scope is enforced by the resonance profile the
# key is authorised against — and a profile is only as well scoped as the corpus
# behind it. This endpoint is that corpus: the guides shipped with the running
# version, so upgrading the app updates what the assistant knows instead of
# leaving a profile quietly describing last year's UI.
#
# Documentation only. No log data, no user data, nothing from the settings
# table. Authenticated by the same suite token siblings already use, so it is
# revocable from Settings -> Integrations without touching the embed key.

DOC_SLUG_TITLES_FALLBACK = "Documentation"


def _suite_token_ok(request: Request) -> bool:
    from app.config import get_settings

    presented = request.headers.get("x-suite-token", "")
    configured = (get_settings().suite_token or "").strip()
    if not presented or not configured:
        return False
    return secrets.compare_digest(presented, configured)


@router.get("/docs")
async def resonance_docs(
    request: Request,
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Security(_bearer)] = None,
    db: aiosqlite.Connection = Depends(get_db),
):
    """Bundle every docs/*.md file with a hash, for resonance to ingest.

    Accepts the suite token, or an admin session so the Settings panel can show
    what would be published without holding a token of its own.

    Sends an ETag over the collected hashes and honours If-None-Match, so a
    resonance that polls costs a 304 rather than a re-ingest on every pass.
    """
    authorised = _suite_token_ok(request)
    if not authorised:
        try:
            from app.dependencies import get_current_user

            user = await get_current_user(request, db, credentials)
            authorised = user.get("role") == "admin"
        except Exception:
            authorised = False
    if not authorised:
        raise HTTPException(status_code=401, detail="Suite token or admin session required")

    from app.api.docs import _docs_dir, _title_from_filename
    from app.integrations.resonance import APP_SLUG
    from app.version import get_version

    documents = []
    docs_dir = _docs_dir()
    if docs_dir.is_dir():
        for path in sorted(docs_dir.glob("*.md")):
            try:
                content = path.read_text()
            except OSError as exc:
                log.warning("could not read %s for resonance publication: %s", path.name, exc)
                continue
            documents.append(
                {
                    "slug": path.stem,
                    "title": _title_from_filename(path.name),
                    "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                    "content": content,
                }
            )

    digest = hashlib.sha256(
        "".join(f"{d['slug']}:{d['sha256']}" for d in documents).encode("utf-8")
    ).hexdigest()
    etag = f'W/"{digest}"'

    if request.headers.get("if-none-match") == etag:
        return JSONResponse(status_code=304, content=None, headers={"ETag": etag})

    return JSONResponse(
        {
            "app": APP_SLUG,
            "app_version": get_version(),
            "module_version": RESONANCE_MODULE_VERSION,
            "etag": etag,
            "documents": documents,
        },
        headers={"ETag": etag},
    )
