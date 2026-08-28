"""
pktCert — FastAPI application entry point.
"""
from __future__ import annotations

import logging
import os.path
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.database import init_db, seed_admin

# -- Routers -------------------------------------------------------------------
from app.api import (
    auth,
    users,
    settings as settings_router,
    system as system_router,
    certificates as certificates_router,
    cas as cas_router,
    templates as templates_router,
    scan_targets as scan_targets_router,
    dashboard as dashboard_router,
    alerts as alerts_router,
    logs as logs_router,
    suite as suite_router,
    user_api_keys as user_api_keys_router,
    ip_info as ip_info_router,
    mxtoolbox as mxtoolbox_router,
    integrations as integrations_router,
    widgets as widgets_router,
    nav as nav_router,
    docs as docs_router,
    crl as crl_router,
    aia as aia_router,
    approvals as approvals_router,
    est as est_router,
    scep as scep_router,
    enrollment_profiles as enrollment_profiles_router,
)
from app.api import resonance as resonance_router
from app.api import resonance_data as resonance_data_router

settings = get_settings()
log = logging.getLogger("pktcert")

# install.sh always replaces these with a real random value before first
# run — reaching here with the placeholder still in place means config.yaml
# is missing/broken (or install.sh was skipped), and every JWT/encrypted
# secret would otherwise be forgeable/decryptable by anyone who reads this
# public source. Fail closed instead of silently signing tokens with a
# known key.
#
# Checks BOTH known placeholder spellings: app/config.py's own in-code
# fallback (used when the key is entirely absent from config.yaml) AND
# config.example.yaml's placeholder text (what an operator would actually
# have in config.yaml if they copied that file without editing it — a
# different string from the code fallback, so checking only one leaves the
# other route to a publicly-known secret completely unguarded).
_PLACEHOLDER_SECRETS = {
    "secret_key": {
        "", "CHANGE_ME_IN_PRODUCTION_secret_key_32chars",
        "CHANGE_ME_generate_with_openssl_rand_hex_32",
    },
    "credential_key": {
        "", "CHANGE_ME_generate_with_fernet_generate_key",
    },
}
for _field, _placeholders in _PLACEHOLDER_SECRETS.items():
    if getattr(settings, _field) in _placeholders:
        raise RuntimeError(
            f"config.yaml has no real '{_field}' set (missing or still the placeholder "
            "value) — refusing to start with a publicly-known secret. Run install.sh, "
            f"or set {_field} in config.yaml yourself (see config.example.yaml)."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    # -- Startup ---------------------------------------------------------------
    from app.logging_handler import SQLiteLogHandler
    _log_handler = SQLiteLogHandler(db_path=settings.db_path)
    _log_handler.attach_to_root_logger("pktcert")
    app.state.log_handler = _log_handler

    log.info("pktCert starting up")
    # Ship our own logs to pktLog if configured.
    try:
        import json as _json, logging as _logging
        import aiosqlite as _aio
        _fwd: dict = {}
        async with _aio.connect(settings.db_path) as _db:
            async with _db.execute(
                "SELECT key, value FROM settings WHERE key LIKE 'log_forward_%'"
            ) as _cur:
                for _k, _v in await _cur.fetchall():
                    try:
                        _fwd[_k] = _json.loads(_v)
                    except Exception:
                        _fwd[_k] = _v
        if _fwd.get("log_forward_enabled"):
            from app.log_forward import configure_forwarding
            configure_forwarding(
                enabled=True,
                host=str(_fwd.get("log_forward_host") or ""),
                port=int(_fwd.get("log_forward_port") or 5514),
                protocol=str(_fwd.get("log_forward_protocol") or "udp"),
                level=getattr(_logging, str(_fwd.get("log_forward_level") or "INFO"), _logging.INFO),
                app_name=str(_fwd.get("log_forward_app_name") or "pktcert"),
            )
    except Exception as _e:
        log.warning(f"Log forwarding setup skipped: {_e}")

    await init_db()
    log.info("Database migrations applied")

    await seed_admin()
    log.info("Admin seed check complete")

    from app.cert.alert_engine import AlertEngine
    alert_engine = AlertEngine()
    await alert_engine.start(settings.db_path)
    app.state.alert_engine = alert_engine

    from app.retention import RetentionScheduler
    retention = RetentionScheduler()
    await retention.start()
    app.state.retention = retention

    from app.cert.ct_discovery import CTDiscovery
    ct_discovery = CTDiscovery()
    await ct_discovery.start()
    app.state.ct_discovery = ct_discovery
    log.info("Alert engine started")

    from app.backup import BackupScheduler
    backup_scheduler = BackupScheduler()
    await backup_scheduler.start()
    log.info("Backup scheduler started")

    from app.cert.scanner import ScanEngine
    scan_engine = ScanEngine()
    await scan_engine.start(settings.db_path)
    app.state.scan_engine = scan_engine
    log.info("Certificate scan engine started")

    from app.cert.renewal import RenewalEngine
    renewal_engine = RenewalEngine()
    await renewal_engine.start(settings.db_path)
    app.state.renewal_engine = renewal_engine
    log.info("Certificate renewal engine started")

    yield

    # -- Shutdown ----------------------------------------------------------------
    log.info("pktCert shutting down")
    await renewal_engine.stop()
    await scan_engine.stop()
    await alert_engine.stop()
    await retention.stop()
    await ct_discovery.stop()
    await backup_scheduler.stop()
    _log_handler.stop()
    log.info("Shutdown complete")


# -- App -------------------------------------------------------------------------

app = FastAPI(
    title="pktCert",
    description="Enterprise certificate management — TLS discovery/inventory and internal CA/PKI issuance for the pkt suite",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

# -- Middleware --------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -- API Routers -----------------------------------------------------------------

app.include_router(auth.router,             prefix="/api/auth",         tags=["auth"])
app.include_router(users.router,            prefix="/api/users",        tags=["users"])
app.include_router(certificates_router.router, prefix="/api/certificates", tags=["certificates"])
app.include_router(cas_router.router,       prefix="/api/cas",          tags=["cas"])
app.include_router(templates_router.router, prefix="/api/templates",    tags=["templates"])
app.include_router(scan_targets_router.router, prefix="/api/scan-targets", tags=["scan-targets"])
app.include_router(dashboard_router.router, prefix="/api/dashboard",    tags=["dashboard"])
app.include_router(alerts_router.router,    prefix="/api/alerts",       tags=["alerts"])
app.include_router(logs_router.router,      prefix="/api/logs",         tags=["logs"])
app.include_router(settings_router.router,  prefix="/api/settings",     tags=["settings"])
app.include_router(system_router.router,    prefix="/api/system",       tags=["system"])
app.include_router(suite_router.router,     prefix="/api/suite",        tags=["suite"])
app.include_router(user_api_keys_router.router, prefix="/api/user-api-keys", tags=["user-api-keys"])
app.include_router(ip_info_router.router,   prefix="/api/ip-info",      tags=["ip-info"])
app.include_router(mxtoolbox_router.router, prefix="/api/mxtoolbox",    tags=["mxtoolbox"])
app.include_router(integrations_router.router, prefix="/api/integrations", tags=["integrations"])
app.include_router(widgets_router.router,   prefix="/api/widgets",      tags=["widgets"])
app.include_router(nav_router.router,       prefix="/api/nav",          tags=["nav"])
app.include_router(docs_router.router,      prefix="/api/docs-content", tags=["docs"])
app.include_router(resonance_router.router, prefix="/api/resonance",    tags=["resonance"])
# The assistant's data surface. Carries its own absolute paths — /api/resonance/data/*
# plus the two documents at /api/resonance/openapi.json and /.well-known/resonance.json —
# so it is mounted without a prefix, and before the SPA catch-all so the grant file wins
# over it.
app.include_router(resonance_data_router.router)
resonance_data_router.register_error_handler(app)
resonance_data_router.validate_grants(app)
app.include_router(approvals_router.router, prefix="/api/approvals",   tags=["approvals"])
app.include_router(enrollment_profiles_router.router, prefix="/api/enrollment-profiles", tags=["enrollment"])
# Deliberately outside /api and unauthenticated — see app/api/crl.py's
# module docstring for why. Registered before the SPA catch-all below so
# it takes priority over that route's broader "/{full_path:path}" pattern.
app.include_router(crl_router.router,       prefix="/crl",              tags=["crl"])
# Also deliberately outside /api and unauthenticated — a CA certificate is
# public by definition (see app/api/aia.py). Registered before the SPA
# catch-all so it wins over "/{full_path:path}".
app.include_router(aia_router.router,       prefix="/aia",              tags=["aia"])
# EST (RFC 7030). The path is fixed by the RFC — devices look at
# /.well-known/est and nowhere else — so it sits outside /api, and before
# the SPA catch-all.
app.include_router(est_router.router,       prefix="/.well-known/est",  tags=["est"])
# SCEP (RFC 8894). Also outside /api and before the SPA catch-all — /scep is
# the conventional path devices are configured with.
app.include_router(scep_router.router,      prefix="/scep",             tags=["scep"])

# -- Health check ------------------------------------------------------------------

@app.get("/api/health", tags=["system"])
async def health():
    return {"status": "ok", "version": "0.1.0"}

# -- Serve React frontend (production build) ---------------------------------------
_frontend_dist = Path(__file__).parent.parent / "frontend" / "dist"
if _frontend_dist.exists():
    app.mount("/assets", StaticFiles(directory=str(_frontend_dist / "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(request: Request, full_path: str):
        # /api/ and /.well-known/ are answered by real routes or not at all.
        # Falling through to index.html gave a 200 of HTML to anything asking
        # for a well-known document — resonance reading
        # /.well-known/resonance.json on an install that publishes none got a
        # page instead of an honest 404.
        if full_path.startswith("api/") or full_path.startswith(".well-known/"):
            raise HTTPException(status_code=404, detail="Not found")
        # Normalize-then-prefix-check (CodeQL's own documented pattern for
        # py/path-injection) rather than pathlib's resolve()/is_relative_to,
        # which its Python taint tracker doesn't recognize as a sanitizer.
        _dist_root = os.path.normpath(str(_frontend_dist))
        _candidate = os.path.normpath(os.path.join(_dist_root, full_path))
        if not (_candidate == _dist_root or _candidate.startswith(_dist_root + os.sep)):
            # Path traversal attempt (e.g. "../../config.yaml") — refuse to
            # serve anything outside the frontend dist directory.
            raise HTTPException(status_code=404, detail="Not found")
        static_file = Path(_candidate)
        if static_file.exists() and static_file.is_file():
            return FileResponse(str(static_file))
        index = _frontend_dist / "index.html"
        # index.html names the hashed bundles, so a cached copy pins the browser
        # to whatever build was current when it was cached — a deploy lands on
        # the server and the person reloading sees no change, with nothing in
        # the network log to explain it because the request never leaves the
        # browser. Vite fingerprints everything under /assets, so only this one
        # file must never be cached; the bundles it points at still can be.
        response = FileResponse(
            str(index),
            headers={"Cache-Control": "no-store, must-revalidate", "Pragma": "no-cache"},
        )
        # pktHub suite-token bootstrap — set sso cookies so React logs in automatically
        _cfg = settings
        _suite_tk = request.headers.get("x-suite-token", "")
        if _suite_tk and _cfg.suite_token and secrets.compare_digest(_suite_tk, _cfg.suite_token):
            from datetime import datetime, timedelta, timezone
            from jose import jwt as _jose_jwt
            from app.dependencies import _SUITE_ROLE_MAP
            _hub_user = request.headers.get("x-suite-user", "hub_user")
            _hub_role = request.headers.get("x-suite-role", "viewer")
            _local_role = _SUITE_ROLE_MAP.get(_hub_role, "viewer")
            _expire = datetime.now(tz=timezone.utc) + timedelta(hours=8)
            _payload = {"sub": "0", "role": _local_role, "exp": _expire, "type": "access"}
            _jwt = _jose_jwt.encode(_payload, _cfg.secret_key, algorithm=_cfg.algorithm)
            response.set_cookie("sso_access_token", _jwt,       max_age=60, httponly=False, samesite="lax")
            response.set_cookie("sso_role",         _local_role, max_age=60, httponly=False, samesite="lax")
        return response


# -- Entrypoint (used by systemd: python -m app.main) -----------------------------
if __name__ == "__main__":
    import json
    import sqlite3
    import uvicorn

    _db_path = Path(__file__).parent.parent / "pktcert.db"
    _ssl_enabled  = False
    _ssl_certfile = None
    _ssl_keyfile  = None
    try:
        _conn = sqlite3.connect(str(_db_path))
        for _key in ("ssl_enabled", "ssl_certfile", "ssl_keyfile"):
            _row = _conn.execute("SELECT value FROM settings WHERE key=?", (_key,)).fetchone()
            if _row:
                _val = json.loads(_row[0])
                if _key == "ssl_enabled":
                    _ssl_enabled = bool(_val)
                elif _key == "ssl_certfile":
                    _ssl_certfile = _val if _val else None
                elif _key == "ssl_keyfile":
                    _ssl_keyfile = _val if _val else None
        _conn.close()
    except Exception as _e:
        log.warning(f"Could not read SSL settings from config DB: {_e}")

    _bind_port = settings.https_port if _ssl_enabled else settings.port

    _uvicorn_kwargs = dict(
        host=settings.host,
        port=_bind_port,
        log_level=settings.log_level.lower(),
        workers=1,
    )

    _ssl_dir = Path(settings.ssl_dir)
    if not _ssl_certfile and (_ssl_dir / "server.crt").exists():
        _ssl_certfile = str(_ssl_dir / "server.crt")
    if not _ssl_keyfile and (_ssl_dir / "server.key").exists():
        _ssl_keyfile = str(_ssl_dir / "server.key")

    if _ssl_enabled and _ssl_certfile and _ssl_keyfile:
        _uvicorn_kwargs["ssl_certfile"] = _ssl_certfile
        _uvicorn_kwargs["ssl_keyfile"]  = _ssl_keyfile
        log.info(f"Starting with HTTPS on port {_bind_port}: cert={_ssl_certfile}")
    else:
        log.info(f"Starting with HTTP on port {_bind_port} (no SSL configured)")

    uvicorn.run("app.main:app", **_uvicorn_kwargs)
