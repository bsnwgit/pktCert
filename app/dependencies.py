"""
FastAPI dependency injection helpers.
"""
from __future__ import annotations
import secrets
from typing import Annotated, Optional
import aiosqlite
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.database import get_db
from app.auth.local import decode_access_token
from app.config import get_settings

DbDep = Annotated[aiosqlite.Connection, Depends(get_db)]

_bearer = HTTPBearer(auto_error=False)

_SUITE_ROLE_MAP = {
    "admin":   "admin",
    "analyst": "analyst",
    "viewer":  "viewer",
}


async def get_current_user(
    request: Request,
    db: DbDep,
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Security(_bearer)] = None,
) -> dict:
    """
    Auth path 1: X-Suite-Token from pktHub proxy — trust X-Suite-User/Role headers.
    Auth path 2: Authorization: Bearer JWT — normal pktCert local auth.
    """
    settings = get_settings()
    suite_token = request.headers.get("x-suite-token", "")
    if suite_token and settings.suite_token and secrets.compare_digest(suite_token, settings.suite_token):
        hub_user = request.headers.get("x-suite-user", "hub_user")
        hub_role = request.headers.get("x-suite-role", "viewer")
        local_role = _SUITE_ROLE_MAP.get(hub_role, "viewer")
        return {
            "id": 0,
            "username": hub_user,
            "email": f"{hub_user}@pkthub",
            "role": local_role,
            "is_active": True,
            "created_at": "2020-01-01 00:00:00",
            "last_login": None,
            "_via_suite": True,
        }

    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    payload = decode_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    async with db.execute(
        "SELECT id, username, email, role, is_active, created_at, last_login FROM users WHERE id = ?",
        (payload["sub"],),
    ) as cur:
        user = await cur.fetchone()
    if not user or not user["is_active"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return dict(user)


async def require_admin(user: Annotated[dict, Depends(get_current_user)]) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user


async def require_analyst(user: Annotated[dict, Depends(get_current_user)]) -> dict:
    if user["role"] not in ("admin", "analyst"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Analyst role or higher required")
    return user


async def require_suite_token(request: Request) -> None:
    """
    Gate for endpoints that are embedded unauthenticated (e.g. pktHub NOC
    Builder widget iframes, see app/api/widgets.py) and therefore can't go
    through the normal login/session flow, but still must not be reachable
    by literally anyone on the network. Requires a valid X-Suite-Token —
    the same trusted-proxy secret used by get_current_user above — and
    nothing else (no fallback to a user session).
    """
    settings = get_settings()
    suite_token = request.headers.get("x-suite-token", "")
    if not (suite_token and settings.suite_token and secrets.compare_digest(suite_token, settings.suite_token)):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Valid X-Suite-Token required")


CurrentUser  = Annotated[dict, Depends(get_current_user)]
AdminUser    = Annotated[dict, Depends(require_admin)]
AnalystUser  = Annotated[dict, Depends(require_analyst)]
