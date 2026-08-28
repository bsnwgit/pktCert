"""
pktCert — Navigation manifest for pktHub's APPS sidebar.

Manifest: GET /api/nav/manifest  → this app's own left-nav, in display order

pktHub mirrors these entries under pktCert in its own sidebar and opens each
one as a chromeless embed of the real page (`/proxy/<app_id><path>?chromeless=1`),
so the hub's menu is this app's menu rather than a re-implementation of it.

Keep in step with NAV in frontend/src/components/Layout.tsx — that const is
what this app renders for a direct visit, this manifest is what the hub
renders. Same menu, two consumers: a page added to one belongs in the other.
"""
from __future__ import annotations

import aiosqlite
from fastapi import APIRouter, Depends

from app.api.approvals import approval_required
from app.database import get_db
from app.dependencies import require_suite_token

# Fetched unauthenticated by pktHub's health poller, and it discloses this
# app's page structure — so it carries the same X-Suite-Token gate as the
# widget endpoints in app/api/widgets.py.
router = APIRouter(dependencies=[Depends(require_suite_token)])

# ── Manifest ──────────────────────────────────────────────────────────────────
# `path` is relative to this app's root. `icon` is the same glyph the app's own
# sidebar draws, so the hub renders a visually identical row.
NAV_MANIFEST = [
    {"path": "/",                        "label": "Dashboard",               "icon": "◑", "admin_only": False},
    {"path": "/scan-targets",            "label": "Scan Targets",            "icon": "⌕", "admin_only": False},
    {"path": "/certificates",            "label": "Certificates",            "icon": "▤", "admin_only": False, "divider_before": True},
    {"path": "/certificate-authorities", "label": "Certificate Authorities", "icon": "⛨", "admin_only": False},
    {"path": "/alerts",                  "label": "Alerts",                  "icon": "△", "admin_only": False, "divider_before": True},
    {"path": "/logs",                    "label": "Logs",                    "icon": "☰", "admin_only": False},
    {"path": "/settings",                "label": "Settings",                "icon": "⚙", "admin_only": True,  "divider_before": True},
]

# Approvals sits between Certificate Authorities and Alerts, but only when
# separation of duties is actually switched on — the sidebar applies the same
# condition via approvalsOnly, and a queue nobody uses is just a dead link.
_APPROVALS_ENTRY = {"path": "/approvals", "label": "Approvals", "icon": "✓", "admin_only": False}
_APPROVALS_AFTER = "/certificate-authorities"


@router.get("/manifest")
async def nav_manifest(db: aiosqlite.Connection = Depends(get_db)):
    if not await _approvals_visible(db):
        return NAV_MANIFEST
    out = []
    for entry in NAV_MANIFEST:
        out.append(entry)
        if entry["path"] == _APPROVALS_AFTER:
            out.append(_APPROVALS_ENTRY)
    return out


async def _approvals_visible(db: aiosqlite.Connection) -> bool:
    """Mirrors approvalsVisible in the sidebar: show the queue if either
    approval gate is on, or if something is already waiting in it."""
    try:
        if await approval_required(db, "issue") or await approval_required(db, "revoke"):
            return True
        async with db.execute("SELECT COUNT(*) FROM cert_requests WHERE status = 'pending'") as cur:
            return (await cur.fetchone())[0] > 0
    except Exception:
        # Never let this break the manifest — the hub would lose the whole menu
        # over one optional row.
        return False
