"""
pktCert — Widget endpoints for pktHub NOC Builder integration.

Manifest: GET /api/widgets/manifest  → list of widget definitions
Views:    GET /api/widgets/{id}      → server-rendered HTML page (iframe target)
"""
from __future__ import annotations

import html

import aiosqlite
from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse

from app.config import get_settings
from app.dependencies import require_suite_token

# These views are embedded as unauthenticated iframes by pktHub's NOC
# Builder, so they can't require a login session — but they render internal
# certificate inventory/alert data, so every route on this router requires
# a valid X-Suite-Token (same trusted-proxy secret pktHub already sends on
# every proxied request).
router = APIRouter(dependencies=[Depends(require_suite_token)])
_s     = get_settings()
_DB    = _s.db_path

# ── Manifest ──────────────────────────────────────────────────────────────────
MANIFEST = [
    {
        "id": "cert_summary", "title": "Certificate Summary",
        "description": "Total/valid/expiring/expired/revoked counts across the inventory",
        "view_path": "/api/widgets/cert_summary",
        "default_w": 460, "default_h": 220, "min_w": 300, "min_h": 160,
    },
    {
        "id": "expiring_certificates", "title": "Expiring Certificates",
        "description": "Certificates expiring or already expired, soonest first",
        "view_path": "/api/widgets/expiring_certificates",
        "default_w": 640, "default_h": 380, "min_w": 340, "min_h": 220,
    },
    {
        "id": "active_alerts", "title": "Active Alerts",
        "description": "Unresolved certificate/CA alert events",
        "view_path": "/api/widgets/active_alerts",
        "default_w": 640, "default_h": 360, "min_w": 320, "min_h": 200,
    },
]


@router.get("/manifest")
async def widget_manifest():
    return MANIFEST


# ── Shared page shell ───────────────────────────────────────────────────────────
def _page(title: str, body: str) -> str:
    return f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0a1628;color:#e2e8f0;font-family:'Inter',system-ui,sans-serif;font-size:13px;height:100vh;overflow:hidden;display:flex;flex-direction:column}}
.hdr{{padding:8px 14px;border-bottom:1px solid #1e293b;display:flex;align-items:center;gap:8px;flex-shrink:0;height:36px}}
.hdr-dot{{width:6px;height:6px;border-radius:50%;background:#818cf8;flex-shrink:0}}
.hdr-title{{font-size:11px;font-weight:600;color:#94a3b8;letter-spacing:0.03em}}
.content{{flex:1;overflow:auto;padding:12px}}
table{{width:100%;border-collapse:collapse}}
th{{text-align:left;font-size:10px;color:#475569;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;padding:4px 8px;border-bottom:1px solid #1e293b}}
td{{padding:6px 8px;border-bottom:1px solid #0f172a;font-size:12px;color:#cbd5e1}}
tr:hover td{{background:#111827}}
.badge{{display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:600}}
.bg{{background:#052e16;color:#4ade80}}.br{{background:#3f1515;color:#f87171}}
.by{{background:#422006;color:#fbbf24}}.bn{{background:#1e293b;color:#64748b}}
.empty{{text-align:center;padding:40px;color:#334155;font-size:12px}}
.tile-row{{display:flex;gap:14px;margin-bottom:14px;flex-wrap:wrap}}
.tile{{flex:1;min-width:90px;background:#111827;border:1px solid #1e293b;border-radius:8px;padding:10px 12px}}
.tile-label{{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:4px}}
.tile-value{{font-size:22px;font-weight:700;color:#e2e8f0}}
</style>
<script>setTimeout(()=>location.reload(),30000)</script>
</head><body>
<div class="hdr"><div class="hdr-dot"></div><div class="hdr-title">{title}</div></div>
<div class="content">{body}</div>
</body></html>"""


def _status_badge(status: str) -> str:
    s = (status or "").lower()
    if s == "valid":
        return '<span class="badge bg">VALID</span>'
    if s == "expiring":
        return '<span class="badge by">EXPIRING</span>'
    if s in ("expired", "revoked"):
        return '<span class="badge br">{}</span>'.format(html.escape(s.upper()))
    return f'<span class="badge bn">{html.escape((status or "UNKNOWN").upper())}</span>'


# ── Certificate Summary widget ─────────────────────────────────────────────────
@router.get("/cert_summary", response_class=HTMLResponse, include_in_schema=False)
async def widget_cert_summary():
    counts = {"valid": 0, "expiring": 0, "expired": 0, "revoked": 0}
    try:
        async with aiosqlite.connect(_DB) as db:
            async with db.execute("SELECT status, COUNT(*) FROM certificates GROUP BY status") as cur:
                for status, n in await cur.fetchall():
                    if status in counts:
                        counts[status] = n
    except Exception:
        pass

    total = sum(counts.values())
    tiles = "".join(
        f'<div class="tile"><div class="tile-label">{label}</div><div class="tile-value">{n}</div></div>'
        for label, n in [("Total", total), ("Valid", counts["valid"]), ("Expiring", counts["expiring"]),
                          ("Expired", counts["expired"]), ("Revoked", counts["revoked"])]
    )
    body = f'<div class="tile-row">{tiles}</div>'
    return HTMLResponse(_page("Certificate Summary", body))


# ── Expiring Certificates widget ───────────────────────────────────────────────
@router.get("/expiring_certificates", response_class=HTMLResponse, include_in_schema=False)
async def widget_expiring_certificates():
    rows = []
    try:
        async with aiosqlite.connect(_DB) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """SELECT common_name, status, source, not_after FROM certificates
                   WHERE status IN ('expiring', 'expired') ORDER BY not_after ASC LIMIT 40"""
            ) as cur:
                rows = [dict(r) for r in await cur.fetchall()]
    except Exception:
        pass

    if rows:
        trs = "".join(
            f"<tr><td>{html.escape(str(r['common_name']))}</td><td>{_status_badge(r['status'])}</td>"
            f"<td>{html.escape((r.get('source') or '').upper())}</td><td>{html.escape(str(r['not_after'] or '')[:19].replace('T', ' '))}</td></tr>"
            for r in rows
        )
        body = (
            "<table><thead><tr><th>Common Name</th><th>Status</th><th>Source</th><th>Expires</th></tr></thead>"
            f"<tbody>{trs}</tbody></table>"
        )
    else:
        body = '<div class="empty">Nothing expiring</div>'
    return HTMLResponse(_page("Expiring Certificates", body))


# ── Active Alerts widget ──────────────────────────────────────────────────────
@router.get("/active_alerts", response_class=HTMLResponse, include_in_schema=False)
async def widget_active_alerts():
    rows = []
    try:
        async with aiosqlite.connect(_DB) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """SELECT ae.severity, ae.message, ae.created_at, c.common_name
                   FROM alert_events ae LEFT JOIN certificates c ON c.id = ae.certificate_id
                   WHERE ae.active = 1 AND ae.acked = 0
                   ORDER BY ae.created_at DESC LIMIT 40"""
            ) as cur:
                rows = [dict(r) for r in await cur.fetchall()]
    except Exception:
        pass

    if rows:
        trs = "".join(
            f"<tr><td>{_status_badge('expired' if r['severity'] == 'critical' else 'expiring')}</td>"
            f"<td>{html.escape(str(r.get('common_name') or ''))}</td><td>{html.escape(str(r['message']))}</td>"
            f"<td>{html.escape(str(r['created_at'])[:19].replace('T',' '))}</td></tr>"
            for r in rows
        )
        body = (
            "<table><thead><tr><th>Severity</th><th>Certificate</th><th>Message</th><th>Fired</th></tr></thead>"
            f"<tbody>{trs}</tbody></table>"
        )
    else:
        body = '<div class="empty">No active alerts</div>'
    return HTMLResponse(_page("Active Alerts", body))
