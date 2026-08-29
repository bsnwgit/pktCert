"""
pktCert — Widget endpoints for pktHub NOC Builder integration.

Manifest: GET /api/widgets/manifest  → list of widget definitions
Views:    GET /api/widgets/{id}      → server-rendered HTML page (iframe target)
"""
from __future__ import annotations

import html
from contextvars import ContextVar

import aiosqlite
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from app.config import get_settings
from app.dependencies import require_suite_token

# These views are embedded as unauthenticated iframes by pktHub's NOC
# Builder, so they can't require a login session — but they render internal
# certificate inventory/alert data, so every route on this router requires
# a valid X-Suite-Token (same trusted-proxy secret pktHub already sends on
# every proxied request).
# ── Refresh interval ──────────────────────────────────────────────────────────
# pktHub's Settings → NOC → "Widget refresh" governs how often a tile reloads
# itself. It arrives as ?refresh=<seconds> on the widget URL; captured here as a
# router dependency so the ~150 view functions need no signature change.
_REFRESH: ContextVar = ContextVar("widget_refresh", default=30)


async def _capture_refresh(request: Request) -> None:
    raw = request.query_params.get("refresh")
    try:
        _REFRESH.set(max(5, min(int(raw), 3600)) if raw else 30)
    except (TypeError, ValueError):
        _REFRESH.set(30)


router = APIRouter(dependencies=[Depends(_capture_refresh), Depends(require_suite_token)])
_s     = get_settings()
_DB    = _s.db_path

# ── Manifest ──────────────────────────────────────────────────────────────────
# `category` groups these in pktHub's NOC library picker. Every data surface the
# app renders in its own UI should have an entry here — the NOC builder can only
# offer what this list declares.
MANIFEST = [
    # ── Overview ──────────────────────────────────────────────────────────────
    {
        "id": "cert_summary", "title": "Certificate Summary", "category": "Overview",
        "description": "Total/valid/expiring/expired/revoked counts across the inventory",
        "view_path": "/api/widgets/cert_summary",
        "default_w": 460, "default_h": 220, "min_w": 300, "min_h": 160,
    },
    {
        "id": "alert_summary", "title": "Alert Summary", "category": "Overview",
        "description": "Active alert counts by severity",
        "view_path": "/api/widgets/alert_summary",
        "default_w": 420, "default_h": 200, "min_w": 260, "min_h": 150,
    },
    {
        "id": "expiry_timeline", "title": "Expiry Timeline", "category": "Overview",
        "description": "Certificates falling due in the next 7, 30, 60 and 90 days",
        "view_path": "/api/widgets/expiry_timeline",
        "default_w": 480, "default_h": 280, "min_w": 280, "min_h": 170,
    },
    {
        "id": "certs_by_source", "title": "Certificates by Source", "category": "Overview",
        "description": "Inventory split across scan, CT log and locally issued",
        "view_path": "/api/widgets/certs_by_source",
        "default_w": 440, "default_h": 260, "min_w": 260, "min_h": 160,
    },

    # ── Certificates ──────────────────────────────────────────────────────────
    {
        "id": "expiring_certificates", "title": "Expiring Certificates", "category": "Certificates",
        "description": "Certificates expiring or already expired, soonest first",
        "view_path": "/api/widgets/expiring_certificates",
        "default_w": 640, "default_h": 380, "min_w": 340, "min_h": 220,
    },
    {
        "id": "recent_certificates", "title": "Recently Discovered", "category": "Certificates",
        "description": "Certificates first seen most recently",
        "view_path": "/api/widgets/recent_certificates",
        "default_w": 680, "default_h": 360, "min_w": 340, "min_h": 200,
    },
    {
        "id": "certs_by_issuer", "title": "Certificates by Issuer", "category": "Certificates",
        "description": "Which authorities the estate depends on",
        "view_path": "/api/widgets/certs_by_issuer",
        "default_w": 560, "default_h": 340, "min_w": 300, "min_h": 200,
    },
    {
        "id": "key_strength", "title": "Key Strength", "category": "Certificates",
        "description": "Certificate distribution across key algorithm and size",
        "view_path": "/api/widgets/key_strength",
        "default_w": 500, "default_h": 300, "min_w": 280, "min_h": 180,
    },
    {
        "id": "weak_certificates", "title": "Weak Certificates", "category": "Certificates",
        "description": "Undersized RSA keys and SHA-1 signatures still in the inventory",
        "view_path": "/api/widgets/weak_certificates",
        "default_w": 680, "default_h": 340, "min_w": 340, "min_h": 200,
    },

    # ── Authorities ───────────────────────────────────────────────────────────
    {
        "id": "ca_status", "title": "CA Status", "category": "Authorities",
        "description": "Certificate authorities with type, status and expiry",
        "view_path": "/api/widgets/ca_status",
        "default_w": 660, "default_h": 320, "min_w": 340, "min_h": 180,
    },
    {
        "id": "ca_issuance", "title": "CA Issuance", "category": "Authorities",
        "description": "Certificates issued per authority",
        "view_path": "/api/widgets/ca_issuance",
        "default_w": 520, "default_h": 300, "min_w": 280, "min_h": 180,
    },

    # ── Discovery ─────────────────────────────────────────────────────────────
    {
        "id": "scan_targets", "title": "Scan Targets", "category": "Discovery",
        "description": "Discovery target health and last scan outcome",
        "view_path": "/api/widgets/scan_targets",
        "default_w": 680, "default_h": 340, "min_w": 340, "min_h": 200,
    },
    {
        "id": "cert_events", "title": "Certificate Events", "category": "Discovery",
        "description": "Recent discovery, issuance, renewal and revocation events",
        "view_path": "/api/widgets/cert_events",
        "default_w": 700, "default_h": 360, "min_w": 340, "min_h": 200,
    },
    {
        "id": "enrollment_activity", "title": "Enrollment Activity", "category": "Discovery",
        "description": "Recent EST/SCEP enrollment outcomes",
        "view_path": "/api/widgets/enrollment_activity",
        "default_w": 700, "default_h": 340, "min_w": 340, "min_h": 200,
    },

    # ── Alerts ────────────────────────────────────────────────────────────────
    {
        "id": "active_alerts", "title": "Active Alerts", "category": "Alerts",
        "description": "Unresolved certificate/CA alert events",
        "view_path": "/api/widgets/active_alerts",
        "default_w": 640, "default_h": 360, "min_w": 320, "min_h": 200,
    },
]


@router.get("/manifest")
async def widget_manifest():
    return MANIFEST



# ── Widget states ──────────────────────────────────────────────────────────────
# A blank tile on a wallboard reads as "all quiet", so the three reasons a widget
# can show nothing must look different from each other:
#   empty — the query ran and there genuinely is nothing
#   cfg   — the widget needs a param chosen in the NOC editor before it can run
#   err   — the query failed; this must never be mistaken for "nothing to report"
# Query helpers record failures here rather than swallowing them; _page() renders
# the error state instead of whatever half-built body the caller produced. The
# ContextVar is per-request: each request runs in its own task context.
_WIDGET_ERR: ContextVar = ContextVar("widget_err", default=None)


def _note_err(exc: BaseException) -> None:
    _WIDGET_ERR.set(f"{type(exc).__name__}: {exc}"[:200])


def _state(kind: str, msg: str, sub: str = "") -> str:
    icon = {"empty": "○", "cfg": "⚙", "err": "⚠"}.get(kind, "○")
    sub_html = f'<div class="state-sub">{html.escape(str(sub))}</div>' if sub else ""
    return (f'<div class="state state-{kind}"><div class="state-icon">{icon}</div>'
            f'<div class="state-msg">{html.escape(str(msg))}</div>{sub_html}</div>')


def _empty(msg: str) -> str:
    return _state("empty", msg)


def _needs(msg: str) -> str:
    """The widget is fine — it is waiting on a filter the NOC editor must set."""
    return _state("cfg", msg, "Select it in the widget's Filters panel")


# ── Shared page shell ───────────────────────────────────────────────────────────
def _page(title: str, body: str) -> str:
    # Widget titles carry device/metric/subnet names chosen in the NOC editor
    # and read back from device data, and these pages render on an
    # unauthenticated display URL — escape before interpolating.
    title = html.escape(str(title))
    # A failed query leaves a body saying "nothing here" — which is a lie.
    _err = _WIDGET_ERR.get()
    if _err:
        body = _state("err", "Widget unavailable", _err)
    return f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#04060a;color:#e2e8f0;font-family:'Inter',system-ui,sans-serif;font-size:13px;height:100vh;overflow:hidden;display:flex;flex-direction:column}}
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
.bar-row{{display:flex;align-items:center;gap:8px;margin-bottom:8px}}
.bar-lbl{{font-size:11px;color:#94a3b8;width:150px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.bar-trk{{flex:1;background:#1e293b;border-radius:3px;height:8px;overflow:hidden}}
.bar-fill{{height:8px;border-radius:3px;background:#818cf8}}
.bar-val{{font-size:10px;color:#475569;width:56px;text-align:right;flex-shrink:0}}
.state{{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;min-height:80px;text-align:center;padding:18px;gap:5px}}
.state-icon{{font-size:17px;line-height:1;opacity:0.85}}
.state-msg{{font-size:12px;font-weight:500}}
.state-sub{{font-size:10px;color:#64748b;max-width:92%;word-break:break-word}}
.state-empty{{color:#64748b}}
.state-cfg{{color:#fbbf24}}
.state-err{{color:#f87171}}
</style>
<script>setTimeout(()=>location.reload(),{_REFRESH.get() * 1000})</script>
</head><body>
<div class="hdr"><div class="hdr-dot"></div><div class="hdr-title">{title}</div></div>
<div class="content">{body}</div>
</body></html>"""


def _status_badge(status: str) -> str:
    s = (status or "").lower()
    if s in ("valid", "active", "ok", "issued"):
        return '<span class="badge bg">{}</span>'.format(html.escape(s.upper()))
    if s == "expiring":
        return '<span class="badge by">EXPIRING</span>'
    if s in ("expired", "revoked", "error", "denied"):
        return '<span class="badge br">{}</span>'.format(html.escape(s.upper()))
    return f'<span class="badge bn">{html.escape((status or "UNKNOWN").upper())}</span>'


# ── Query helper ────────────────────────────────────────────────────────────────
async def _rows(sql: str, params: tuple = ()) -> list[dict]:
    try:
        async with aiosqlite.connect(_DB) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(sql, params) as cur:
                return [dict(r) for r in await cur.fetchall()]
    except Exception as exc:
        _note_err(exc)
        return []


def _fmt_ts(ts) -> str:
    return str(ts)[:19].replace("T", " ") if ts else "—"


# ── Tiles / bars ────────────────────────────────────────────────────────────────
def _tiles(pairs) -> str:
    return '<div class="tile-row">' + "".join(
        f'<div class="tile"><div class="tile-label">{html.escape(str(label))}</div>'
        f'<div class="tile-value">{html.escape(str(value))}</div></div>'
        for label, value in pairs
    ) + "</div>"


def _bars(rows, color: str = "#818cf8") -> str:
    """rows = [(label, numeric_value, display_value)] — scaled to the largest."""
    peak = max((r[1] or 0) for r in rows) if rows else 0
    return "".join(
        f'<div class="bar-row"><div class="bar-lbl" title="{html.escape(str(lbl))}">{html.escape(str(lbl))}</div>'
        f'<div class="bar-trk"><div class="bar-fill" style="width:{(val / peak * 100) if peak else 0:.1f}%;background:{color}"></div></div>'
        f'<div class="bar-val">{html.escape(str(disp))}</div></div>'
        for lbl, val, disp in rows
    )


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
    except Exception as exc:
        _note_err(exc)

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
    except Exception as exc:
        _note_err(exc)

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
        body = _empty('Nothing expiring')
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
    except Exception as exc:
        _note_err(exc)

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
        body = _empty('No active alerts')
    return HTMLResponse(_page("Active Alerts", body))


# ── Alert Summary widget ──────────────────────────────────────────────────────
@router.get("/alert_summary", response_class=HTMLResponse, include_in_schema=False)
async def widget_alert_summary():
    rows   = await _rows(
        "SELECT LOWER(severity) AS sev, COUNT(*) AS n FROM alert_events "
        "WHERE active = 1 AND acked = 0 GROUP BY sev"
    )
    counts = {r["sev"]: r["n"] for r in rows}
    body   = _tiles([
        ("Active",   sum(counts.values())),
        ("Critical", counts.get("critical", 0)),
        ("Warning",  counts.get("warning", 0)),
        ("Info",     counts.get("info", 0)),
    ])
    return HTMLResponse(_page("Alert Summary", body))


# ── Expiry Timeline widget ────────────────────────────────────────────────────
@router.get("/expiry_timeline", response_class=HTMLResponse, include_in_schema=False)
async def widget_expiry_timeline():
    # Buckets are cumulative windows from now, so a cert due in 5 days counts in
    # every bucket it falls inside — that is how a renewal backlog is read.
    rows = await _rows(
        """SELECT
             SUM(CASE WHEN not_after < datetime('now') THEN 1 ELSE 0 END) AS overdue,
             SUM(CASE WHEN not_after >= datetime('now') AND not_after < datetime('now','+7 days')  THEN 1 ELSE 0 END) AS d7,
             SUM(CASE WHEN not_after >= datetime('now') AND not_after < datetime('now','+30 days') THEN 1 ELSE 0 END) AS d30,
             SUM(CASE WHEN not_after >= datetime('now') AND not_after < datetime('now','+60 days') THEN 1 ELSE 0 END) AS d60,
             SUM(CASE WHEN not_after >= datetime('now') AND not_after < datetime('now','+90 days') THEN 1 ELSE 0 END) AS d90
           FROM certificates WHERE status <> 'revoked' AND not_after IS NOT NULL"""
    )
    r = rows[0] if rows else {}
    buckets = [
        ("Already expired", r.get("overdue") or 0),
        ("Within 7 days",   r.get("d7")  or 0),
        ("Within 30 days",  r.get("d30") or 0),
        ("Within 60 days",  r.get("d60") or 0),
        ("Within 90 days",  r.get("d90") or 0),
    ]
    body = _bars([(lbl, n, str(n)) for lbl, n in buckets])
    return HTMLResponse(_page("Expiry Timeline", body))


# ── Certificates by Source widget ─────────────────────────────────────────────
@router.get("/certs_by_source", response_class=HTMLResponse, include_in_schema=False)
async def widget_certs_by_source():
    rows = await _rows(
        "SELECT COALESCE(NULLIF(source,''),'unknown') AS source, COUNT(*) AS n "
        "FROM certificates GROUP BY source ORDER BY n DESC"
    )
    body = _bars([(r["source"], r["n"], str(r["n"])) for r in rows]) \
        if rows else _empty('No certificates discovered or issued yet')
    return HTMLResponse(_page("Certificates by Source", body))


# ── Recently Discovered widget ────────────────────────────────────────────────
@router.get("/recent_certificates", response_class=HTMLResponse, include_in_schema=False)
async def widget_recent_certificates():
    rows = await _rows(
        """SELECT common_name, issuer, source, status, host, port, first_seen_at
           FROM certificates ORDER BY first_seen_at DESC LIMIT 40"""
    )
    if rows:
        trs = "".join(
            f"<tr><td>{html.escape(str(r['common_name']))}</td>"
            f"<td>{html.escape(str(r.get('issuer') or ''))[:40]}</td>"
            f"<td>{html.escape(str(r.get('host') or ''))}"
            f"{(':' + str(r['port'])) if r.get('port') else ''}</td>"
            f"<td>{_status_badge(r['status'])}</td>"
            f"<td>{html.escape(_fmt_ts(r.get('first_seen_at')))}</td></tr>"
            for r in rows
        )
        body = ("<table><thead><tr><th>Common Name</th><th>Issuer</th><th>Host</th>"
                "<th>Status</th><th>First Seen</th></tr></thead>"
                f"<tbody>{trs}</tbody></table>")
    else:
        body = _empty('No certificates discovered or issued yet')
    return HTMLResponse(_page("Recently Discovered", body))


# ── Certificates by Issuer widget ─────────────────────────────────────────────
@router.get("/certs_by_issuer", response_class=HTMLResponse, include_in_schema=False)
async def widget_certs_by_issuer():
    rows = await _rows(
        "SELECT COALESCE(NULLIF(issuer,''),'unknown') AS issuer, COUNT(*) AS n "
        "FROM certificates GROUP BY issuer ORDER BY n DESC LIMIT 20"
    )
    body = _bars([(r["issuer"], r["n"], str(r["n"])) for r in rows]) \
        if rows else _empty('No certificates discovered or issued yet')
    return HTMLResponse(_page("Certificates by Issuer", body))


# ── Key Strength widget ───────────────────────────────────────────────────────
@router.get("/key_strength", response_class=HTMLResponse, include_in_schema=False)
async def widget_key_strength():
    rows = await _rows(
        """SELECT COALESCE(NULLIF(key_algorithm,''),'unknown') AS alg, key_size, COUNT(*) AS n
           FROM certificates GROUP BY alg, key_size ORDER BY n DESC LIMIT 20"""
    )
    body = _bars([
        (f"{r['alg'].upper()}{(' ' + str(r['key_size'])) if r.get('key_size') else ''}",
         r["n"], str(r["n"]))
        for r in rows
    ]) if rows else _empty('No certificates discovered or issued yet')
    return HTMLResponse(_page("Key Strength", body))


# ── Weak Certificates widget ──────────────────────────────────────────────────
@router.get("/weak_certificates", response_class=HTMLResponse, include_in_schema=False)
async def widget_weak_certificates():
    # RSA under 2048 bits and any SHA-1 signature are the two findings worth a
    # NOC wall; both are long past deprecation.
    rows = await _rows(
        """SELECT common_name, key_algorithm, key_size, signature_algorithm, status, not_after
           FROM certificates
           WHERE status <> 'revoked'
             AND ((LOWER(key_algorithm) = 'rsa' AND key_size IS NOT NULL AND key_size < 2048)
                  OR LOWER(signature_algorithm) LIKE '%sha1%')
           ORDER BY key_size ASC LIMIT 40"""
    )
    if rows:
        trs = "".join(
            f"<tr><td>{html.escape(str(r['common_name']))}</td>"
            f"<td>{html.escape(str(r.get('key_algorithm') or '').upper())} "
            f"{r.get('key_size') or ''}</td>"
            f"<td>{html.escape(str(r.get('signature_algorithm') or ''))}</td>"
            f"<td>{_status_badge(r['status'])}</td></tr>"
            for r in rows
        )
        body = ("<table><thead><tr><th>Common Name</th><th>Key</th>"
                "<th>Signature</th><th>Status</th></tr></thead>"
                f"<tbody>{trs}</tbody></table>")
    else:
        body = _empty('No undersized keys or SHA-1 signatures found')
    return HTMLResponse(_page("Weak Certificates", body))


# ── CA Status widget ──────────────────────────────────────────────────────────
@router.get("/ca_status", response_class=HTMLResponse, include_in_schema=False)
async def widget_ca_status():
    rows = await _rows(
        """SELECT name, ca_type, status, key_algorithm, key_size, not_after, source
           FROM certificate_authorities ORDER BY ca_type, name"""
    )
    if rows:
        trs = "".join(
            f"<tr><td>{html.escape(str(r['name']))}</td>"
            f"<td>{html.escape(str(r.get('ca_type') or ''))}</td>"
            f"<td>{_status_badge(r['status'])}</td>"
            f"<td>{html.escape(str(r.get('key_algorithm') or '').upper())} {r.get('key_size') or ''}</td>"
            f"<td>{html.escape(_fmt_ts(r.get('not_after')))}</td></tr>"
            for r in rows
        )
        body = ("<table><thead><tr><th>Authority</th><th>Type</th><th>Status</th>"
                "<th>Key</th><th>Expires</th></tr></thead>"
                f"<tbody>{trs}</tbody></table>")
    else:
        body = _empty('No certificate authorities configured')
    return HTMLResponse(_page("CA Status", body))


# ── CA Issuance widget ────────────────────────────────────────────────────────
@router.get("/ca_issuance", response_class=HTMLResponse, include_in_schema=False)
async def widget_ca_issuance():
    rows = await _rows(
        """SELECT ca.name, COUNT(c.id) AS n
           FROM certificate_authorities ca
           LEFT JOIN certificates c ON c.ca_id = ca.id
           GROUP BY ca.id ORDER BY n DESC"""
    )
    body = _bars([(r["name"], r["n"], str(r["n"])) for r in rows]) \
        if rows else _empty('No certificate authorities configured')
    return HTMLResponse(_page("CA Issuance", body))


# ── Scan Targets widget ───────────────────────────────────────────────────────
@router.get("/scan_targets", response_class=HTMLResponse, include_in_schema=False)
async def widget_scan_targets():
    rows = await _rows(
        """SELECT name, host, cidr, ports, enabled, last_scan_at, last_status, last_error
           FROM scan_targets ORDER BY
             CASE last_status WHEN 'error' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END, name"""
    )
    if rows:
        trs = "".join(
            f"<tr><td>{html.escape(str(r['name']))}</td>"
            f"<td>{html.escape(str(r.get('host') or r.get('cidr') or ''))}</td>"
            f"<td>{html.escape(str(r.get('ports') or ''))}</td>"
            f"<td>{_status_badge(r.get('last_status') if r.get('enabled') else 'disabled')}</td>"
            f"<td>{html.escape(_fmt_ts(r.get('last_scan_at')))}</td></tr>"
            for r in rows
        )
        body = ("<table><thead><tr><th>Target</th><th>Scope</th><th>Ports</th>"
                "<th>Last Status</th><th>Last Scan</th></tr></thead>"
                f"<tbody>{trs}</tbody></table>")
    else:
        body = _empty('No discovery targets configured')
    return HTMLResponse(_page("Scan Targets", body))


# ── Certificate Events widget ─────────────────────────────────────────────────
@router.get("/cert_events", response_class=HTMLResponse, include_in_schema=False)
async def widget_cert_events():
    rows = await _rows(
        """SELECT e.event_type, e.message, e.created_at, c.common_name
           FROM cert_events e LEFT JOIN certificates c ON c.id = e.certificate_id
           ORDER BY e.created_at DESC LIMIT 40"""
    )
    if rows:
        def _evt(t: str) -> str:
            t = (t or "").lower()
            if t in ("revoked", "scan_failed"):
                return f'<span class="badge br">{html.escape(t.upper())}</span>'
            if t == "expiring_soon":
                return '<span class="badge by">EXPIRING</span>'
            if t in ("issued", "renewed"):
                return f'<span class="badge bg">{html.escape(t.upper())}</span>'
            return f'<span class="badge bn">{html.escape(t.upper())}</span>'

        trs = "".join(
            f"<tr><td>{html.escape(_fmt_ts(r['created_at']))}</td>"
            f"<td>{_evt(r['event_type'])}</td>"
            f"<td>{html.escape(str(r.get('common_name') or ''))}</td>"
            f"<td>{html.escape(str(r.get('message') or ''))[:70]}</td></tr>"
            for r in rows
        )
        body = ("<table><thead><tr><th>Time</th><th>Event</th><th>Certificate</th>"
                "<th>Detail</th></tr></thead>"
                f"<tbody>{trs}</tbody></table>")
    else:
        body = _empty('No events')
    return HTMLResponse(_page("Certificate Events", body))


# ── Enrollment Activity widget ────────────────────────────────────────────────
@router.get("/enrollment_activity", response_class=HTMLResponse, include_in_schema=False)
async def widget_enrollment_activity():
    rows = await _rows(
        """SELECT protocol, operation, client_ip, subject, outcome, created_at
           FROM enrollment_log ORDER BY created_at DESC LIMIT 40"""
    )
    if rows:
        trs = "".join(
            f"<tr><td>{html.escape(_fmt_ts(r['created_at']))}</td>"
            f"<td>{html.escape(str(r.get('protocol') or '').upper())}</td>"
            f"<td>{html.escape(str(r.get('operation') or ''))}</td>"
            f"<td>{html.escape(str(r.get('subject') or r.get('client_ip') or ''))[:40]}</td>"
            f"<td>{_status_badge(r.get('outcome'))}</td></tr>"
            for r in rows
        )
        body = ("<table><thead><tr><th>Time</th><th>Protocol</th><th>Operation</th>"
                "<th>Subject</th><th>Outcome</th></tr></thead>"
                f"<tbody>{trs}</tbody></table>")
    else:
        body = _empty('No EST/SCEP enrollments recorded')
    return HTMLResponse(_page("Enrollment Activity", body))
