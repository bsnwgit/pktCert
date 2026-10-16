"""
Certificate Transparency log search — crt.sh (free, no key) and Censys
(optional, per-user API key from the Cert Keys tab) as alternate discovery
sources alongside the active TLS scanner.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Any

import httpx

log = logging.getLogger("pktcert.ct_search")

_CRTSH_URL = "https://crt.sh/"


async def search_crtsh(domain: str) -> list[dict[str, Any]]:
    """Query crt.sh's JSON API for certificates matching *.domain. Returns
    raw crt.sh rows (not yet normalized to our certificates schema) —
    caller fetches the live cert separately via x509_utils.fetch_cert_chain
    since crt.sh doesn't reliably return the full PEM for every entry."""
    params = {"q": f"%.{domain}", "output": "json"}
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(_CRTSH_URL, params=params)
    if resp.status_code != 200:
        log.warning(f"crt.sh returned HTTP {resp.status_code} for {domain}")
        return []
    try:
        return resp.json()
    except ValueError:
        return []


# ── Validating one certificate against the log ─────────────────────────────
#
# crt.sh refuses `output=json` for fingerprint lookups ("Unsupported output
# type"), so a certificate cannot be looked up by hash and read back as data.
# What does return JSON is a search by name. So validation searches each public
# name the certificate carries and recognises the certificate among the entries
# by serial number — unique per issuing CA — and issuer.

_MAX_NAMES = 10

# A name under one of these can never be in a public log. Searching for it would
# only tell a third party what the internal network calls its hosts, so these
# are skipped rather than sent.
_NON_PUBLIC_SUFFIXES = (
    ".local", ".lan", ".internal", ".intranet", ".corp", ".home", ".private",
    ".localdomain", ".home.arpa", ".test", ".example", ".invalid", ".localhost",
)

_RETRY_STATUSES = (502, 503, 504)


class CrtshUnavailable(Exception):
    """crt.sh could not answer — which says nothing about the certificate."""


async def _crtsh_query(name: str) -> list[dict[str, Any]]:
    params = {"q": name, "output": "json"}
    resp = None
    # crt.sh is a free shared service and routinely answers 502 under load, so
    # one retry is worth having; more would just be rude to it.
    for attempt in (1, 2):
        try:
            async with httpx.AsyncClient(timeout=30, headers={"User-Agent": "pktcert"}) as client:
                resp = await client.get(_CRTSH_URL, params=params)
        except httpx.HTTPError as e:
            if attempt == 2:
                raise CrtshUnavailable(f"could not reach crt.sh ({type(e).__name__})")
            await asyncio.sleep(2)
            continue
        if resp.status_code in _RETRY_STATUSES and attempt == 1:
            await asyncio.sleep(2)
            continue
        break
    if resp.status_code != 200:
        raise CrtshUnavailable(f"crt.sh returned HTTP {resp.status_code}")
    if not resp.text.strip():
        return []
    try:
        data = resp.json()
    except ValueError:
        raise CrtshUnavailable("crt.sh returned something that was not JSON")
    return data if isinstance(data, list) else []


def _is_public_name(name: str) -> bool:
    bare = name.lstrip("*.").lower()
    if "." not in bare or " " in bare:
        return False
    try:
        ipaddress.ip_address(bare)
        return False
    except ValueError:
        pass
    return not bare.endswith(_NON_PUBLIC_SUFFIXES)


def _norm_serial(serial: Any) -> str:
    return str(serial or "").strip().lower().lstrip("0")


def _issuer_cn(issuer: Any) -> str:
    """Issuer CN where there is one. Our own rows hold RFC 4514 ("CN=R3,O=…")
    and crt.sh holds "C=US, O=…, CN=R3" — same CA, different field order, so a
    whole-string comparison would call every issuer unexpected."""
    s = str(issuer or "")
    m = re.search(r"(?:^|,\s*)CN=((?:\\,|[^,])+)", s)
    return (m.group(1) if m else s).strip().lower()


def _not_expired(row: dict[str, Any]) -> bool:
    try:
        end = datetime.fromisoformat(str(row.get("not_after")))
    except ValueError:
        return True  # unreadable date: keep it, a false alarm beats a missed one
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    return end > datetime.now(timezone.utc)


def _entry_out(row: dict[str, Any], status: str) -> dict[str, Any]:
    return {
        "crtsh_id": row.get("id"),
        "issuer": row.get("issuer_name"),
        "common_name": row.get("common_name"),
        "names": [n.strip() for n in str(row.get("name_value") or "").split("\n") if n.strip()],
        "not_before": row.get("not_before"),
        "not_after": row.get("not_after"),
        "logged_at": row.get("entry_timestamp"),
        "serial_number": row.get("serial_number"),
        "status": status,  # known | same_issuer | unexpected
    }


async def validate_against_crtsh(
    cert: dict[str, Any], known_serials: set[str]
) -> dict[str, Any]:
    """Check one inventory certificate against Certificate Transparency.

    Two questions, answered from the same searches:

    * **logged** — is this certificate in the log? ``None`` when crt.sh could
      not be asked, because "could not check" must never read as "not logged".
    * **unexpected** — unexpired certificates for the same names that are
      neither in the inventory (``known_serials``) nor from this certificate's
      issuer: the shape of a mis-issuance, or of a certificate someone obtained
      without telling you.

    ``cert`` needs common_name, san, serial_number, issuer.
    """
    names: list[str] = []
    for n in [cert.get("common_name"), *(cert.get("san") or [])]:
        n = str(n or "").strip().lower()
        if n and n not in names:
            names.append(n)
    public = [n for n in names if _is_public_name(n)]
    skipped = [n for n in names if n not in public]
    truncated = public[_MAX_NAMES:]
    public = public[:_MAX_NAMES]

    my_serial = _norm_serial(cert.get("serial_number"))
    my_issuer = _issuer_cn(cert.get("issuer"))
    known = {_norm_serial(s) for s in known_serials}

    logged_entry: dict[str, Any] | None = None
    other: dict[tuple, dict[str, Any]] = {}
    errors: list[str] = []
    checked: list[str] = []

    for name in public:
        try:
            rows = await _crtsh_query(name)
        except CrtshUnavailable as e:
            errors.append(f"{name}: {e}")
            continue
        checked.append(name)
        for row in rows:
            serial = _norm_serial(row.get("serial_number"))
            if serial == my_serial and _issuer_cn(row.get("issuer_name")) == my_issuer:
                # A certificate and its precertificate are separate log entries
                # with the same serial; either one proves it was logged.
                logged_entry = logged_entry or _entry_out(row, "known")
                continue
            if not _not_expired(row):
                continue
            if serial in known:
                status = "known"
            elif _issuer_cn(row.get("issuer_name")) == my_issuer:
                status = "same_issuer"
            else:
                status = "unexpected"
            other.setdefault((serial, row.get("issuer_ca_id")), _entry_out(row, status))

    others = list(other.values())
    unexpected = [e for e in others if e["status"] == "unexpected"]
    same_issuer = [e for e in others if e["status"] == "same_issuer"]

    if not public:
        verdict = "not_applicable"
    elif not checked:
        verdict = "unavailable"
    elif unexpected:
        verdict = "unexpected_found"
    elif logged_entry:
        verdict = "logged"
    elif errors:
        verdict = "inconclusive"
    else:
        verdict = "not_logged"

    return {
        "verdict": verdict,
        "logged": True if logged_entry else (False if checked and not errors else None),
        "logged_entry": logged_entry,
        "unexpected": unexpected,
        "same_issuer": same_issuer,
        "names_checked": checked,
        "names_skipped": skipped,
        "names_over_limit": truncated,
        "errors": errors,
        "crtsh_url": (
            f"https://crt.sh/?sha256={cert['fingerprint_sha256']}"
            if cert.get("fingerprint_sha256") else None
        ),
    }


async def search_censys(domain: str, api_id: str, api_secret: str) -> list[dict[str, Any]]:
    """Query Censys's host search for the given domain. Requires a Censys
    API ID/Secret pair (Cert Keys -> Censys, stored as 'api_id:api_secret')."""
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(
            "https://search.censys.io/api/v2/hosts/search",
            params={"q": domain, "per_page": 50},
            auth=(api_id, api_secret),
        )
    if resp.status_code != 200:
        log.warning(f"Censys returned HTTP {resp.status_code} for {domain}")
        return []
    data = resp.json()
    return data.get("result", {}).get("hits", [])
