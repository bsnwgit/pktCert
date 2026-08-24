"""
app/api/resonance_data.py — the data half of the resonance contract.

app/api/resonance.py mounts the panel. This module is what the panel is
allowed to *read* once it is mounted, and it exists because the embed contract
has three parts and mounting only satisfies one of them:

  1. an OpenAPI document at a stable same-origin path      -> /api/resonance/openapi.json
  2. a grant file naming what may be called                -> /.well-known/resonance.json
  3. endpoints that behave: bounded, JSON, stable fields   -> /api/resonance/data/*

Why a separate surface rather than granting against /api/certificates/* directly.
The operations named in a grant have to carry a stable operationId, prose a
stranger can choose between, enums for every fixed vocabulary, a declared
response schema, and a bounded page with a total. pktCert's own endpoints were
written for a SPA that already knows all of that: most return a bare array,
several cap at a few hundred rows with no total, and their parameters are typed
but not described. Retrofitting the contract onto them would change response
shapes the frontend already consumes. These wrap the same tables and the same
serialisers instead, so there is no second implementation of any query — only a
second, narrower doorway with the labels the model needs.

Authentication is the app's existing session, not a new one. The panel's calls
are ordinary same-origin fetches from our own page, so they carry the refresh
cookie exactly as /api/resonance/code does, and they are admitted by the same
helpers that admit /code — see resonance_session_user below. Nothing here
issues, accepts or understands a credential of resonance's, and the panel can
therefore only ever read what the signed-in person could already read.

WHAT IS DELIBERATELY ABSENT IS THE POINT OF THE DESIGN, and in a certificate
authority it matters more than anywhere else in the suite. No private key, no
passcode, and no PEM of anything that is not already public leaves this module.
Nothing here issues a certificate, revokes one, signs a CSR, creates or edits a
CA, or approves a request — and the approval queue is read-only *because*
approving is the act of issuing or revoking, which is exactly the decision an
assistant must never take on someone's behalf. The three operations that change
anything acknowledge an alert or switch an existing rule: acting on what an
administrator already put there, never authoring or destroying it.
"""
from __future__ import annotations

import asyncio
import copy
import json
import logging
from dataclasses import dataclass
from typing import Any, Literal, Optional

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.exceptions import ResponseValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.database import get_db

# Deliberately the same helpers /api/resonance/code uses, imported rather than
# reimplemented: the two surfaces must never disagree about who counts as
# signed in, which origin counts as ours, or whether the feature is on.
from app.api.resonance import (
    LEVEL_RANK, _allowed_roles, _get, _same_origin, _user_for_code, role_level,
)
from app.dependencies import require_admin, require_analyst

log = logging.getLogger("pktcert.api.resonance_data")

router = APIRouter(tags=["resonance-data"])

DATA_PREFIX = "/api/resonance/data"
SPEC_PATH = "/api/resonance/openapi.json"
GRANT_PATH = "/.well-known/resonance.json"


# ── What the assistant is allowed to call ────────────────────────────────────
#
# The one list. The grant file is generated from it, the published spec is
# filtered to it, and startup checks it against the routes that actually exist.
# An operationId that is not here is invisible to the assistant even though it
# is a perfectly ordinary route of this app.


@dataclass(frozen=True)
class Grant:
    op: str
    # Set on ANY operation that changes state, whatever its HTTP verb.
    # Resonance reads the values back to the person before running one.
    writes: bool = False


GRANTED: tuple[Grant, ...] = (
    Grant("listCertificates"),
    Grant("getCertificate"),
    Grant("listCertificateAuthorities"),
    Grant("getCertificateSummary"),
    Grant("listCertRequests"),
    Grant("listAlertEvents"),
    Grant("listAlertRules"),
    Grant("searchApplicationLog"),
    # Everything below changes state. There is deliberately no issuing, no
    # revoking, no signing, no approving and no delete of anything — see the
    # module docstring. What is left is acknowledging an alert and switching a
    # rule an administrator already wrote.
    Grant("ackAlertEvent", writes=True),
    Grant("ackAllAlertEvents", writes=True),
    Grant("toggleAlertRule", writes=True),
)


# ── Vocabulary ────────────────────────────────────────────────────────────────
#
# These are the enums the requirement is really about: without them a model
# asks for status "about to expire" and source "imported", gets a 422, and
# reports the app as broken. Every one of these is fixed in pktCert's own code
# — the install-specific vocabulary (CA names, template names) cannot be, and
# is published through listCertificateAuthorities instead.

CertStatus = Literal["valid", "expiring", "expired", "revoked"]
CertSource = Literal["issued", "enrolled", "scan", "ct", "external"]
CaType = Literal["root", "intermediate"]
AlertSeverity = Literal["info", "warning", "critical"]
RequestType = Literal["issue", "revoke"]
RequestStatus = Literal["pending", "approved", "rejected", "cancelled"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


# ── Errors ────────────────────────────────────────────────────────────────────


class ResonanceDataError(HTTPException):
    """Rendered as {"error": "..."} — the message reaches the person verbatim."""


class ErrorResponse(BaseModel):
    error: str = Field(description="What went wrong, phrased for the person to act on.")


def register_error_handler(app) -> None:
    """Give this surface the {"error": ...} body the grant contract specifies.

    Scoped to ResonanceDataError so the rest of the app keeps FastAPI's
    {"detail": ...}, which its own frontend already reads.
    """

    @app.exception_handler(ResonanceDataError)
    async def _render(_request: Request, exc: ResonanceDataError):  # noqa: ANN202
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    @app.exception_handler(ResponseValidationError)
    async def _schema_drifted(request: Request, exc: ResponseValidationError):  # noqa: ANN202
        """Report a declared schema that no longer matches what the tables return.

        This fires after the route body has already succeeded, so the module's
        own try/except cannot see it, and it is logged by uvicorn rather than by
        anything the SQLite handler is attached to — a 500 with a generic
        message in the panel and not one line anywhere on the server. Now it
        names the fields.

        Only this surface is rewritten; every other response_model in the app
        keeps FastAPI's existing behaviour.
        """
        if not request.url.path.startswith("/api/resonance/"):
            raise exc
        fields = sorted({".".join(str(p) for p in err.get("loc", ())[-2:])
                         for err in exc.errors()})[:8]
        log.error(
            "resonance response schema no longer matches the data on %s: %s",
            request.url.path, ", ".join(fields) or "unknown field",
        )
        return JSONResponse(
            {"error": "pktCert produced a result it could not describe. This is a fault in "
                      "pktCert, not in the question — it has been logged."},
            status_code=500,
        )


_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"model": ErrorResponse, "description": "No signed-in session on this request."},
    403: {"model": ErrorResponse, "description": "Signed in, but not permitted to use the assistant."},
    404: {"model": ErrorResponse, "description": "The assistant is switched off on this install."},
    504: {"model": ErrorResponse, "description": "The store did not answer in time; ask something narrower."},
}


# ── Session ───────────────────────────────────────────────────────────────────


async def resonance_session_user(
    request: Request, db: aiosqlite.Connection = Depends(get_db)
) -> dict:
    """Admit a call the panel made from our own page, on this app's own session.

    Same four gates as /api/resonance/code, in the same order and for the same
    reasons: the request must present as same-origin before any cookie is
    honoured, it must carry a session we recognise, the feature must be on, and
    the person's role must be one an admin listed. The last two mean this whole
    surface is inert on an install that never enabled the panel — a route that
    exists but answers 404 until someone turns the feature on deliberately.
    """
    if not _same_origin(request):
        raise ResonanceDataError(status_code=403, detail="Cross-site request refused.")

    user = await _user_for_code(request, db)
    if not user:
        raise ResonanceDataError(status_code=401, detail="Not signed in to pktCert.")

    if not bool(await _get(db, "resonance_enabled", False)):
        raise ResonanceDataError(status_code=404, detail="The assistant is not enabled on this install.")

    if user["role"] not in await _allowed_roles(db):
        raise ResonanceDataError(
            status_code=403, detail="Your role is not permitted to use the assistant."
        )

    # Audit trail, and the only way to answer "did the assistant actually ask us
    # anything". A successful read is otherwise silent, so without this the
    # difference between "the panel never called" and "the panel called and got
    # what it wanted" is invisible from the server — which is exactly the
    # question asked when an answer looks wrong. One line per call, at INFO, so
    # it lands in the Logs page too.
    route = request.scope.get("route")
    log.info(
        "resonance call: %s (%s) -> %s",
        user.get("username"), user.get("role"),
        getattr(route, "operation_id", None) or request.url.path,
    )
    return user


async def resonance_write_user(
    request: Request, db: aiosqlite.Connection = Depends(get_db)
) -> dict:
    """As above, and the role must be set to "write" rather than "read".

    Two gates have to agree before anything changes, and they answer different
    questions. This one is the admin's: has this role been trusted to let the
    assistant act at all. The second, inside each operation, is pktCert's own:
    may this person do this thing anyway. A role set to "write" never gains a
    right its holder does not already have in the interface — it only decides
    whether the assistant may exercise the rights they do have.
    """
    user = await resonance_session_user(request, db)
    if LEVEL_RANK.get(await role_level(db, user["role"]), 0) < LEVEL_RANK["write"]:
        raise ResonanceDataError(
            status_code=403,
            detail=("The assistant is set to read-only for your role, so it cannot make "
                    "that change. An administrator sets this under Settings → Resonance."),
        )
    return user


async def _apply_app_rule(user: dict, rule, what: str) -> None:
    """Apply pktCert's own role rule for the endpoint this operation mirrors.

    The rule itself is imported rather than restated, so a change to who may do
    something in the interface reaches the assistant in the same commit instead
    of leaving two role models to drift apart.
    """
    try:
        await rule(user)
    except HTTPException as exc:
        raise ResonanceDataError(
            status_code=exc.status_code,
            detail=f"Your pktCert role does not permit you to {what}.",
        ) from exc


SessionUser = Depends(resonance_session_user)
WriteUser = Depends(resonance_write_user)


# ── Response schemas ──────────────────────────────────────────────────────────
#
# Declared because resonance validates a result against the schema before the
# model is allowed to read it, so a shape it cannot describe is a shape it
# refuses. `extra="allow"` throughout: these describe rows that grow columns
# over time, and a new column should reach the answer rather than be stripped
# out of it by a schema written before it existed.
#
# NO SCHEMA HERE CARRIES A PRIVATE KEY, A PASSCODE, OR A LEAF PEM. Possession is
# reported as a boolean and nothing more — the interface makes an admin re-enter
# their password to see a key, and an assistant has no equivalent of that.


class Certificate(BaseModel):
    """One certificate in pktCert's inventory, issued here or found by discovery."""

    model_config = ConfigDict(extra="allow")

    id: int = Field(description="pktCert's own id for this certificate.")
    common_name: Optional[str] = Field(None, description="The certificate's CN.")
    san: list[str] = Field(default_factory=list, description="Subject alternative names.")
    issuer: Optional[str] = Field(None, description="Distinguished name of whatever signed it.")
    serial_number: Optional[str] = Field(None, description="Serial, as hex.")
    fingerprint_sha256: Optional[str] = Field(None, description="SHA-256 fingerprint.")
    not_before: Optional[str] = Field(None, description="Start of validity (ISO 8601).")
    not_after: Optional[str] = Field(None, description="Expiry (ISO 8601). The field most questions are really about.")
    days_until_expiry: Optional[int] = Field(
        None, description="Whole days from now until not_after. Negative once expired."
    )
    key_algorithm: Optional[str] = Field(None, description="RSA, EC, and so on.")
    key_size: Optional[int] = Field(None, description="Key size in bits.")
    signature_algorithm: Optional[str] = Field(None, description="Algorithm the issuer signed with.")
    status: Optional[str] = Field(None, description="valid, expiring, expired or revoked.")
    source: Optional[str] = Field(
        None, description="How pktCert came to know about it: issued, enrolled, scan, ct or external."
    )
    host: Optional[str] = Field(None, description="Where discovery found it, if it was discovered.")
    port: Optional[int] = Field(None, description="Port it was found on, if it was discovered.")
    ca_id: Optional[int] = Field(None, description="The internal CA that issued it, if pktCert issued it.")
    has_private_key: bool = Field(False, description="Whether pktCert holds the key. The key itself is never returned.")
    revoked_at: Optional[str] = Field(None, description="When it was revoked (ISO 8601), if it was.")
    revoked_reason: Optional[str] = Field(None, description="Why it was revoked, if it was.")
    auto_renew: bool = Field(False, description="Whether pktCert renews it automatically.")
    first_seen_at: Optional[str] = Field(None, description="When pktCert first recorded it.")
    last_seen_at: Optional[str] = Field(None, description="When discovery last saw it live.")


class CertificateList(BaseModel):
    model_config = ConfigDict(extra="allow")
    total: int = Field(description="How many certificates matched, before paging.")
    limit: int = Field(description="The page size that was applied.")
    offset: int = Field(description="How many were skipped.")
    returned: int = Field(0, description="How many are in this response.")
    truncated_for_size: bool = Field(
        False, description="True when the page was cut to fit. Ask for fewer, or narrow the filters."
    )
    certificates: list[Certificate] = Field(default_factory=list)


class CertificateAuthority(BaseModel):
    """One internal CA pktCert operates."""

    model_config = ConfigDict(extra="allow")

    id: int
    name: Optional[str] = Field(None, description="The name an administrator gave it.")
    ca_type: Optional[str] = Field(None, description="root or intermediate.")
    parent_ca_id: Optional[int] = Field(None, description="Its issuer, for an intermediate.")
    subject: Optional[str] = Field(None, description="Its distinguished name.")
    key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    signature_algorithm: Optional[str] = None
    not_before: Optional[str] = Field(None, description="Start of validity (ISO 8601).")
    not_after: Optional[str] = Field(None, description="Expiry (ISO 8601).")
    days_until_expiry: Optional[int] = Field(
        None, description="Whole days until this CA expires. Negative once expired."
    )
    status: Optional[str] = Field(None, description="active, disabled, expiring, expired or revoked.")
    key_storage: Optional[str] = Field(
        None, description="local when pktCert holds the key, offline when the key is kept elsewhere."
    )
    issued_count: int = Field(0, description="How many certificates in the inventory this CA issued.")
    created_at: Optional[str] = None


class CertificateAuthorityList(BaseModel):
    model_config = ConfigDict(extra="allow")
    total: int
    returned: int = 0
    truncated_for_size: bool = False
    authorities: list[CertificateAuthority] = Field(default_factory=list)


class ExpiringCertificate(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: int
    common_name: Optional[str] = None
    not_after: Optional[str] = None
    status: Optional[str] = None


class CertificateSummary(BaseModel):
    """Counts across the whole inventory — the "how are we doing" answer."""

    model_config = ConfigDict(extra="allow")

    total: int = Field(description="Every certificate pktCert knows about.")
    valid: int
    expiring: int = Field(description="Inside the warning window an administrator configured.")
    expired: int
    revoked: int
    issued: int = Field(description="Issued by an internal CA here.")
    discovered: int = Field(description="Found by network scanning or certificate transparency.")
    ca_count: int = Field(description="Internal CAs configured.")
    scan_targets: int = Field(description="Discovery targets currently enabled.")
    active_alerts: int = Field(description="Alert events not yet resolved.")
    pending_requests: int = Field(description="Issue or revoke requests waiting for a second admin.")
    expiring_soon: list[ExpiringCertificate] = Field(
        default_factory=list, description="The ten nearest expiries or already-expired certificates."
    )


class CertRequest(BaseModel):
    """An issue or revoke request waiting on, or decided by, a second administrator."""

    model_config = ConfigDict(extra="allow")

    id: int
    request_type: Optional[str] = Field(None, description="issue or revoke.")
    status: Optional[str] = Field(None, description="pending, approved, rejected or cancelled.")
    common_name: Optional[str] = Field(None, description="The CN the request is about.")
    sans: list[str] = Field(default_factory=list)
    ca_id: Optional[int] = None
    certificate_id: Optional[int] = Field(None, description="The certificate a revoke request targets.")
    reason: Optional[str] = Field(None, description="Reason given for a revocation.")
    requested_by: Optional[str] = None
    justification: Optional[str] = None
    requested_at: Optional[str] = None
    decided_by: Optional[str] = None
    decided_at: Optional[str] = None
    decision_note: Optional[str] = None


class CertRequestList(BaseModel):
    model_config = ConfigDict(extra="allow")
    total: int
    limit: int
    offset: int
    returned: int = 0
    truncated_for_size: bool = False
    requests: list[CertRequest] = Field(default_factory=list)


class AlertEvent(BaseModel):
    """One firing of a pktCert alert rule."""

    model_config = ConfigDict(extra="allow")

    id: int
    rule_id: Optional[int] = None
    rule_name: Optional[str] = Field(None, description="Name of the rule that fired.")
    certificate_id: Optional[int] = Field(None, description="The certificate it is about, if any.")
    ca_id: Optional[int] = Field(None, description="The CA it is about, if any.")
    severity: Optional[str] = None
    message: Optional[str] = Field(None, description="What the rule said when it fired.")
    value: Optional[float] = None
    threshold: Optional[float] = None
    active: bool = Field(False, description="True while the condition behind it still holds.")
    acked: bool = Field(False, description="True once somebody has acknowledged it.")
    acked_by: Optional[str] = None
    acked_at: Optional[str] = None
    resolved: bool = False
    resolved_at: Optional[str] = None
    created_at: Optional[str] = Field(None, description="When it fired (ISO 8601).")


class AlertEventList(BaseModel):
    model_config = ConfigDict(extra="allow")
    total: int
    limit: int
    offset: int
    returned: int = 0
    truncated_for_size: bool = False
    events: list[AlertEvent] = Field(default_factory=list)


class AlertRule(BaseModel):
    """A rule an administrator configured. Rules fire events; events are the firings."""

    model_config = ConfigDict(extra="allow")

    id: int
    name: Optional[str] = None
    condition_type: Optional[str] = Field(None, description="What the rule watches.")
    threshold: Optional[float] = None
    severity: Optional[str] = None
    enabled: bool = False
    channels: list[str] = Field(default_factory=list, description="Where a firing is delivered.")
    created_at: Optional[str] = None


class AlertRuleList(BaseModel):
    model_config = ConfigDict(extra="allow")
    total: int
    returned: int = 0
    truncated_for_size: bool = False
    rules: list[AlertRule] = Field(default_factory=list)


class AppLogRecord(BaseModel):
    """One line of pktCert's own diagnostic log — not certificate data."""

    model_config = ConfigDict(extra="allow")

    id: int
    level: Optional[str] = None
    logger: Optional[str] = Field(None, description="Which part of pktCert wrote it.")
    message: Optional[str] = None
    created_at: Optional[str] = Field(None, description="When it was written (ISO 8601).")


class AppLogResult(BaseModel):
    model_config = ConfigDict(extra="allow")
    total: int
    limit: int
    offset: int
    returned: int = 0
    truncated_for_size: bool = False
    records: list[AppLogRecord] = Field(default_factory=list)


# ── Operations ────────────────────────────────────────────────────────────────
#
# Every summary and description here is written for a reader who has never seen
# pktCert, because that is literally what chooses between them: a model picks an
# operation from these sentences and nothing else. "Search logs" would leave it
# guessing between the certificate inventory and the app's own diagnostics,
# which are two entirely different questions asked with almost the same words.

# One page is capped well below what the SPA allows. The panel's results are
# read back to a person in a conversation, so a hundred rows is already past the
# point of being an answer, and a model handed five hundred narrows nothing. The
# maxima are deliberately above what always fits — _fit() reports the cut, and a
# caller that wants density should be able to ask for it.
_SEARCH_DEFAULT, _SEARCH_MAX = 25, 100
_LIST_DEFAULT, _LIST_MAX = 50, 200

# Resonance truncates a result over 20 KB and tells the model it did. That turns
# a clean page into JSON that stops mid-record, so the cut is made here instead,
# where it can leave the envelope intact and say what happened in a field the
# model can act on. 18 KB leaves headroom for transport framing.
_RESULT_BUDGET_BYTES = 18_000

# Resonance gives up on a call after 20 seconds and tells the person the
# application did not answer. Answering at 15 with something they can act on
# beats going quiet at 20.
_CALL_TIMEOUT_SECONDS = 15


def _encoded_size(value: Any) -> int:
    return len(json.dumps(value, default=str).encode("utf-8"))


def _fit(payload: dict, items_key: str) -> dict:
    """Trim a page to the byte budget, and record that it had to.

    Always keeps at least one item: an empty page for one oversized record is a
    worse answer than an oversized one, and the caller can still see `total`.
    """
    items = list(payload.get(items_key) or [])
    # Price the envelope with the two fields this adds, so adding them cannot
    # push a result that just fitted back over the line.
    envelope = dict(payload)
    envelope[items_key] = []
    envelope["returned"] = len(items)
    envelope["truncated_for_size"] = True
    budget = _RESULT_BUDGET_BYTES - _encoded_size(envelope)

    kept: list = []
    used = 0
    for item in items:
        size = _encoded_size(item) + 1   # + the separating comma
        if kept and used + size > budget:
            break
        kept.append(item)
        used += size

    payload[items_key] = kept
    payload["returned"] = len(kept)
    payload["truncated_for_size"] = len(kept) < len(items)
    return payload


async def _in_time(awaitable, what: str):
    """Bound a query so a slow one is answered rather than abandoned."""
    try:
        return await asyncio.wait_for(awaitable, _CALL_TIMEOUT_SECONDS)
    except asyncio.TimeoutError as exc:
        raise ResonanceDataError(
            status_code=504,
            detail=(
                f"pktCert took longer than {_CALL_TIMEOUT_SECONDS} seconds to {what}. "
                "Narrow the time range, or filter by status, CA or name."
            ),
        ) from exc


def _days_until(not_after: Optional[str]) -> Optional[int]:
    """Whole days from now to an expiry, or None if it cannot be read.

    Computed here rather than left to the model: "is anything expiring" is the
    question this application exists to answer, and a model doing date
    arithmetic on strings gets it wrong in ways nobody notices until a
    certificate does expire.
    """
    if not not_after:
        return None
    from datetime import datetime, timezone

    text = str(not_after).strip().replace(" ", "T").rstrip("Z")
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (when - datetime.now(timezone.utc)).days


@router.get(
    f"{DATA_PREFIX}/certificates",
    operation_id="listCertificates",
    summary="Search the certificate inventory",
    description=(
        "Search every certificate pktCert knows about — the ones it issued from an internal CA, "
        "the ones devices enrolled for themselves, and the ones network scanning or certificate "
        "transparency found. Soonest expiry first, which is almost always the order the question "
        "wants. Use expiring_within_days for 'what is about to expire'; it counts from now, so 30 "
        "means the next thirty days and includes anything already expired unless status is also "
        "set. Every filter is optional and they combine with AND. Returns at most `limit` "
        "certificates plus the total that matched. Private keys and passcodes are never returned; "
        "has_private_key only says whether pktCert holds one."
    ),
    response_model=CertificateList,
    responses=_ERRORS,
)
async def list_certificates(
    _user: dict = SessionUser,
    status: Optional[CertStatus] = Query(None, description="Only certificates in this state."),
    source: Optional[CertSource] = Query(None, description="Only certificates pktCert acquired this way."),
    ca_id: Optional[int] = Query(None, description="Only certificates issued by this internal CA."),
    search: Optional[str] = Query(
        None, max_length=200,
        description="Substring of the common name, a SAN, or the host it was found on.",
    ),
    expiring_within_days: Optional[int] = Query(
        None, ge=0, le=3650,
        description="Only certificates expiring within this many days from now.",
    ),
    limit: int = Query(
        _SEARCH_DEFAULT, ge=1, le=_SEARCH_MAX,
        description=f"How many to return. Default {_SEARCH_DEFAULT}, maximum {_SEARCH_MAX}.",
    ),
    offset: int = Query(0, ge=0, description="How many to skip, for paging."),
    db: aiosqlite.Connection = Depends(get_db),
):
    from app.api.certificates import _cert_out

    clauses: list[str] = []
    params: list = []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if source:
        clauses.append("source = ?")
        params.append(source)
    if ca_id:
        clauses.append("ca_id = ?")
        params.append(ca_id)
    if search:
        clauses.append("(common_name LIKE ? OR host LIKE ? OR san_json LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like])
    if expiring_within_days is not None:
        clauses.append("not_after IS NOT NULL AND datetime(not_after) <= datetime('now', ?)")
        params.append(f"+{int(expiring_within_days)} days")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    async with db.execute(f"SELECT COUNT(*) FROM certificates {where}", params) as cur:
        total = (await cur.fetchone())[0]

    async with db.execute(
        f"SELECT * FROM certificates {where} ORDER BY not_after ASC LIMIT ? OFFSET ?",
        params + [limit, offset],
    ) as cur:
        rows = await cur.fetchall()

    certificates = []
    for r in rows:
        d = _cert_out(r)
        d["days_until_expiry"] = _days_until(d.get("not_after"))
        certificates.append(d)

    return _fit(
        {"total": total, "limit": limit, "offset": offset, "certificates": certificates},
        "certificates",
    )


@router.get(
    f"{DATA_PREFIX}/certificates/{{cert_id}}",
    operation_id="getCertificate",
    summary="Read one certificate in full",
    description=(
        "Everything pktCert records about a single certificate, by the id listCertificates "
        "returned. Use this after a search when the question is about one certificate in "
        "particular — who issued it, when it expires, whether pktCert holds its key. The key "
        "itself and any passcode are never returned."
    ),
    response_model=Certificate,
    responses={**_ERRORS, 404: {"model": ErrorResponse, "description": "No certificate with that id."}},
)
async def get_certificate(
    cert_id: int = Path(description="Id of the certificate, as returned by listCertificates."),
    _user: dict = SessionUser,
    db: aiosqlite.Connection = Depends(get_db),
):
    from app.api.certificates import _cert_out

    async with db.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise ResonanceDataError(status_code=404, detail=f"There is no certificate {cert_id}.")
    out = _cert_out(row)
    out["days_until_expiry"] = _days_until(out.get("not_after"))
    return out


@router.get(
    f"{DATA_PREFIX}/cas",
    operation_id="listCertificateAuthorities",
    summary="List the internal certificate authorities",
    description=(
        "The CAs pktCert operates and issues from — their names, whether each is a root or an "
        "intermediate, when each expires, and how many certificates in the inventory each has "
        "issued. This is also how to turn a ca_id seen elsewhere into a name. A CA's own expiry "
        "matters more than any single certificate's, because everything under it stops being "
        "trusted with it. No private key or CSR is returned."
    ),
    response_model=CertificateAuthorityList,
    responses=_ERRORS,
)
async def list_certificate_authorities(
    _user: dict = SessionUser,
    db: aiosqlite.Connection = Depends(get_db),
):
    from app.api.cas import _ca_out

    async with db.execute(
        "SELECT ca_id, COUNT(*) AS n FROM certificates WHERE ca_id IS NOT NULL GROUP BY ca_id"
    ) as cur:
        issued = {r["ca_id"]: r["n"] for r in await cur.fetchall()}

    async with db.execute("SELECT * FROM certificate_authorities ORDER BY name") as cur:
        rows = await cur.fetchall()

    authorities = []
    for r in rows:
        d = _ca_out(r)
        # A CA certificate is public by definition and pktCert already serves it
        # at /aia — but it is two kilobytes of base64 that would crowd out the
        # answer, and a model cannot do anything with a PEM anyway.
        d.pop("cert_pem", None)
        d["days_until_expiry"] = _days_until(d.get("not_after"))
        d["issued_count"] = issued.get(d.get("id"), 0)
        authorities.append(d)

    return _fit({"total": len(authorities), "authorities": authorities}, "authorities")


@router.get(
    f"{DATA_PREFIX}/summary",
    operation_id="getCertificateSummary",
    summary="Counts across the whole certificate estate",
    description=(
        "One small result answering 'how are we doing' — how many certificates are valid, "
        "expiring, expired and revoked, how many came from an internal CA against discovery, how "
        "many CAs and discovery targets exist, how many alerts are outstanding, how many issue or "
        "revoke requests are waiting for a second administrator, and the ten nearest expiries. "
        "Ask this before listCertificates when the question is about totals rather than about "
        "particular certificates."
    ),
    response_model=CertificateSummary,
    responses=_ERRORS,
)
async def get_certificate_summary(
    _user: dict = SessionUser,
    db: aiosqlite.Connection = Depends(get_db),
):
    async def _count(query: str, params: tuple = ()) -> int:
        async with db.execute(query, params) as cur:
            row = await cur.fetchone()
        return row[0] if row else 0

    async with db.execute(
        """SELECT id, common_name, not_after, status FROM certificates
           WHERE status IN ('expiring', 'expired') ORDER BY not_after ASC LIMIT 10"""
    ) as cur:
        expiring_soon = [dict(r) for r in await cur.fetchall()]

    return {
        "total": await _count("SELECT COUNT(*) FROM certificates"),
        "valid": await _count("SELECT COUNT(*) FROM certificates WHERE status = 'valid'"),
        "expiring": await _count("SELECT COUNT(*) FROM certificates WHERE status = 'expiring'"),
        "expired": await _count("SELECT COUNT(*) FROM certificates WHERE status = 'expired'"),
        "revoked": await _count("SELECT COUNT(*) FROM certificates WHERE status = 'revoked'"),
        "issued": await _count("SELECT COUNT(*) FROM certificates WHERE source = 'issued'"),
        "discovered": await _count(
            "SELECT COUNT(*) FROM certificates WHERE source IN ('scan', 'ct')"
        ),
        "ca_count": await _count("SELECT COUNT(*) FROM certificate_authorities"),
        "scan_targets": await _count("SELECT COUNT(*) FROM scan_targets WHERE enabled = 1"),
        "active_alerts": await _count("SELECT COUNT(*) FROM alert_events WHERE active = 1"),
        "pending_requests": await _count(
            "SELECT COUNT(*) FROM cert_requests WHERE status = 'pending'"
        ),
        "expiring_soon": expiring_soon,
    }


@router.get(
    f"{DATA_PREFIX}/requests",
    operation_id="listCertRequests",
    summary="Read the issue and revoke approval queue",
    description=(
        "Requests to issue or revoke a certificate that are waiting for, or have already had, a "
        "decision from a second administrator. READ ONLY, and deliberately so: approving one of "
        "these is the act of issuing or revoking the certificate itself, which is not something "
        "an assistant may do. Use this to report what is waiting and who raised it; a person "
        "makes the decision in the interface. Newest first."
    ),
    response_model=CertRequestList,
    responses=_ERRORS,
)
async def list_cert_requests(
    _user: dict = SessionUser,
    status: Optional[RequestStatus] = Query(None, description="Only requests in this state."),
    request_type: Optional[RequestType] = Query(None, description="Only issue, or only revoke, requests."),
    limit: int = Query(
        _SEARCH_DEFAULT, ge=1, le=_SEARCH_MAX,
        description=f"How many to return. Default {_SEARCH_DEFAULT}, maximum {_SEARCH_MAX}.",
    ),
    offset: int = Query(0, ge=0, description="How many to skip, for paging."),
    db: aiosqlite.Connection = Depends(get_db),
):
    from app.api.approvals import _out

    clauses: list[str] = []
    params: list = []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if request_type:
        clauses.append("request_type = ?")
        params.append(request_type)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    async with db.execute(f"SELECT COUNT(*) FROM cert_requests {where}", params) as cur:
        total = (await cur.fetchone())[0]

    async with db.execute(
        f"SELECT * FROM cert_requests {where} ORDER BY requested_at DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    ) as cur:
        rows = await cur.fetchall()

    return _fit(
        {"total": total, "limit": limit, "offset": offset,
         "requests": [_out(r) for r in rows]},
        "requests",
    )


@router.get(
    f"{DATA_PREFIX}/alerts/events",
    operation_id="listAlertEvents",
    summary="List alerts that have fired",
    description=(
        "Individual firings of pktCert's alert rules — a certificate approaching expiry, a CA "
        "approaching expiry, a discovery scan failing — newest first. This is what to read for "
        "'what is wrong' or 'what happened overnight'. An event with acked false is one nobody "
        "has looked at yet; active true means the condition still holds. Returns at most `limit` "
        "events plus the total that matched."
    ),
    response_model=AlertEventList,
    responses=_ERRORS,
)
async def list_alert_events(
    _user: dict = SessionUser,
    unacked_only: bool = Query(False, description="Only events nobody has acknowledged yet."),
    active_only: bool = Query(False, description="Only events whose condition still holds."),
    severity: Optional[AlertSeverity] = Query(None, description="Only events raised at this severity."),
    since: Optional[str] = Query(None, description="Only events fired at or after this time. ISO 8601."),
    until: Optional[str] = Query(None, description="Only events fired at or before this time. ISO 8601."),
    limit: int = Query(
        _SEARCH_DEFAULT, ge=1, le=_SEARCH_MAX,
        description=f"How many to return. Default {_SEARCH_DEFAULT}, maximum {_SEARCH_MAX}.",
    ),
    offset: int = Query(0, ge=0, description="How many to skip, for paging."),
    db: aiosqlite.Connection = Depends(get_db),
):
    from app.api.alerts import _event_out

    clauses: list[str] = []
    params: list = []
    if unacked_only:
        clauses.append("e.acked = 0")
    if active_only:
        clauses.append("e.active = 1")
    if severity:
        clauses.append("e.severity = ?")
        params.append(severity)
    if since:
        # created_at is written by SQLite's datetime('now') — space separated,
        # no 'Z' — so both sides go through datetime() to compare like for like.
        clauses.append("e.created_at >= datetime(?)")
        params.append(since)
    if until:
        clauses.append("e.created_at <= datetime(?)")
        params.append(until)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    async with db.execute(f"SELECT COUNT(*) FROM alert_events e {where}", params) as cur:
        total = (await cur.fetchone())[0]

    async with db.execute(
        f"""SELECT e.*, r.name AS rule_name
            FROM alert_events e
            LEFT JOIN alert_rules r ON r.id = e.rule_id
            {where}
            ORDER BY e.created_at DESC
            LIMIT ? OFFSET ?""",
        params + [limit, offset],
    ) as cur:
        rows = await cur.fetchall()

    events = []
    for r in rows:
        d = _event_out(r)
        d["rule_name"] = r["rule_name"]
        events.append(d)

    return _fit({"total": total, "limit": limit, "offset": offset, "events": events}, "events")


@router.get(
    f"{DATA_PREFIX}/alerts/rules",
    operation_id="listAlertRules",
    summary="List the configured alert rules",
    description=(
        "The rules an administrator has set up, whether each is switched on, what it watches and "
        "at what threshold. Rules are the configuration; listAlertEvents is what they have "
        "actually fired. Read this to answer 'are we even watching for that', and to get the rule "
        "id toggleAlertRule needs."
    ),
    response_model=AlertRuleList,
    responses=_ERRORS,
)
async def list_alert_rules(
    _user: dict = SessionUser,
    enabled_only: bool = Query(False, description="Only rules that are currently switched on."),
    db: aiosqlite.Connection = Depends(get_db),
):
    from app.api.alerts import _rule_out

    where = "WHERE enabled = 1" if enabled_only else ""
    async with db.execute(f"SELECT * FROM alert_rules {where} ORDER BY name") as cur:
        rows = await cur.fetchall()
    rules = [_rule_out(r) for r in rows]
    return _fit({"total": len(rules), "rules": rules}, "rules")


@router.get(
    f"{DATA_PREFIX}/app-log",
    operation_id="searchApplicationLog",
    summary="Search pktCert's own diagnostic log",
    description=(
        "pktCert's internal log — what the application itself did and any errors it hit. This is "
        "NOT certificate data: for certificates use listCertificates, and for alert firings use "
        "listAlertEvents. Read this to answer 'why did the scan not run' or 'what went wrong at "
        "three this morning'. Newest first."
    ),
    response_model=AppLogResult,
    responses=_ERRORS,
)
async def search_application_log(
    _user: dict = SessionUser,
    level: Optional[LogLevel] = Query(None, description="Only lines at this level."),
    logger: Optional[str] = Query(
        None, max_length=120, description="Only lines from loggers with this prefix."
    ),
    search: Optional[str] = Query(None, max_length=200, description="Substring of the message."),
    since: Optional[str] = Query(None, description="Only lines at or after this time. ISO 8601."),
    until: Optional[str] = Query(None, description="Only lines at or before this time. ISO 8601."),
    limit: int = Query(
        _SEARCH_DEFAULT, ge=1, le=_SEARCH_MAX,
        description=f"How many to return. Default {_SEARCH_DEFAULT}, maximum {_SEARCH_MAX}.",
    ),
    offset: int = Query(0, ge=0, description="How many to skip, for paging."),
    db: aiosqlite.Connection = Depends(get_db),
):
    clauses: list[str] = []
    params: list = []
    if level:
        clauses.append("level = ?")
        params.append(level)
    if logger:
        clauses.append("logger LIKE ?")
        params.append(f"{logger}%")
    if search:
        clauses.append("message LIKE ?")
        params.append(f"%{search}%")
    if since:
        clauses.append("created_at >= ?")
        params.append(since)
    if until:
        clauses.append("created_at <= ?")
        params.append(until)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    async with db.execute(f"SELECT COUNT(*) FROM app_logs {where}", params) as cur:
        total = (await cur.fetchone())[0]

    async with db.execute(
        f"SELECT id, level, logger, message, created_at FROM app_logs {where} "
        "ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    ) as cur:
        rows = await cur.fetchall()

    return _fit(
        {"total": total, "limit": limit, "offset": offset,
         "records": [dict(r) for r in rows]},
        "records",
    )


# ── The two documents ─────────────────────────────────────────────────────────
#
# Neither carries data — only names — so both are readable without a login, in
# the same way this app already publishes its own /openapi.json. Publishing them
# grants nothing on its own: an operation is reachable only because it is in
# GRANTED, and reachable only to a signed-in person whose role an admin listed.


def _declared_operation_ids(app) -> set[str]:
    """operationIds actually registered on the app.

    Walks the route table rather than calling app.openapi(), which would build
    and cache the schema at import time — before the SPA catch-all is mounted.

    The walk recurses because the table is not reliably flat: recent FastAPI
    keeps an included router as a single wrapper object holding its own routes,
    where earlier versions spliced them straight in. pkt installs pin only a
    lower bound on fastapi, so both layouts are live in the field and a walker
    that understood one of them would have reported every operation missing on
    the other.
    """
    found: set[str] = set()
    seen: set[int] = set()

    def walk(routes) -> None:
        for route in routes or []:
            if id(route) in seen:
                continue
            seen.add(id(route))
            op = getattr(route, "operation_id", None)
            if op:
                found.add(op)
            nested = getattr(route, "routes", None)
            if nested is None:
                inner = getattr(route, "original_router", None)
                nested = getattr(inner, "routes", None) if inner is not None else None
            if nested:
                walk(nested)

    walk(getattr(app, "routes", []))
    return found


def validate_grants(app) -> list[str]:
    """Fail loudly at startup when a grant names an operation that is not there.

    A grant for a route that has been renamed is the quiet failure mode of this
    whole arrangement: the panel asks for it, gets a 404, and reports the app as
    having no such capability rather than as misconfigured. Returns the missing
    names so a caller can act on them; logs them either way.
    """
    declared = _declared_operation_ids(app)
    missing = [g.op for g in GRANTED if g.op not in declared]
    if missing:
        log.error(
            "resonance grant names %d operation(s) this app does not declare: %s — "
            "they are being withheld from /.well-known/resonance.json",
            len(missing), ", ".join(missing),
        )
    return missing


async def writes_are_enabled(db: aiosqlite.Connection) -> bool:
    """True when at least one role has been trusted with more than reading.

    The grant is one document for the whole origin and is served without a
    login, so it cannot vary per person — but it can tell the truth about the
    install. Where no role is set to "write", the write operations are withheld
    from it entirely rather than advertised and refused on every attempt.
    """
    for role in ("admin", "analyst", "viewer"):
        if LEVEL_RANK.get(await role_level(db, role), 0) >= LEVEL_RANK["write"]:
            return True
    return False


def build_grant(app, allow_writes: bool) -> dict:
    """The grant document, generated from GRANTED so the two cannot disagree."""
    declared = _declared_operation_ids(app)
    allow: list[dict] = []
    for g in GRANTED:
        if g.op not in declared:
            continue
        if g.writes and not allow_writes:
            continue
        entry: dict[str, Any] = {"op": g.op}
        if g.writes:
            entry["writes"] = True
        allow.append(entry)
    return {"resonance": 1, "spec": SPEC_PATH, "allow": allow}


def _referenced_schemas(node: Any, out: set[str]) -> None:
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
            out.add(ref.rsplit("/", 1)[-1])
        for value in node.values():
            _referenced_schemas(value, out)
    elif isinstance(node, list):
        for value in node:
            _referenced_schemas(value, out)


def build_spec(app, allow_writes: bool) -> dict:
    """This app's own OpenAPI, narrowed to the granted operations.

    Generated from the live routes rather than written by hand, so a parameter
    that changes shape changes here too — the failure a hand-kept spec always
    ends in is the assistant confidently sending a field that stopped existing.
    Narrowed rather than published whole because everything an operation's prose
    has to compete with is another operation's prose: a hundred and twenty of
    them, most of which the grant forbids, is a hundred and twenty chances to
    pick the wrong one.
    """
    full = app.openapi()
    granted = {g.op for g in GRANTED if allow_writes or not g.writes}

    paths: dict[str, dict] = {}
    for path, item in (full.get("paths") or {}).items():
        # Deep-copied because app.openapi() hands back the app's own cached
        # schema object: editing an operation in place here would edit the
        # document this app publishes at /openapi.json as well.
        kept = {
            method: copy.deepcopy(operation)
            for method, operation in item.items()
            if isinstance(operation, dict) and operation.get("operationId") in granted
        }
        if kept:
            for operation in kept.values():
                # Nothing is presented on these calls but the person's own
                # session cookie, which the browser attaches by itself.
                operation.pop("security", None)
            paths[path] = kept

    wanted: set[str] = set()
    _referenced_schemas(paths, wanted)
    all_schemas = (full.get("components") or {}).get("schemas") or {}
    resolved: dict[str, Any] = {}
    while wanted:
        name = wanted.pop()
        if name in resolved or name not in all_schemas:
            continue
        resolved[name] = copy.deepcopy(all_schemas[name])
        nested: set[str] = set()
        _referenced_schemas(all_schemas[name], nested)
        wanted |= nested - resolved.keys()

    spec: dict[str, Any] = {
        "openapi": full.get("openapi", "3.1.0"),
        "info": {
            "title": "pktCert — assistant data surface",
            "version": full.get("info", {}).get("version", "0.1.0"),
            "description": (
                "The operations pktCert publishes for an embedded assistant. Every call is made "
                "by pktCert's own page, same-origin, on the session of the person already signed "
                "in, so nothing here can reach data that person could not already open in the "
                "interface. No private key, passcode or certificate PEM is exposed, and nothing "
                "here issues, revokes, signs or approves anything."
            ),
        },
        "paths": paths,
    }
    if resolved:
        spec["components"] = {"schemas": resolved}
    return spec


# Two possible documents — with writes and without — so the setting can change
# without a restart while the expensive part is still built once each.
_spec_cache: dict[bool, Any] = {}


@router.get(GRANT_PATH, include_in_schema=False)
async def resonance_grant(request: Request, db: aiosqlite.Connection = Depends(get_db)):
    """What this install permits the assistant to call. Names only, no data.

    Public by contract: it has to be readable before anyone signs in, and it
    carries nothing but operation names. Whether the write operations appear
    depends on the levels an admin set, so an install that has trusted nobody
    with writes publishes a grant that cannot be read as offering them.
    """
    grant = build_grant(request.app, await writes_are_enabled(db))
    log.info("resonance grant fetched: %d operation(s), %d writing",
             len(grant["allow"]), sum(1 for a in grant["allow"] if a.get("writes")))
    return JSONResponse(
        grant,
        media_type="application/json",
        headers={"Cache-Control": "public, max-age=300"},
    )


@router.get(SPEC_PATH, include_in_schema=False)
async def resonance_spec(request: Request, db: aiosqlite.Connection = Depends(get_db)):
    """The OpenAPI document for the granted operations."""
    allow_writes = await writes_are_enabled(db)
    if allow_writes not in _spec_cache:
        _spec_cache[allow_writes] = build_spec(request.app, allow_writes)
    log.info("resonance spec fetched (writes %s)", "included" if allow_writes else "withheld")
    return JSONResponse(
        _spec_cache[allow_writes],
        media_type="application/json",
        headers={"Cache-Control": "public, max-age=300"},
    )


# ── Operations that change something ──────────────────────────────────────────
#
# Every one of these is marked `writes: true` in the grant, so resonance stops
# and reads the actual values back to the person before it runs one. That
# confirmation is theirs to enforce and cannot be relied on here, which is why
# both gates above still apply on the request itself.
#
# What is absent is the design. In a certificate authority the consequential
# acts are issuing, revoking, signing and approving — and an approval here IS an
# issuance or a revocation, performed the moment it is granted. None of them are
# reachable from this surface at any role level. What is left changes a flag
# somebody can read and reverse.


class AckResult(BaseModel):
    model_config = ConfigDict(extra="allow")
    event_id: int = Field(description="The alert event this refers to.")
    acknowledged: bool = Field(description="True if this call acknowledged it.")
    already_acknowledged: bool = Field(
        description="True when someone had already acknowledged it, in which case nothing changed."
    )
    acked_at: Optional[str] = Field(None, description="When it was acknowledged (ISO 8601, UTC).")
    message: str = Field(description="What happened, phrased to be read back to the person.")


class AckAllResult(BaseModel):
    model_config = ConfigDict(extra="allow")
    acknowledged: int = Field(description="How many outstanding alerts this call acknowledged.")
    message: str = Field(description="What happened, phrased to be read back to the person.")


class ToggleRuleResult(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: int = Field(description="The rule that was switched.")
    name: Optional[str] = Field(None, description="Its name, for reading back.")
    enabled: bool = Field(description="Whether the rule is now on.")
    message: str = Field(description="What happened, phrased to be read back to the person.")


@router.post(
    f"{DATA_PREFIX}/alerts/events/{{event_id}}/ack",
    operation_id="ackAlertEvent",
    summary="Acknowledge one alert",
    description=(
        "Mark a single fired alert as seen, recording who did it and when. This changes state. It "
        "does not resolve the alert or fix the condition behind it — a certificate close to "
        "expiry is still close to expiry, and the rule will fire again. Acknowledging something "
        "already acknowledged changes nothing and says so. Available to analysts and "
        "administrators, as in the interface."
    ),
    response_model=AckResult,
    responses={**_ERRORS, 404: {"model": ErrorResponse, "description": "No alert event with that id."}},
)
async def ack_alert_event(
    event_id: int = Path(
        description="Id of the alert event to acknowledge, as returned by listAlertEvents."
    ),
    user: dict = WriteUser,
    db: aiosqlite.Connection = Depends(get_db),
):
    await _apply_app_rule(user, require_analyst, "acknowledge alerts")

    async with db.execute(
        "SELECT e.acked, e.acked_at, r.name FROM alert_events e "
        "LEFT JOIN alert_rules r ON r.id = e.rule_id WHERE e.id = ?",
        (event_id,),
    ) as cur:
        row = await cur.fetchone()
    if not row:
        raise ResonanceDataError(status_code=404, detail=f"There is no alert event {event_id}.")

    name = row["name"] or "unnamed rule"
    if row["acked"]:
        when = str(row["acked_at"] or "").replace(" ", "T") + "Z" if row["acked_at"] else None
        return {
            "event_id": event_id, "acknowledged": False, "already_acknowledged": True,
            "acked_at": when,
            "message": f"Alert {event_id} ({name}) was already acknowledged"
                       + (f" at {when}." if when else "."),
        }

    await db.execute(
        "UPDATE alert_events SET acked = 1, acked_by = ?, acked_at = datetime('now') "
        "WHERE id = ? AND acked = 0",
        (user.get("username"), event_id),
    )
    await db.commit()

    async with db.execute("SELECT acked_at FROM alert_events WHERE id = ?", (event_id,)) as cur:
        acked = (await cur.fetchone())["acked_at"]
    when = str(acked).replace(" ", "T") + "Z" if acked else None
    log.info("resonance: %s acknowledged alert event %s", user.get("username"), event_id)
    return {
        "event_id": event_id, "acknowledged": True, "already_acknowledged": False,
        "acked_at": when,
        "message": f"Acknowledged alert {event_id} ({name}). The condition behind it is unchanged.",
    }


@router.post(
    f"{DATA_PREFIX}/alerts/events/ack-all",
    operation_id="ackAllAlertEvents",
    summary="Acknowledge every outstanding alert",
    description=(
        "Mark every alert nobody has acknowledged yet as seen, in one go. This changes state, and "
        "it is not reversible from here — there is no un-acknowledge. It resolves nothing: every "
        "condition behind every alert is untouched. Reports how many were acknowledged, which is "
        "zero when there was nothing outstanding. Available to analysts and administrators, as in "
        "the interface."
    ),
    response_model=AckAllResult,
    responses=_ERRORS,
)
async def ack_all_alert_events(
    user: dict = WriteUser,
    db: aiosqlite.Connection = Depends(get_db),
):
    await _apply_app_rule(user, require_analyst, "acknowledge alerts")

    async with db.execute("SELECT COUNT(*) FROM alert_events WHERE acked = 0") as cur:
        outstanding = (await cur.fetchone())[0]
    if not outstanding:
        return {"acknowledged": 0, "message": "There were no unacknowledged alerts."}

    await db.execute(
        "UPDATE alert_events SET acked = 1, acked_by = ?, acked_at = datetime('now') "
        "WHERE acked = 0",
        (user.get("username"),),
    )
    await db.commit()
    log.info("resonance: %s acknowledged all %d outstanding alerts",
             user.get("username"), outstanding)
    return {
        "acknowledged": outstanding,
        "message": f"Acknowledged {outstanding} alert"
                   f"{'' if outstanding == 1 else 's'}. None of the conditions behind them changed.",
    }


@router.post(
    f"{DATA_PREFIX}/alerts/rules/{{rule_id}}/toggle",
    operation_id="toggleAlertRule",
    summary="Switch an existing alert rule on or off",
    description=(
        "Turn a rule an administrator already created on, or off. This changes state. Switching a "
        "rule off stops it firing at all, so anything it was watching for goes unreported until "
        "it is switched back on — say which rule and which direction before doing it. It cannot "
        "create, edit or delete a rule, only flip the one switch. Administrators only, as in the "
        "interface."
    ),
    response_model=ToggleRuleResult,
    responses={**_ERRORS, 404: {"model": ErrorResponse, "description": "No alert rule with that id."}},
)
async def toggle_alert_rule(
    rule_id: int = Path(description="Id of the rule to switch, as returned by listAlertRules."),
    user: dict = WriteUser,
    db: aiosqlite.Connection = Depends(get_db),
):
    await _apply_app_rule(user, require_admin, "change alert rules")

    async with db.execute("SELECT id, name, enabled FROM alert_rules WHERE id = ?", (rule_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise ResonanceDataError(status_code=404, detail=f"There is no alert rule {rule_id}.")

    new_enabled = 0 if row["enabled"] else 1
    await db.execute("UPDATE alert_rules SET enabled = ? WHERE id = ?", (new_enabled, rule_id))
    await db.commit()
    log.info("resonance: %s switched alert rule %s %s",
             user.get("username"), rule_id, "on" if new_enabled else "off")
    return {
        "id": rule_id,
        "name": row["name"],
        "enabled": bool(new_enabled),
        "message": f"Alert rule {rule_id} ({row['name']}) is now "
                   f"{'on' if new_enabled else 'off'}.",
    }
