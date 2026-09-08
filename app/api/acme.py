"""
ACME — Automatic Certificate Management Environment (RFC 8555).

Served at /acme/..., outside /api and outside the SPA, so that clients built
against Let's Encrypt point at pktCert by changing one directory URL.

EST and SCEP cover network gear. Nothing on a Linux host or in a cluster speaks
either — Caddy, Traefik, cert-manager, certbot and acme.sh all speak ACME, and
they speak it unattended. This is what lets the internal CA serve the servers.

Implemented:

  GET  /acme/directory            — entry point, unauthenticated
  HEAD /acme/new-nonce            — anti-replay nonce
  POST /acme/new-account          — register, bound to a profile by EAB
  POST /acme/new-order            — order for a set of identifiers
  POST /acme/authz/{id}           — authorization status  (POST-as-GET)
  POST /acme/chall/{id}           — answer a challenge
  POST /acme/order/{id}           — order status          (POST-as-GET)
  POST /acme/order/{id}/finalize  — CSR in
  POST /acme/cert/{id}            — certificate chain out (POST-as-GET)
  POST /acme/revoke-cert          — revoke

Resource *fetches* are POST-as-GET — a POST whose payload is the empty string,
not a GET. That is not decoration: implementing them as plain GETs would make
every order and certificate URL an unauthenticated read.

Issuance itself is not reimplemented here. A finalized order ends in the same
enrollment.issue_from_csr() call as an EST enrolment, under the same profile,
CA and template, so an ACME certificate is indistinguishable from a device one
and lands in the same inventory with the same CRL distribution point.

Authorisation is External Account Binding: every account is tied at
registration to an enrolment profile, and therefore to a CA, a template and a
name constraint. EAB is mandatory — an internal ACME server that signs whatever
it is asked for is a takeover machine for every name on the network.
"""
from __future__ import annotations

import json
import secrets
from typing import Optional

import aiosqlite
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse

from app.cert import acme_jws, acme_validation, enrollment, issuance, x509_utils
from app.cert.acme_jws import AcmeError
from app.cert.crypto import decrypt_str
from app.database import get_db

router = APIRouter()

_PROTOCOL = "acme"
# How long an order and its authorizations stay open. Long enough for a client
# to stand up a challenge responder, short enough that abandoned orders age out.
_ORDER_TTL = "+7 days"


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _base(db: aiosqlite.Connection) -> str:
    """The externally-reachable root, shared with the CRL and AIA endpoints —
    a client that cannot reach those cannot use a certificate from here
    either, so there is no case for a second setting that could disagree."""
    return (await issuance.get_crl_base_url(db)).rstrip("/")


def _urls(base: str) -> dict:
    root = f"{base}/acme"
    return {
        "newNonce": f"{root}/new-nonce",
        "newAccount": f"{root}/new-account",
        "newOrder": f"{root}/new-order",
        "revokeCert": f"{root}/revoke-cert",
        "keyChange": f"{root}/key-change",
        "root": root,
    }


async def _nonce_headers(db: aiosqlite.Connection, extra: Optional[dict] = None) -> dict:
    headers = {"Replay-Nonce": await acme_jws.issue_nonce(db), "Cache-Control": "no-store"}
    if extra:
        headers.update(extra)
    return headers


async def _problem(db: aiosqlite.Connection, err: AcmeError) -> JSONResponse:
    return JSONResponse(
        status_code=err.status,
        content={"type": f"urn:ietf:params:acme:error:{err.kind}", "detail": err.detail},
        media_type="application/problem+json",
        headers=await _nonce_headers(db),
    )


async def _ok(db: aiosqlite.Connection, content, status: int = 200,
              extra_headers: Optional[dict] = None) -> JSONResponse:
    return JSONResponse(status_code=status, content=content,
                        headers=await _nonce_headers(db, extra_headers))


# ── request authentication ───────────────────────────────────────────────────

async def _account_from_kid(db: aiosqlite.Connection, kid: str):
    """Accounts are addressed by URL. Only the trailing id is trusted — the
    rest of the kid is whatever the client was told at registration, and a
    reverse proxy may have rewritten it."""
    try:
        account_id = int(kid.rstrip("/").rsplit("/", 1)[-1])
    except ValueError:
        raise AcmeError("accountDoesNotExist", "the kid is not an account URL known here", 400)
    async with db.execute("SELECT * FROM acme_accounts WHERE id = ?", (account_id,)) as cur:
        account = await cur.fetchone()
    if not account:
        raise AcmeError("accountDoesNotExist", "no such account", 400)
    if account["status"] != "valid":
        raise AcmeError("unauthorized", f"this account is {account['status']}", 403)
    return account


async def _authenticate(request: Request, db: aiosqlite.Connection, expected_url: str):
    """Parse, nonce-check and verify a JWS. Returns (jws, account-or-None)."""
    try:
        body = await request.json()
    except ValueError:
        raise AcmeError("malformed", "request body is not JSON")

    jws = acme_jws.parse_jws(body, expected_url)
    # Spent before the signature is checked, so a replayed request cannot be
    # retried cheaply against a signature oracle.
    await acme_jws.consume_nonce(db, jws.nonce)

    if jws.kid:
        account = await _account_from_kid(db, jws.kid)
        key = acme_jws.public_key_from_jwk(json.loads(account["jwk_json"]))
    else:
        account = None
        key = acme_jws.public_key_from_jwk(jws.jwk)

    acme_jws.verify_signature(jws, key)

    if account is not None:
        await db.execute(
            "UPDATE acme_accounts SET last_seen_at = datetime('now') WHERE id = ?", (account["id"],)
        )
        await db.commit()
    return jws, account


async def _profile_for(db: aiosqlite.Connection, account):
    async with db.execute(
        "SELECT * FROM enrollment_profiles WHERE id = ?", (account["profile_id"],)
    ) as cur:
        profile = await cur.fetchone()
    if not profile or not profile["enabled"]:
        raise AcmeError("unauthorized", "the enrolment profile behind this account is not enabled", 403)
    return profile


# ── serialisation ────────────────────────────────────────────────────────────

def _identifier_of(authz) -> dict:
    name = authz["identifier"]
    return {"type": "dns", "value": f"*.{name}" if authz["wildcard"] else name}


async def _order_json(db: aiosqlite.Connection, base: str, order) -> dict:
    async with db.execute(
        "SELECT * FROM acme_authorizations WHERE order_id = ? ORDER BY id", (order["id"],)
    ) as cur:
        authzs = await cur.fetchall()

    payload = {
        "status": order["status"],
        "expires": order["expires_at"],
        "identifiers": [_identifier_of(a) for a in authzs],
        "authorizations": [f"{base}/acme/authz/{a['id']}" for a in authzs],
        "finalize": f"{base}/acme/order/{order['id']}/finalize",
    }
    if order["certificate_id"]:
        payload["certificate"] = f"{base}/acme/cert/{order['certificate_id']}"
    if order["error_json"]:
        payload["error"] = json.loads(order["error_json"])
    return payload


async def _authz_json(db: aiosqlite.Connection, base: str, authz) -> dict:
    async with db.execute(
        "SELECT * FROM acme_challenges WHERE authz_id = ? ORDER BY id", (authz["id"],)
    ) as cur:
        challenges = await cur.fetchall()
    payload = {
        "identifier": {"type": "dns", "value": authz["identifier"]},
        "status": authz["status"],
        "expires": authz["expires_at"],
        "challenges": [_challenge_json(base, c) for c in challenges],
    }
    if authz["wildcard"]:
        payload["wildcard"] = True
    return payload


def _challenge_json(base: str, challenge) -> dict:
    payload = {
        "type": challenge["type"],
        "url": f"{base}/acme/chall/{challenge['id']}",
        "status": challenge["status"],
        "token": challenge["token"],
    }
    if challenge["validated_at"]:
        payload["validated"] = challenge["validated_at"]
    if challenge["error_json"]:
        payload["error"] = json.loads(challenge["error_json"])
    return payload


# ── directory and nonce ──────────────────────────────────────────────────────

@router.get("/directory")
async def directory(db: aiosqlite.Connection = Depends(get_db)):
    urls = _urls(await _base(db))
    return {
        "newNonce": urls["newNonce"],
        "newAccount": urls["newAccount"],
        "newOrder": urls["newOrder"],
        "revokeCert": urls["revokeCert"],
        "keyChange": urls["keyChange"],
        "meta": {
            # Every account must be bound to an enrolment profile, and clients
            # surface this to explain why registration needs credentials.
            "externalAccountRequired": True,
        },
    }


@router.head("/new-nonce")
@router.get("/new-nonce")
async def new_nonce(db: aiosqlite.Connection = Depends(get_db)):
    return Response(status_code=204, headers=await _nonce_headers(db))


# ── accounts ─────────────────────────────────────────────────────────────────

@router.post("/new-account")
async def new_account(request: Request, db: aiosqlite.Connection = Depends(get_db)):
    base = await _base(db)
    url = f"{base}/acme/new-account"
    try:
        jws, _ = await _authenticate(request, db, url)
        if jws.jwk is None:
            raise AcmeError("malformed", "new-account must be signed with an embedded 'jwk'")
        payload = jws.payload or {}
        thumbprint = acme_jws.jwk_thumbprint(jws.jwk)

        async with db.execute(
            "SELECT * FROM acme_accounts WHERE jwk_thumbprint = ?", (thumbprint,)
        ) as cur:
            existing = await cur.fetchone()
        if existing:
            # Re-registration with the same key returns the account rather than
            # erroring — clients rely on this to discover their own URL.
            if payload.get("onlyReturnExisting"):
                pass
            return await _ok(db, {
                "status": existing["status"],
                "contact": json.loads(existing["contact_json"]),
                "orders": f"{base}/acme/account/{existing['id']}/orders",
            }, 200, {"Location": f"{base}/acme/account/{existing['id']}"})
        if payload.get("onlyReturnExisting"):
            raise AcmeError("accountDoesNotExist", "no account exists for this key", 400)

        eab = payload.get("externalAccountBinding")
        if not eab:
            raise AcmeError(
                "externalAccountRequired",
                "registration requires external account binding — create an ACME enrolment "
                "profile in pktCert and use its key id and HMAC key",
                403,
            )
        kid = None
        try:
            kid = json.loads(acme_jws.b64u_decode(eab["protected"])).get("kid")
        except (ValueError, KeyError, TypeError):
            raise AcmeError("malformed", "externalAccountBinding protected header is unreadable")

        async with db.execute(
            "SELECT * FROM enrollment_profiles WHERE protocol = ? AND username = ? AND enabled = 1",
            (_PROTOCOL, kid),
        ) as cur:
            profile = await cur.fetchone()
        if not profile:
            raise AcmeError("unauthorized", "external account key id not recognised", 403)

        # The profile secret is the EAB MAC key. It is handed to the operator
        # once, at profile creation, in the form a client expects.
        mac_key = acme_jws.b64u_decode(decrypt_str(profile["secret_enc"]))
        acme_jws.verify_eab(eab, jws.jwk, mac_key, url)

        contact = payload.get("contact") or []
        cur = await db.execute(
            """INSERT INTO acme_accounts (profile_id, jwk_thumbprint, jwk_json, contact_json)
               VALUES (?, ?, ?, ?) RETURNING *""",
            (profile["id"], thumbprint, json.dumps(jws.jwk), json.dumps(contact)),
        )
        account = await cur.fetchone()
        await enrollment.log_attempt(
            db, profile_id=profile["id"], protocol=_PROTOCOL, operation="new-account",
            client_ip=_client_ip(request), outcome="issued",
            detail=f"ACME account {account['id']} registered",
        )
        return await _ok(db, {
            "status": "valid", "contact": contact,
            "orders": f"{base}/acme/account/{account['id']}/orders",
        }, 201, {"Location": f"{base}/acme/account/{account['id']}"})
    except AcmeError as e:
        return await _problem(db, e)


@router.post("/account/{account_id}")
async def account_detail(account_id: int, request: Request, db: aiosqlite.Connection = Depends(get_db)):
    base = await _base(db)
    try:
        jws, account = await _authenticate(request, db, f"{base}/acme/account/{account_id}")
        if not account or account["id"] != account_id:
            raise AcmeError("unauthorized", "this account may not act on that one", 403)

        payload = jws.payload or {}
        if payload.get("status") == "deactivated":
            await db.execute(
                "UPDATE acme_accounts SET status = 'deactivated' WHERE id = ?", (account_id,))
            await db.commit()
        elif "contact" in payload:
            await db.execute(
                "UPDATE acme_accounts SET contact_json = ? WHERE id = ?",
                (json.dumps(payload["contact"] or []), account_id))
            await db.commit()

        async with db.execute("SELECT * FROM acme_accounts WHERE id = ?", (account_id,)) as cur:
            account = await cur.fetchone()
        return await _ok(db, {
            "status": account["status"], "contact": json.loads(account["contact_json"]),
            "orders": f"{base}/acme/account/{account_id}/orders",
        })
    except AcmeError as e:
        return await _problem(db, e)


# ── orders ───────────────────────────────────────────────────────────────────

async def _check_identifier(profile, value: str) -> tuple[str, bool]:
    """Validate one requested identifier against the profile. Returns
    (base name, is wildcard)."""
    wildcard = value.startswith("*.")
    name = value[2:] if wildcard else value
    if not name or "*" in name:
        raise AcmeError("rejectedIdentifier", f"'{value}' is not a usable DNS identifier", 400)

    if wildcard and not profile["allow_wildcard"]:
        raise AcmeError(
            "rejectedIdentifier",
            f"'{value}' is a wildcard, and this enrolment profile does not permit wildcards",
            403,
        )

    suffix = (profile["allowed_name_suffix"] or "").strip().lower()
    # The same label-boundary rule the CSR gate applies, so an order is
    # refused for exactly the names its certificate would later be refused
    # for — failing at finalize instead would mean the client had already
    # stood up challenge responders for names it was never going to get.
    if suffix and not enrollment._name_allowed(name, suffix):
        raise AcmeError(
            "rejectedIdentifier",
            f"this profile may only issue names ending in '{suffix}'; refused: {value}",
            403,
        )
    return name, wildcard


async def _enforce_order_rate(db: aiosqlite.Connection, profile) -> None:
    """max_orders_per_hour, 0 meaning unlimited.

    ACME's normal behaviour is to come back every renewal cycle, so a lifetime
    cap of the kind EST uses would strand a fleet mid-renewal with nobody awake
    to raise it. A rate degrades safely instead: a client that trips it retries
    and succeeds later.
    """
    limit = profile["max_orders_per_hour"] or 0
    if limit <= 0:
        return
    async with db.execute(
        """SELECT COUNT(*) FROM acme_orders o
             JOIN acme_accounts a ON a.id = o.account_id
            WHERE a.profile_id = ? AND o.created_at > datetime('now', '-1 hour')""",
        (profile["id"],),
    ) as cur:
        used = (await cur.fetchone())[0]
    if used >= limit:
        raise AcmeError(
            "rateLimited",
            f"this profile is limited to {limit} orders per hour; {used} have been placed",
            429,
        )


@router.post("/new-order")
async def new_order(request: Request, db: aiosqlite.Connection = Depends(get_db)):
    base = await _base(db)
    try:
        jws, account = await _authenticate(request, db, f"{base}/acme/new-order")
        if not account:
            raise AcmeError("malformed", "new-order must be signed with 'kid'")
        profile = await _profile_for(db, account)
        payload = jws.payload or {}

        identifiers = payload.get("identifiers")
        if not isinstance(identifiers, list) or not identifiers:
            raise AcmeError("malformed", "an order needs at least one identifier")
        for entry in identifiers:
            if not isinstance(entry, dict) or entry.get("type") != "dns":
                raise AcmeError("rejectedIdentifier", "only DNS identifiers are supported")

        await _enforce_order_rate(db, profile)
        checked = [await _check_identifier(profile, e.get("value", "")) for e in identifiers]

        # ARI's `replaces`, where the client sends it. Without it a renewal is
        # indistinguishable from a first issuance; the finalize path falls back
        # to matching on the identifier set.
        replaces_id = None
        if payload.get("replaces"):
            async with db.execute(
                """SELECT c.id FROM certificates c JOIN acme_orders o ON o.certificate_id = c.id
                    WHERE o.account_id = ? AND c.serial_number = ?""",
                (account["id"], str(payload["replaces"]).lower()),
            ) as cur:
                found = await cur.fetchone()
            replaces_id = found["id"] if found else None

        cur = await db.execute(
            """INSERT INTO acme_orders (account_id, identifiers_json, replaces_cert_id, expires_at)
               VALUES (?, ?, ?, datetime('now', ?)) RETURNING *""",
            (account["id"], json.dumps([v for v, _ in checked]), replaces_id, _ORDER_TTL),
        )
        order = await cur.fetchone()

        for name, wildcard in checked:
            cur = await db.execute(
                """INSERT INTO acme_authorizations (order_id, identifier, wildcard, expires_at)
                   VALUES (?, ?, ?, datetime('now', ?)) RETURNING *""",
                (order["id"], name, int(wildcard), _ORDER_TTL),
            )
            authz = await cur.fetchone()
            # A wildcard can only ever be proven through DNS, so offering
            # http-01 for one would be offering a challenge that cannot pass.
            types = ["dns-01"] if wildcard else ["http-01", "dns-01"]
            for challenge_type in types:
                await db.execute(
                    "INSERT INTO acme_challenges (authz_id, type, token) VALUES (?, ?, ?)",
                    (authz["id"], challenge_type, acme_jws.b64u(secrets.token_bytes(24))),
                )
        await db.commit()

        async with db.execute("SELECT * FROM acme_orders WHERE id = ?", (order["id"],)) as cur:
            order = await cur.fetchone()
        return await _ok(db, await _order_json(db, base, order), 201,
                         {"Location": f"{base}/acme/order/{order['id']}"})
    except AcmeError as e:
        return await _problem(db, e)


@router.post("/order/{order_id}")
async def order_detail(order_id: int, request: Request, db: aiosqlite.Connection = Depends(get_db)):
    base = await _base(db)
    try:
        _, account = await _authenticate(request, db, f"{base}/acme/order/{order_id}")
        order = await _owned_order(db, account, order_id)
        return await _ok(db, await _order_json(db, base, order))
    except AcmeError as e:
        return await _problem(db, e)


async def _owned_order(db: aiosqlite.Connection, account, order_id: int):
    async with db.execute("SELECT * FROM acme_orders WHERE id = ?", (order_id,)) as cur:
        order = await cur.fetchone()
    if not order:
        raise AcmeError("malformed", "no such order", 404)
    if not account or order["account_id"] != account["id"]:
        raise AcmeError("unauthorized", "this order belongs to another account", 403)
    return order


# ── authorizations and challenges ────────────────────────────────────────────

@router.post("/authz/{authz_id}")
async def authorization(authz_id: int, request: Request, db: aiosqlite.Connection = Depends(get_db)):
    base = await _base(db)
    try:
        _, account = await _authenticate(request, db, f"{base}/acme/authz/{authz_id}")
        async with db.execute("SELECT * FROM acme_authorizations WHERE id = ?", (authz_id,)) as cur:
            authz = await cur.fetchone()
        if not authz:
            raise AcmeError("malformed", "no such authorization", 404)
        await _owned_order(db, account, authz["order_id"])
        return await _ok(db, await _authz_json(db, base, authz))
    except AcmeError as e:
        return await _problem(db, e)


@router.post("/chall/{challenge_id}")
async def challenge(challenge_id: int, request: Request, db: aiosqlite.Connection = Depends(get_db)):
    base = await _base(db)
    try:
        _, account = await _authenticate(request, db, f"{base}/acme/chall/{challenge_id}")
        async with db.execute("SELECT * FROM acme_challenges WHERE id = ?", (challenge_id,)) as cur:
            chall = await cur.fetchone()
        if not chall:
            raise AcmeError("malformed", "no such challenge", 404)
        async with db.execute(
            "SELECT * FROM acme_authorizations WHERE id = ?", (chall["authz_id"],)
        ) as cur:
            authz = await cur.fetchone()
        order = await _owned_order(db, account, authz["order_id"])

        if chall["status"] == "valid":
            return await _ok(db, _challenge_json(base, chall))
        if chall["type"] != "http-01":
            raise AcmeError(
                "unsupportedChallenge",
                f"{chall['type']} is offered but not yet validated by this server; use http-01",
                400,
            )

        account_jwk = json.loads(account["jwk_json"])
        key_auth = acme_jws.key_authorization(chall["token"], account_jwk)
        try:
            import asyncio
            await asyncio.to_thread(
                acme_validation.validate_http_01, authz["identifier"], chall["token"], key_auth
            )
        except acme_validation.ValidationFailed as e:
            problem = {"type": "urn:ietf:params:acme:error:incorrectResponse", "detail": str(e)}
            await db.execute(
                "UPDATE acme_challenges SET status = 'invalid', error_json = ? WHERE id = ?",
                (json.dumps(problem), challenge_id))
            await db.execute(
                "UPDATE acme_authorizations SET status = 'invalid' WHERE id = ?", (authz["id"],))
            await db.execute(
                "UPDATE acme_orders SET status = 'invalid', error_json = ? WHERE id = ?",
                (json.dumps(problem), order["id"]))
            await db.commit()
            await enrollment.log_attempt(
                db, profile_id=account["profile_id"], protocol=_PROTOCOL, operation="challenge",
                client_ip=_client_ip(request), subject=authz["identifier"],
                outcome="denied", detail=str(e),
            )
        else:
            await db.execute(
                """UPDATE acme_challenges SET status = 'valid', validated_at = datetime('now')
                    WHERE id = ?""", (challenge_id,))
            await db.execute(
                "UPDATE acme_authorizations SET status = 'valid' WHERE id = ?", (authz["id"],))
            await db.commit()
            await _advance_order(db, order["id"])

        async with db.execute("SELECT * FROM acme_challenges WHERE id = ?", (challenge_id,)) as cur:
            chall = await cur.fetchone()
        return await _ok(db, _challenge_json(base, chall),
                         extra_headers={"Link": f'<{base}/acme/authz/{authz["id"]}>;rel="up"'})
    except AcmeError as e:
        return await _problem(db, e)


async def _advance_order(db: aiosqlite.Connection, order_id: int) -> None:
    """An order becomes ready once every authorization is valid."""
    async with db.execute(
        "SELECT status FROM acme_authorizations WHERE order_id = ?", (order_id,)
    ) as cur:
        statuses = [r["status"] for r in await cur.fetchall()]
    if statuses and all(s == "valid" for s in statuses):
        await db.execute(
            "UPDATE acme_orders SET status = 'ready' WHERE id = ? AND status = 'pending'", (order_id,))
        await db.commit()


# ── finalize and download ────────────────────────────────────────────────────

def _csr_der_to_pem(der: bytes) -> str:
    from cryptography import x509
    return x509.load_der_x509_csr(der).public_bytes(serialization.Encoding.PEM).decode()


async def _supersede_previous(db: aiosqlite.Connection, account, order, new_cert_id: int) -> None:
    """Link a renewal to what it replaced.

    ARI's `replaces` is authoritative where the client sends it. Where it does
    not — and plenty of clients still don't — fall back to the same account
    holding an unexpired certificate for exactly the same names. Without this
    a renewal is invisible: the replaced certificate stays 'valid' and goes on
    raising expiry alerts nobody can act on, and the inventory accumulates
    unlinked generations of one name, four a year at 90-day validity.

    Deferred to issuance rather than decided at order time, so an order that
    never completes supersedes nothing.
    """
    previous_id = order["replaces_cert_id"]
    if not previous_id:
        names = sorted(json.loads(order["identifiers_json"]))
        async with db.execute(
            """SELECT c.id, c.san_json FROM certificates c
                 JOIN acme_orders o ON o.certificate_id = c.id
                WHERE o.account_id = ? AND c.id != ? AND c.status = 'valid'
                  AND c.not_after > datetime('now')
             ORDER BY c.id DESC""",
            (account["id"], new_cert_id),
        ) as cur:
            for row in await cur.fetchall():
                try:
                    if sorted(json.loads(row["san_json"] or "[]")) == names:
                        previous_id = row["id"]
                        break
                except ValueError:
                    continue
    if previous_id:
        await issuance.supersede(db, previous_id, new_cert_id)
        await db.execute(
            "INSERT INTO cert_events (certificate_id, event_type, message) VALUES (?, 'renewed', ?)",
            (previous_id, f"Superseded by ACME-renewed certificate {new_cert_id}"),
        )


@router.post("/order/{order_id}/finalize")
async def finalize(order_id: int, request: Request, db: aiosqlite.Connection = Depends(get_db)):
    base = await _base(db)
    try:
        jws, account = await _authenticate(request, db, f"{base}/acme/order/{order_id}/finalize")
        order = await _owned_order(db, account, order_id)
        profile = await _profile_for(db, account)

        if order["status"] == "valid":
            return await _ok(db, await _order_json(db, base, order),
                             extra_headers={"Location": f"{base}/acme/order/{order_id}"})
        if order["status"] != "ready":
            raise AcmeError("orderNotReady",
                            f"this order is {order['status']}; every authorization must be valid first",
                            403)

        payload = jws.payload or {}
        if not payload.get("csr"):
            raise AcmeError("badCSR", "finalize needs a 'csr'")
        try:
            csr_pem = _csr_der_to_pem(acme_jws.b64u_decode(payload["csr"]))
        except Exception:
            raise AcmeError("badCSR", "the CSR could not be read as DER PKCS#10")

        csr = x509_utils.csr_from_pem(csr_pem)
        requested = {n.lower().rstrip(".") for n in enrollment._names_in_csr(csr)}
        ordered = {v.lower() for v in json.loads(order["identifiers_json"])}
        # The CSR is the thing being signed; the order that preceded it is not
        # evidence about its contents. A CSR naming anything the order did not
        # cover has had no authorization performed for that name at all.
        if not requested or not requested <= ordered:
            raise AcmeError(
                "badCSR",
                "the CSR names identifiers this order did not authorize: "
                + ", ".join(sorted(requested - ordered)),
            )

        try:
            row, _pem = await enrollment.issue_from_csr(db, profile, csr_pem, _PROTOCOL)
        except enrollment.EnrollmentError as e:
            problem = {"type": "urn:ietf:params:acme:error:badCSR", "detail": str(e)}
            await db.execute("UPDATE acme_orders SET status = 'invalid', error_json = ? WHERE id = ?",
                             (json.dumps(problem), order_id))
            await db.commit()
            await enrollment.log_attempt(
                db, profile_id=profile["id"], protocol=_PROTOCOL, operation="finalize",
                client_ip=_client_ip(request), subject=", ".join(sorted(ordered)),
                outcome="denied", detail=str(e),
            )
            raise AcmeError("badCSR", str(e), e.status)

        await db.execute(
            "UPDATE certificates SET acme_order_id = ? WHERE id = ?", (order_id, row["id"]))
        await _supersede_previous(db, account, order, row["id"])
        await db.execute(
            "UPDATE acme_orders SET status = 'valid', certificate_id = ?, csr_pem = ? WHERE id = ?",
            (row["id"], csr_pem, order_id))
        await db.commit()

        async with db.execute("SELECT * FROM acme_orders WHERE id = ?", (order_id,)) as cur:
            order = await cur.fetchone()
        return await _ok(db, await _order_json(db, base, order),
                         extra_headers={"Location": f"{base}/acme/order/{order_id}"})
    except AcmeError as e:
        return await _problem(db, e)


async def _chain_pem(db: aiosqlite.Connection, cert_row) -> str:
    """Leaf first, then every CA up to and including the root — what a client
    installs. Without the intermediates a server sending only this certificate
    is unverifiable, which is the failure AIA exists to paper over."""
    parts = [cert_row["cert_pem"].strip()]
    ca_id = cert_row["ca_id"]
    seen: set[int] = set()
    while ca_id and ca_id not in seen:
        seen.add(ca_id)
        async with db.execute(
            "SELECT cert_pem, parent_ca_id FROM certificate_authorities WHERE id = ?", (ca_id,)
        ) as cur:
            ca = await cur.fetchone()
        if not ca:
            break
        parts.append(ca["cert_pem"].strip())
        ca_id = ca["parent_ca_id"]
    return "\n".join(parts) + "\n"


@router.post("/cert/{cert_id}")
async def download_certificate(cert_id: int, request: Request, db: aiosqlite.Connection = Depends(get_db)):
    base = await _base(db)
    try:
        _, account = await _authenticate(request, db, f"{base}/acme/cert/{cert_id}")
        async with db.execute(
            """SELECT c.* FROM certificates c JOIN acme_orders o ON o.certificate_id = c.id
                WHERE c.id = ? AND o.account_id = ?""",
            (cert_id, account["id"] if account else -1),
        ) as cur:
            cert_row = await cur.fetchone()
        if not cert_row:
            raise AcmeError("unauthorized", "no certificate here for this account", 403)
        return Response(
            content=await _chain_pem(db, cert_row),
            media_type="application/pem-certificate-chain",
            headers=await _nonce_headers(db),
        )
    except AcmeError as e:
        return await _problem(db, e)


# ── revocation ───────────────────────────────────────────────────────────────

@router.post("/revoke-cert")
async def revoke_certificate(request: Request, db: aiosqlite.Connection = Depends(get_db)):
    """RFC 8555 §7.6.

    Accepts a revocation signed by the account that ordered the certificate, or
    by the certificate's own key. The second path involves no account and no
    profile, and so bypasses the approvals flow entirely — that is mandatory in
    the spec and every client implements it. It is defensible because proof of
    possession is strong evidence: whoever holds the key can already impersonate
    the service. It is logged as its own thing, because "who revoked this, and
    under what authority" is exactly the question asked afterwards.
    """
    base = await _base(db)
    try:
        jws, account = await _authenticate(request, db, f"{base}/acme/revoke-cert")
        payload = jws.payload or {}
        if not payload.get("certificate"):
            raise AcmeError("malformed", "revocation needs a 'certificate'")

        from cryptography import x509 as _x509
        try:
            target = _x509.load_der_x509_certificate(acme_jws.b64u_decode(payload["certificate"]))
        except Exception:
            raise AcmeError("malformed", "the certificate could not be read as DER")

        fingerprint = x509_utils.parse_certificate(
            target.public_bytes(serialization.Encoding.PEM).decode())["fingerprint_sha256"]
        async with db.execute(
            "SELECT * FROM certificates WHERE fingerprint_sha256 = ?", (fingerprint,)
        ) as cur:
            cert_row = await cur.fetchone()
        if not cert_row:
            raise AcmeError("malformed", "that certificate was not issued here", 404)
        if cert_row["status"] == "revoked":
            raise AcmeError("alreadyRevoked", "that certificate is already revoked", 400)

        by_certificate_key = account is None
        if by_certificate_key:
            # Signed with an embedded jwk: the only acceptable key is the
            # certificate's own, and it has to actually be that key.
            presented = acme_jws.jwk_thumbprint(jws.jwk)
            expected = acme_jws.jwk_thumbprint(acme_jws.jwk_from_public_key(target.public_key()))
            if presented != expected:
                raise AcmeError("unauthorized",
                                "revocation must be signed by the certificate's own key "
                                "or by the account that ordered it", 403)
        else:
            async with db.execute(
                "SELECT 1 FROM acme_orders WHERE certificate_id = ? AND account_id = ?",
                (cert_row["id"], account["id"]),
            ) as cur:
                if not await cur.fetchone():
                    raise AcmeError("unauthorized", "this account did not order that certificate", 403)

        reason = payload.get("reason")
        reason = int(reason) if isinstance(reason, int) else 0
        await db.execute(
            """UPDATE certificates SET status = 'revoked', revoked_at = datetime('now'),
                   revoked_reason = ? WHERE id = ?""",
            (str(reason), cert_row["id"]))
        await db.execute(
            "INSERT INTO cert_events (certificate_id, ca_id, event_type, message) VALUES (?, ?, 'revoked', ?)",
            (cert_row["id"], cert_row["ca_id"],
             "Revoked over ACME, authorised by the certificate's own key — no account involved"
             if by_certificate_key else
             f"Revoked over ACME by account {account['id']}"),
        )
        await db.commit()
        await enrollment.log_attempt(
            db, profile_id=None if by_certificate_key else account["profile_id"],
            protocol=_PROTOCOL, operation="revoke-cert", client_ip=_client_ip(request),
            subject=cert_row["common_name"], outcome="issued",
            detail="authorised by certificate key" if by_certificate_key else "authorised by account key",
        )
        return Response(status_code=200, headers=await _nonce_headers(db))
    except AcmeError as e:
        return await _problem(db, e)
