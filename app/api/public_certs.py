"""
/api/public-certs/* — certificates from a publicly-trusted CA.

The internal CA (app/api/cas.py) issues certificates that anyone who has
installed the root will trust. This is for the other case: a name that has to
be trusted natively, by people who will never install anything. That trust
comes from the issuing CA being in browser and OS root stores, which an
internal root cannot be, so the certificate has to come from outside — from
Let's Encrypt, or any other ACME CA the operator points this at.

Three things are configured here and they are deliberately separate, because
in practice they belong to different people:

  * a DNS provider — the credential that proves control of a zone
  * an ACME account — which CA, and the key identifying us to it
  * a managed request — the names, and the renewal policy for them

Validation is dns-01 (app/cert/dns/). It is the only challenge that works for
a host the public internet cannot reach, and the only one that yields a
wildcard.

Unlike the ACME server side, pktCert generates and holds the private key for
these, so it can genuinely renew them unattended rather than only noticing
that someone else should have.
"""
from __future__ import annotations

import json
import logging

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.cert import acme_client, dns as dns_registry, x509_utils
from app.cert.crypto import decrypt_str, encrypt_str
from app.database import get_db
from app.dependencies import AdminUser, CurrentUser

log = logging.getLogger("pktcert.public_certs")

router = APIRouter()

# Named rather than free text so the UI can offer them, but the underlying
# field stays a URL: any ACME CA works, and an operator can paste their own.
KNOWN_DIRECTORIES = {
    "letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
    "buypass": "https://api.buypass.com/acme/directory",
    "google": "https://dv.acme-v02.api.pki.goog/directory",
    "zerossl": "https://acme.zerossl.com/v2/DV90",
}


# ── DNS providers ────────────────────────────────────────────────────────────

class DnsProviderRequest(BaseModel):
    name: str
    provider: str
    credential: str = ""
    enabled: bool = True


def _dns_out(r) -> dict:
    return {
        "id": r["id"], "name": r["name"], "provider": r["provider"],
        "enabled": bool(r["enabled"]), "last_used_at": r["last_used_at"],
        "last_error": r["last_error"], "created_at": r["created_at"],
        # Never the credential. It is a zone-wide secret — anything holding it
        # can repoint the domain — and there is no view that needs it back.
    }


@router.get("/providers")
async def list_provider_types(user: CurrentUser):
    """What this build can actually construct, straight from the registry, so
    the dropdown cannot offer a backend that isn't compiled in."""
    return dns_registry.describe_providers()


@router.get("/directories")
async def list_directories(user: CurrentUser):
    return [{"key": k, "url": v} for k, v in KNOWN_DIRECTORIES.items()]


@router.get("/dns-providers")
async def list_dns_providers(user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM dns_providers ORDER BY name") as cur:
        return [_dns_out(r) for r in await cur.fetchall()]


@router.post("/dns-providers", status_code=201)
async def create_dns_provider(body: DnsProviderRequest, user: AdminUser,
                              db: aiosqlite.Connection = Depends(get_db)):
    if not dns_registry.lookup(body.provider):
        raise HTTPException(400, f"Unknown DNS provider — this build supports: "
                                 f"{', '.join(dns_registry.provider_names())}")
    if not body.credential.strip():
        raise HTTPException(400, "A credential is required")
    try:
        cur = await db.execute(
            """INSERT INTO dns_providers (name, provider, credential_enc, enabled)
               VALUES (?, ?, ?, ?) RETURNING *""",
            (body.name.strip(), body.provider, encrypt_str(body.credential.strip()), int(body.enabled)),
        )
    except aiosqlite.IntegrityError:
        raise HTTPException(409, f"A DNS provider named '{body.name}' already exists")
    row = await cur.fetchone()
    await db.commit()
    return _dns_out(row)


@router.post("/dns-providers/{provider_id}/test")
async def test_dns_provider(provider_id: int, user: AdminUser,
                            db: aiosqlite.Connection = Depends(get_db)):
    """Check the credential before an order depends on it. A failed validation
    costs a rate-limited attempt at the CA; a failed button costs nothing."""
    async with db.execute("SELECT * FROM dns_providers WHERE id = ?", (provider_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "DNS provider not found")
    try:
        provider = dns_registry.get_provider(row["provider"], decrypt_str(row["credential_enc"]))
        detail = await provider.check()
    except dns_registry.DnsError as e:
        await db.execute("UPDATE dns_providers SET last_error = ? WHERE id = ?", (str(e), provider_id))
        await db.commit()
        raise HTTPException(400, str(e))
    await db.execute(
        "UPDATE dns_providers SET last_error = NULL, last_used_at = datetime('now') WHERE id = ?",
        (provider_id,))
    await db.commit()
    return {"status": "ok", "detail": detail}


@router.delete("/dns-providers/{provider_id}", status_code=204)
async def delete_dns_provider(provider_id: int, user: AdminUser,
                              db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute(
        "SELECT COUNT(*) FROM public_cert_requests WHERE dns_provider_id = ?", (provider_id,)
    ) as cur:
        in_use = (await cur.fetchone())[0]
    if in_use:
        raise HTTPException(
            409, f"{in_use} managed certificate(s) still use this provider — they could not renew without it")
    await db.execute("DELETE FROM dns_providers WHERE id = ?", (provider_id,))
    await db.commit()


# ── ACME accounts at the public CA ───────────────────────────────────────────

class AccountRequest(BaseModel):
    name: str
    directory_url: str
    environment: str = "staging"
    contact_email: str = ""
    eab_kid: str = ""
    eab_hmac_key: str = ""


def _account_out(r) -> dict:
    return {
        "id": r["id"], "name": r["name"], "directory_url": r["directory_url"],
        "environment": r["environment"], "account_url": r["account_url"],
        "contact": json.loads(r["contact_json"]), "registered": bool(r["account_url"]),
        "created_at": r["created_at"],
    }


@router.get("/accounts")
async def list_accounts(user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM public_acme_accounts ORDER BY name") as cur:
        return [_account_out(r) for r in await cur.fetchall()]


@router.post("/accounts", status_code=201)
async def create_account(body: AccountRequest, user: AdminUser,
                         db: aiosqlite.Connection = Depends(get_db)):
    """Generate an account key and register it with the CA.

    Registration happens here rather than lazily at first order so that a bad
    directory URL, a missing EAB credential or unaccepted terms surface while
    someone is looking at the screen.
    """
    url = body.directory_url.strip()
    if not url.startswith("https://"):
        raise HTTPException(400, "The directory URL must be https")

    key_pem = acme_client.generate_account_key_pem()
    try:
        async with acme_client.AcmeClient(url, key_pem) as client:
            account_url = await client.register(
                [body.contact_email] if body.contact_email.strip() else [],
                eab_kid=body.eab_kid.strip(), eab_hmac=body.eab_hmac_key.strip(),
            )
    except acme_client.AcmeClientError as e:
        raise HTTPException(400, str(e))

    contact = [body.contact_email.strip()] if body.contact_email.strip() else []
    try:
        cur = await db.execute(
            """INSERT INTO public_acme_accounts
               (name, directory_url, environment, account_key_enc, account_url, contact_json,
                eab_kid, eab_hmac_enc, terms_agreed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now')) RETURNING *""",
            (body.name.strip(), url, body.environment, encrypt_str(key_pem), account_url,
             json.dumps(contact), body.eab_kid.strip() or None,
             encrypt_str(body.eab_hmac_key.strip()) if body.eab_hmac_key.strip() else None),
        )
    except aiosqlite.IntegrityError:
        raise HTTPException(409, f"An account named '{body.name}' already exists")
    row = await cur.fetchone()
    await db.commit()
    return _account_out(row)


@router.delete("/accounts/{account_id}", status_code=204)
async def delete_account(account_id: int, user: AdminUser,
                         db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("DELETE FROM public_acme_accounts WHERE id = ?", (account_id,))
    await db.commit()


# ── managed certificates ─────────────────────────────────────────────────────

class CertRequest(BaseModel):
    name: str
    account_id: int
    dns_provider_id: int
    identifiers: list[str]
    key_algorithm: str = "ec"
    key_size: int = 2048
    renew_before_days: int = 30
    auto_renew: bool = True
    enabled: bool = True


def _request_out(r) -> dict:
    return {
        "id": r["id"], "name": r["name"], "account_id": r["account_id"],
        "dns_provider_id": r["dns_provider_id"],
        "identifiers": json.loads(r["identifiers_json"]),
        "key_algorithm": r["key_algorithm"], "key_size": r["key_size"],
        "renew_before_days": r["renew_before_days"], "auto_renew": bool(r["auto_renew"]),
        "enabled": bool(r["enabled"]), "status": r["status"], "last_error": r["last_error"],
        "last_attempt_at": r["last_attempt_at"], "certificate_id": r["certificate_id"],
        "created_at": r["created_at"],
    }


@router.get("/requests")
async def list_requests(user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM public_cert_requests ORDER BY name") as cur:
        return [_request_out(r) for r in await cur.fetchall()]


@router.post("/requests", status_code=201)
async def create_request(body: CertRequest, user: AdminUser,
                         db: aiosqlite.Connection = Depends(get_db)):
    names = [n.strip().lower() for n in body.identifiers if n.strip()]
    if not names:
        raise HTTPException(400, "At least one name is required")
    for name in names:
        # A public CA will refuse a name that isn't a real registered domain,
        # and it will do so after a validation attempt against a rate limit.
        # Catching the obvious cases here costs nothing.
        bare = name.lstrip("*.")
        if "." not in bare or bare.endswith((".local", ".lan", ".internal", ".home", ".corp")):
            raise HTTPException(
                400,
                f"'{name}' is not a publicly resolvable domain — a public CA can only issue for "
                "names under a real registered domain, not an internal-only suffix",
            )

    cur = await db.execute(
        """INSERT INTO public_cert_requests
           (name, account_id, dns_provider_id, identifiers_json, key_algorithm, key_size,
            renew_before_days, auto_renew, enabled)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *""",
        (body.name.strip(), body.account_id, body.dns_provider_id, json.dumps(names),
         body.key_algorithm, body.key_size, max(1, body.renew_before_days),
         int(body.auto_renew), int(body.enabled)),
    )
    row = await cur.fetchone()
    await db.commit()
    return _request_out(row)


class CertUpdate(BaseModel):
    auto_renew: bool | None = None
    renew_before_days: int | None = None
    enabled: bool | None = None


@router.patch("/requests/{request_id}")
async def update_request(request_id: int, body: CertUpdate, user: AdminUser,
                         db: aiosqlite.Connection = Depends(get_db)):
    """Change the renewal policy without reissuing.

    Partial by design: every field is optional and only what is sent is
    written. The alternative — replacing the whole row — means a UI that
    forgets a field silently resets it, which is exactly how the enrolment
    toggle used to drop a profile's wildcard permission.
    """
    async with db.execute("SELECT * FROM public_cert_requests WHERE id = ?", (request_id,)) as cur:
        existing = await cur.fetchone()
    if not existing:
        raise HTTPException(404, "Managed certificate not found")

    updates, params = [], []
    if body.auto_renew is not None:
        updates.append("auto_renew = ?")
        params.append(int(body.auto_renew))
    if body.renew_before_days is not None:
        if body.renew_before_days < 1:
            raise HTTPException(400, "The renewal window must be at least one day")
        updates.append("renew_before_days = ?")
        params.append(body.renew_before_days)
    if body.enabled is not None:
        updates.append("enabled = ?")
        params.append(int(body.enabled))
    if not updates:
        return _request_out(existing)

    params.append(request_id)
    await db.execute(f"UPDATE public_cert_requests SET {', '.join(updates)} WHERE id = ?", params)
    await db.commit()
    async with db.execute("SELECT * FROM public_cert_requests WHERE id = ?", (request_id,)) as cur:
        return _request_out(await cur.fetchone())


async def run_request(db: aiosqlite.Connection, request_id: int) -> dict:
    """Order (or re-order) one managed certificate. Shared by the endpoint and
    the renewal loop, so an automatic renewal is identical to a manual one."""
    async with db.execute("SELECT * FROM public_cert_requests WHERE id = ?", (request_id,)) as cur:
        req = await cur.fetchone()
    if not req:
        raise HTTPException(404, "Managed certificate not found")
    async with db.execute(
        "SELECT * FROM public_acme_accounts WHERE id = ?", (req["account_id"],)) as cur:
        account = await cur.fetchone()
    async with db.execute(
        "SELECT * FROM dns_providers WHERE id = ?", (req["dns_provider_id"],)) as cur:
        provider = await cur.fetchone()
    if not account or not provider:
        raise HTTPException(400, "The account or DNS provider for this certificate is missing")
    if not provider["enabled"]:
        raise HTTPException(400, "The DNS provider for this certificate is disabled")

    names = json.loads(req["identifiers_json"])
    try:
        async with acme_client.AcmeClient(
            account["directory_url"], decrypt_str(account["account_key_enc"]), account["account_url"]
        ) as client:
            chain_pem, key_pem = await client.obtain(
                names, provider["provider"], decrypt_str(provider["credential_enc"]),
                req["key_algorithm"], req["key_size"],
            )
    except (acme_client.AcmeClientError, dns_registry.DnsError) as e:
        await db.execute(
            """UPDATE public_cert_requests SET status = 'failed', last_error = ?,
                   last_attempt_at = datetime('now') WHERE id = ?""",
            (str(e), request_id))
        await db.commit()
        raise HTTPException(400, str(e))

    # The CA returns leaf first, then its intermediates. Stored the same way
    # every other certificate here is: leaf in cert_pem, the rest in chain_pem.
    blocks = [b + "-----END CERTIFICATE-----\n"
              for b in chain_pem.split("-----END CERTIFICATE-----") if "BEGIN" in b]
    leaf_pem, rest = blocks[0], "".join(blocks[1:])
    info = x509_utils.parse_certificate(leaf_pem)

    previous_id = req["certificate_id"]
    try:
        cur = await db.execute(
            """INSERT INTO certificates
               (common_name, san_json, issuer, subject, serial_number, fingerprint_sha256,
                not_before, not_after, key_algorithm, key_size, signature_algorithm,
                status, source, cert_pem, chain_pem, private_key_enc, public_request_id,
                renewed_from_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'valid', 'public', ?, ?, ?, ?, ?)
               RETURNING *""",
            (info["common_name"], json.dumps(info["san"]), info["issuer"], info["subject"],
             info["serial_number"], info["fingerprint_sha256"], info["not_before"], info["not_after"],
             info["key_algorithm"], info["key_size"], info["signature_algorithm"],
             leaf_pem, rest or None, encrypt_str(key_pem), request_id, previous_id),
        )
        row = await cur.fetchone()
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "That certificate is already in the inventory")

    if previous_id:
        from app.cert import issuance
        await issuance.supersede(db, previous_id, row["id"])

    await db.execute(
        """UPDATE public_cert_requests SET status = 'valid', last_error = NULL,
               last_attempt_at = datetime('now'), certificate_id = ? WHERE id = ?""",
        (row["id"], request_id))
    await db.execute(
        "UPDATE dns_providers SET last_used_at = datetime('now') WHERE id = ?", (provider["id"],))
    await db.execute(
        "INSERT INTO cert_events (certificate_id, event_type, message) VALUES (?, ?, ?)",
        (row["id"], "renewed" if previous_id else "issued",
         f"Obtained from {account['name']} ({account['environment']}) for "
         f"{', '.join(names)} — validated over DNS via {provider['name']}"))
    await db.commit()
    return {"status": "ok", "certificate_id": row["id"], "not_after": info["not_after"]}


@router.post("/requests/{request_id}/issue")
async def issue_now(request_id: int, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    """Issue or replace this certificate now. The same path the renewal loop
    takes, so 'renew' is not a separate operation with its own bugs."""
    return await run_request(db, request_id)


# RFC 5280 reasonCode numbers behind pktCert's stored reason names. The local
# CRL is written from the name; ACME's revokeCert carries the integer.
REASON_CODE_NUMBERS = {
    "unspecified": 0, "key_compromise": 1, "ca_compromise": 2, "affiliation_changed": 3,
    "superseded": 4, "cessation_of_operation": 5, "certificate_hold": 6,
    "privilege_withdrawn": 9, "aa_compromise": 10,
}


async def revoke_at_ca(db: aiosqlite.Connection, cert_row, reason: int = 0) -> None:
    """Revoke a public certificate at the CA that issued it.

    Shared with the approvals flow, which needs the same thing to happen when a
    second admin approves rather than when the first one asks. Marking the row
    revoked without this would be theatre: nobody checks pktCert's CRL for a
    Let's Encrypt certificate, so it would read as revoked here and stay
    trusted everywhere that matters.
    """
    request_id = cert_row["public_request_id"] if "public_request_id" in cert_row.keys() else None
    if not request_id:
        raise HTTPException(400, "That certificate is not managed by a public CA request")
    async with db.execute(
        """SELECT a.* FROM public_acme_accounts a
             JOIN public_cert_requests r ON r.account_id = a.id WHERE r.id = ?""",
        (request_id,),
    ) as cur:
        account = await cur.fetchone()
    if not account:
        raise HTTPException(400, "The account that issued this certificate is missing")

    try:
        async with acme_client.AcmeClient(
            account["directory_url"], decrypt_str(account["account_key_enc"]), account["account_url"]
        ) as client:
            await client.revoke(cert_row["cert_pem"], reason)
    except acme_client.AcmeClientError as e:
        raise HTTPException(400, str(e))

    # Auto-renew off: a revoked certificate that quietly comes back an hour
    # later is not what anyone means by revoking it.
    await db.execute(
        "UPDATE public_cert_requests SET auto_renew = 0, status = 'pending' WHERE id = ?", (request_id,))


@router.post("/requests/{request_id}/revoke")
async def revoke_now(request_id: int, user: AdminUser, reason: int = 0,
                     db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM public_cert_requests WHERE id = ?", (request_id,)) as cur:
        req = await cur.fetchone()
    if not req or not req["certificate_id"]:
        raise HTTPException(404, "This managed certificate has nothing issued to revoke")
    async with db.execute("SELECT * FROM certificates WHERE id = ?", (req["certificate_id"],)) as cur:
        cert = await cur.fetchone()
    async with db.execute(
        "SELECT * FROM public_acme_accounts WHERE id = ?", (req["account_id"],)) as cur:
        account = await cur.fetchone()
    if not cert or not account:
        raise HTTPException(400, "The certificate or its account is missing")

    # Separation of duties applies here exactly as it does to internal
    # revocation. It was skipped before, which meant the approvals toggle
    # silently covered only half the certificates in the inventory — and the
    # half it missed is the one the public actually depends on.
    from app.api import approvals

    if await approvals.approval_required(db, "revoke"):
        name = next((k for k, v in REASON_CODE_NUMBERS.items() if v == reason), "unspecified")
        request_row = await approvals.create_request(
            db, user, "revoke", certificate_id=cert["id"], reason="", reason_code=name,
        )
        return JSONResponse(
            status_code=202,
            content={
                "pending_approval": True,
                "request_id": request_row["id"],
                "detail": (
                    f"Request {request_row['id']} is awaiting approval from another admin. "
                    "Nothing has been revoked at the CA yet."
                ),
            },
        )

    await revoke_at_ca(db, cert, reason)
    await db.execute(
        """UPDATE certificates SET status = 'revoked', revoked_at = datetime('now'),
               revoked_reason = ? WHERE id = ?""", (str(reason), cert["id"]))
    await db.execute(
        "INSERT INTO cert_events (certificate_id, event_type, message) VALUES (?, 'revoked', ?)",
        (cert["id"], f"Revoked at {account['name']} (reason {reason}) by {user['username']}"))
    await db.commit()
    return {"status": "revoked"}


@router.delete("/requests/{request_id}", status_code=204)
async def delete_request(request_id: int, user: AdminUser,
                         db: aiosqlite.Connection = Depends(get_db)):
    """Stops managing the certificate. What was already issued stays in the
    inventory and stays valid — it is deployed somewhere, and forgetting about
    it here does not untrust it."""
    await db.execute("DELETE FROM public_cert_requests WHERE id = ?", (request_id,))
    await db.commit()
