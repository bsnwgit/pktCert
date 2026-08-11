"""
SCEP — Simple Certificate Enrollment Protocol (RFC 8894).

Served at /scep, the conventional location. Everything is one endpoint
distinguished by an `operation` query parameter, because SCEP was designed in
the 1990s for devices with minimal HTTP stacks:

  GET  /scep?operation=GetCACert      — the CA certificate(s)
  GET  /scep?operation=GetCACaps      — what this server supports
  GET  /scep?operation=PKIOperation   — enrol (base64 in the query string)
  POST /scep?operation=PKIOperation   — enrol (binary body; preferred)

Why bother, given EST exists and is better in every respect: SCEP is what
network equipment actually speaks. Cisco IOS and ASA, Juniper, Palo Alto,
Fortinet, and every MDM pushing certificates to laptops and phones. EST is the
modern replacement, but on kit more than a few years old SCEP is often the only
option present.

Authentication is a challenge password carried inside the CSR, matched against
an enrolment profile's secret (app/cert/enrollment.py). That's weaker than
EST's per-request Basic auth — there is no username, and the secret is shared
across every device using that profile — which is exactly why profile scoping
(name suffix, certificate cap) earns its keep here.

Unlike EST, SCEP does *not* require TLS. The request body is itself encrypted
to the CA's public key, so the challenge password isn't exposed to the network
the way an EST secret over plain HTTP would be. Devices routinely enrol over
plain HTTP, and refusing that would make this endpoint useless for the hardware
it exists to serve.
"""
from __future__ import annotations

import base64
import binascii
import logging

import aiosqlite
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from app.cert import enrollment, scep_messages, x509_utils
from app.cert.crypto import decrypt_str
from app.database import get_db

log = logging.getLogger("pktcert.scep")

router = APIRouter()

# What this server supports, one per line, per RFC 8894 §3.5.2. Advertising
# POSTPKIOperation matters: without it a device sends the whole request
# base64-encoded in a GET query string, which large CSRs overflow.
CA_CAPS = "\n".join([
    "POSTPKIOperation",
    "SHA-256",
    "SHA-512",
    "AES",
    "SCEPStandard",
])


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _scep_ca(db: aiosqlite.Connection):
    """The CA that SCEP enrolments run through.

    Taken from the enabled SCEP profiles rather than configured separately —
    a profile already names its CA, and having two places to set it is how
    they end up disagreeing.
    """
    async with db.execute(
        """SELECT ca.* FROM certificate_authorities ca
           JOIN enrollment_profiles p ON p.ca_id = ca.id
           WHERE p.protocol = 'scep' AND p.enabled = 1 AND ca.status = 'active'
           ORDER BY ca.id LIMIT 1"""
    ) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(
            503,
            "No SCEP enrolment profile is configured. Create one under "
            "Settings → Enrolment before pointing devices here.",
        )
    return row


async def _ca_chain(db: aiosqlite.Connection, ca_row) -> list:
    """The CA plus everything above it, so a device can build a full path."""
    chain, seen = [], set()
    current = ca_row["id"]
    while current is not None and current not in seen:
        seen.add(current)
        async with db.execute(
            "SELECT cert_pem, parent_ca_id FROM certificate_authorities WHERE id = ?", (current,)
        ) as cur:
            row = await cur.fetchone()
        if not row or not row["cert_pem"]:
            break
        chain.append(x509_utils.cert_from_pem(row["cert_pem"]))
        current = row["parent_ca_id"]
    return chain


@router.get("")
@router.get("/")
async def scep_get(
    request: Request,
    operation: str = "",
    message: str = "",
    db: aiosqlite.Connection = Depends(get_db),
):
    if operation == "GetCACaps":
        return Response(content=CA_CAPS, media_type="text/plain")

    if operation == "GetCACert":
        ca_row = await _scep_ca(db)
        chain = await _ca_chain(db, ca_row)
        await enrollment.log_attempt(
            db, profile_id=None, protocol="scep", operation="getcacert",
            client_ip=_client_ip(request), outcome="issued",
            detail=f"{len(chain)} certificate(s) returned",
        )
        if len(chain) == 1:
            # A single CA goes back bare, per §4.2.1 — some older clients
            # cannot parse a PKCS#7 here.
            return Response(
                content=chain[0].public_bytes(serialization.Encoding.DER),
                media_type="application/x-x509-ca-cert",
            )
        return Response(
            content=pkcs7.serialize_certificates(chain, serialization.Encoding.DER),
            media_type="application/x-x509-ca-ra-cert",
        )

    if operation == "PKIOperation":
        if not message:
            raise HTTPException(400, "PKIOperation requires a message parameter")
        try:
            # The query-string form is base64, and often URL-encoded on top —
            # FastAPI has already undone the URL layer by this point.
            der = base64.b64decode(message)
        except (binascii.Error, ValueError) as e:
            raise HTTPException(400, f"message is not valid base64: {e}")
        return await _pki_operation(request, db, der)

    raise HTTPException(400, f"Unsupported or missing operation: {operation or '(none)'}")


@router.post("")
@router.post("/")
async def scep_post(
    request: Request,
    operation: str = "",
    db: aiosqlite.Connection = Depends(get_db),
):
    if operation != "PKIOperation":
        raise HTTPException(400, f"POST supports only PKIOperation, not {operation or '(none)'}")
    body = await request.body()
    if not body:
        raise HTTPException(400, "Empty request body")
    return await _pki_operation(request, db, body)


async def _pki_operation(request: Request, db: aiosqlite.Connection, der: bytes) -> Response:
    """Handle a PKCSReq: unwrap it, authorise it, and answer with a CertRep.

    A SCEP failure is reported *inside* a signed CertRep, not as an HTTP error.
    Devices largely ignore HTTP status codes here, and one that gets a 403 with
    no CertRep typically just retries forever. Returning a proper failure
    response with a failInfo is the difference between a device that reports a
    problem and one that silently loops.
    """
    ca_row = await _scep_ca(db)
    client_ip = _client_ip(request)
    ca_cert = x509_utils.cert_from_pem(ca_row["cert_pem"])
    ca_key = x509_utils.key_from_pem(decrypt_str(ca_row["private_key_enc"]))

    try:
        scep_request = scep_messages.parse_pki_message(der, ca_cert, ca_key)
    except scep_messages.ScepError as e:
        # Nothing parsed, so there's no transactionID to answer against and no
        # signer certificate to encrypt to — an HTTP error is all that's left.
        await enrollment.log_attempt(
            db, profile_id=None, protocol="scep", operation="pkioperation",
            client_ip=client_ip, outcome="error", detail=str(e),
        )
        raise HTTPException(400, str(e))

    def fail(reason: str, code: str, profile_id=None, subject: str = "") -> Response:
        log.info(f"SCEP request from {client_ip} refused: {reason}")
        body = scep_messages.build_cert_rep(
            scep_request, None, ca_cert, ca_key, failure=code
        )
        return Response(content=body, media_type="application/x-pki-message")

    if scep_request.message_type != scep_messages.MESSAGE_TYPE_PKCS_REQ:
        await enrollment.log_attempt(
            db, profile_id=None, protocol="scep", operation="pkioperation",
            client_ip=client_ip, outcome="denied",
            detail=f"unsupported messageType {scep_request.message_type}",
        )
        return fail("unsupported messageType", scep_messages.FAIL_INFO_BAD_REQUEST)

    csr = x509_utils.csr_from_pem(x509_utils.csr_der_to_pem(scep_request.csr_der))
    subject = csr.subject.rfc4514_string()

    if not scep_request.challenge_password:
        await enrollment.log_attempt(
            db, profile_id=None, protocol="scep", operation="pkioperation",
            client_ip=client_ip, subject=subject, outcome="denied",
            detail="no challenge password in the CSR",
        )
        return fail("no challenge password", scep_messages.FAIL_INFO_BAD_IDENTITY)

    try:
        profile = await enrollment.authenticate(db, "scep", scep_request.challenge_password)
    except enrollment.EnrollmentError as e:
        await enrollment.log_attempt(
            db, profile_id=None, protocol="scep", operation="pkioperation",
            client_ip=client_ip, subject=subject, outcome="denied", detail=str(e),
        )
        return fail(str(e), scep_messages.FAIL_INFO_BAD_IDENTITY)

    try:
        enrollment.check_csr_allowed(profile, csr)
        row, cert_pem = await enrollment.issue_from_csr(
            db, profile, x509_utils.csr_der_to_pem(scep_request.csr_der), "scep"
        )
    except enrollment.EnrollmentError as e:
        await enrollment.log_attempt(
            db, profile_id=profile["id"], protocol="scep", operation="pkioperation",
            client_ip=client_ip, subject=subject, outcome="denied", detail=str(e),
        )
        return fail(str(e), scep_messages.FAIL_INFO_BAD_REQUEST)

    chain = await _ca_chain(db, ca_row)
    body = scep_messages.build_cert_rep(
        scep_request, x509_utils.cert_from_pem(cert_pem), ca_cert, ca_key, chain=chain,
    )
    await enrollment.log_attempt(
        db, profile_id=profile["id"], protocol="scep", operation="pkioperation",
        client_ip=client_ip, subject=subject, outcome="issued",
        detail=f"profile '{profile['name']}'", certificate_id=row["id"],
    )
    return Response(content=body, media_type="application/x-pki-message")
