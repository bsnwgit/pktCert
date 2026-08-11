"""
EST — Enrollment over Secure Transport (RFC 7030).

Served at /.well-known/est/... , outside /api and outside the SPA, because the
paths are fixed by the RFC: a device is built to look there and nowhere else.

Implemented operations:

  GET  /.well-known/est/cacerts        — the CA chain, so a device can install
                                          the trust anchor before it enrols
  POST /.well-known/est/simpleenroll   — enrol: PKCS#10 in, certificate out
  POST /.well-known/est/simplereenroll — the same, for renewal
  GET  /.well-known/est/csrattrs       — what the server would like in a CSR

Everything is base64 with `Content-Transfer-Encoding: base64` and PKCS#7
certs-only responses, exactly as §4 requires. Devices are strict about this;
returning a bare PEM certificate instead of a PKCS#7 bundle is the classic way
to make an EST client fail with no useful diagnostic.

Authentication is HTTP Basic against an enrolment profile (app/cert/
enrollment.py). RFC 7030 also allows TLS client-certificate authentication;
that isn't offered here because it needs the TLS terminator to request and
pass through client certificates, which isn't something pktCert controls when
it's behind a proxy — and silently accepting a weaker check while claiming
client-cert auth would be worse than not offering it.

NOTE ON TRANSPORT: EST is defined over TLS, and a shared enrolment secret sent
over plain HTTP is a shared enrolment secret handed to anyone on the path.
pktCert serves HTTP by default, so these endpoints refuse to operate over a
non-TLS connection unless an operator explicitly accepts the risk with the
est_allow_insecure_http setting — see _require_secure_transport below.
"""
from __future__ import annotations

import base64
import binascii

import aiosqlite
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response

from app.cert import enrollment, x509_utils
from app.database import get_db

router = APIRouter()

_PKCS7_MIME = "application/pkcs7-mime; smime-type=certs-only"


def _b64_lines(der: bytes) -> str:
    """Base64 with the line breaks RFC 7030 §4.1.3 expects."""
    encoded = base64.b64encode(der).decode()
    return "\n".join(encoded[i:i + 64] for i in range(0, len(encoded), 64)) + "\n"


def _pkcs7_response(certs: list) -> Response:
    der = pkcs7.serialize_certificates(certs, serialization.Encoding.DER)
    return Response(
        content=_b64_lines(der),
        media_type=_PKCS7_MIME,
        headers={"Content-Transfer-Encoding": "base64"},
    )


async def _setting_true(db: aiosqlite.Connection, key: str) -> bool:
    import json
    async with db.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cur:
        row = await cur.fetchone()
    if not row or row[0] is None:
        return False
    try:
        return bool(json.loads(row[0]))
    except (ValueError, TypeError):
        return False


async def _require_secure_transport(request: Request, db: aiosqlite.Connection) -> None:
    """Refuse to accept enrolment credentials over plain HTTP.

    EST is specified over TLS for an obvious reason: the request carries a
    shared secret that yields a certificate. Over HTTP that secret is readable
    by anything on the path, and the certificate it produces is trusted by
    everything that trusts the CA. Honouring X-Forwarded-Proto covers the
    normal case of TLS terminating at a reverse proxy.
    """
    if request.url.scheme == "https":
        return
    if (request.headers.get("x-forwarded-proto") or "").lower() == "https":
        return
    if await _setting_true(db, "est_allow_insecure_http"):
        return
    raise HTTPException(
        status_code=421,
        detail=(
            "EST requires TLS — this request arrived over plain HTTP, which would expose the "
            "enrolment secret to anything on the network path. Terminate TLS in front of pktCert "
            "(or enable SSL under Settings → Security). To allow HTTP anyway on a trusted, "
            "isolated network, set est_allow_insecure_http."
        ),
    )


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _basic_credentials(authorization: str | None) -> tuple[str, str]:
    if not authorization or not authorization.lower().startswith("basic "):
        raise HTTPException(
            status_code=401,
            detail="EST enrolment requires HTTP Basic authentication",
            headers={"WWW-Authenticate": 'Basic realm="pktCert EST"'},
        )
    try:
        decoded = base64.b64decode(authorization.split(" ", 1)[1]).decode()
    except (binascii.Error, UnicodeDecodeError, IndexError):
        raise HTTPException(status_code=401, detail="Malformed Authorization header")
    username, _, password = decoded.partition(":")
    return username, password


async def _ca_chain(db: aiosqlite.Connection) -> list:
    """Every CA certificate this server knows about.

    cacerts is unauthenticated, so there's no profile to tell us which CA the
    caller intends to enrol against — and picking one (say, the lowest id)
    would hand a device enrolling against an intermediate nothing but the root,
    leaving it unable to build a chain. RFC 7030 §4.1.3 wants the certificates
    needed to establish trust, so return the lot: roots first, since some
    clients install in the order given, and deduplicated by fingerprint.
    """
    async with db.execute(
        """SELECT cert_pem FROM certificate_authorities
           WHERE cert_pem != '' AND status IN ('active', 'disabled')
           ORDER BY CASE ca_type WHEN 'root' THEN 0 ELSE 1 END, id"""
    ) as cur:
        rows = await cur.fetchall()

    chain, seen = [], set()
    for row in rows:
        try:
            cert = x509_utils.cert_from_pem(row["cert_pem"])
        except Exception:
            continue
        fingerprint = cert.fingerprint(hashes.SHA256())
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        chain.append(cert)

    if not chain:
        raise HTTPException(404, "No CA certificate available")
    return chain


@router.get("/cacerts")
async def cacerts(request: Request, db: aiosqlite.Connection = Depends(get_db)):
    """RFC 7030 §4.1 — unauthenticated by design. A device has to be able to
    obtain the trust anchor before it has any credential to present, and the
    CA certificate is public regardless."""
    chain = await _ca_chain(db)
    await enrollment.log_attempt(
        db, profile_id=None, protocol="est", operation="cacerts",
        client_ip=_client_ip(request), outcome="issued",
        detail=f"{len(chain)} certificate(s) returned",
    )
    return _pkcs7_response(chain)


@router.get("/csrattrs")
async def csrattrs():
    """RFC 7030 §4.5. pktCert imposes nothing beyond what the profile's
    template already dictates, so this is an empty (204) response — which the
    RFC explicitly permits and which clients handle as "no extra attributes
    required"."""
    return Response(status_code=204)


async def _enroll(request: Request, db: aiosqlite.Connection, authorization: str | None, operation: str):
    await _require_secure_transport(request, db)
    username, password = _basic_credentials(authorization)
    client_ip = _client_ip(request)

    try:
        profile = await enrollment.authenticate(db, "est", password, username=username)
    except enrollment.EnrollmentError as e:
        await enrollment.log_attempt(
            db, profile_id=None, protocol="est", operation=operation,
            client_ip=client_ip, outcome="denied", detail=str(e),
        )
        raise HTTPException(
            status_code=e.status, detail=str(e),
            headers={"WWW-Authenticate": 'Basic realm="pktCert EST"'},
        )

    raw = await request.body()
    try:
        # The body is base64 PKCS#10, per §4.2.1 — with or without PEM armour
        # depending on the client, so accept both rather than being pedantic
        # about something that costs nothing to tolerate.
        text = raw.decode().strip()
        if "-----BEGIN CERTIFICATE REQUEST-----" in text:
            csr_pem = text
        else:
            der = base64.b64decode("".join(text.split()))
            csr_pem = x509_utils.csr_der_to_pem(der)
        csr = x509_utils.csr_from_pem(csr_pem)
    except Exception as e:
        await enrollment.log_attempt(
            db, profile_id=profile["id"], protocol="est", operation=operation,
            client_ip=client_ip, outcome="error", detail=f"Unreadable CSR: {e}",
        )
        raise HTTPException(400, f"Could not read the PKCS#10 request: {e}")

    subject = csr.subject.rfc4514_string()
    try:
        enrollment.check_csr_allowed(profile, csr)
        row, cert_pem = await enrollment.issue_from_csr(db, profile, csr_pem, "est")
    except enrollment.EnrollmentError as e:
        await enrollment.log_attempt(
            db, profile_id=profile["id"], protocol="est", operation=operation,
            client_ip=client_ip, subject=subject, outcome="denied", detail=str(e),
        )
        raise HTTPException(status_code=e.status, detail=str(e))

    await enrollment.log_attempt(
        db, profile_id=profile["id"], protocol="est", operation=operation,
        client_ip=client_ip, subject=subject, outcome="issued",
        detail=f"profile '{profile['name']}'", certificate_id=row["id"],
    )
    return _pkcs7_response([x509_utils.cert_from_pem(cert_pem)])


@router.post("/simpleenroll")
async def simpleenroll(
    request: Request,
    authorization: str | None = Header(default=None),
    db: aiosqlite.Connection = Depends(get_db),
):
    return await _enroll(request, db, authorization, "simpleenroll")


@router.post("/simplereenroll")
async def simplereenroll(
    request: Request,
    authorization: str | None = Header(default=None),
    db: aiosqlite.Connection = Depends(get_db),
):
    """RFC 7030 §4.2.2. Identical handling to enrolment here: the device
    presents a fresh CSR and receives a fresh certificate. pktCert does not
    require the old certificate to be presented, because that would mean
    accepting TLS client-certificate authentication, which isn't offered (see
    the module docstring)."""
    return await _enroll(request, db, authorization, "simplereenroll")
