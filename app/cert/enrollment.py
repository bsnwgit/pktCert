"""
app/cert/enrollment.py
-----------------------
Shared logic behind the enrolment protocols (EST in app/api/est.py, SCEP in
app/api/scep.py): authenticate a profile, decide whether a CSR is allowed
under it, sign it, and record what happened.

Both protocols land here so a device gets the same certificate and the same
policy either way — the wire format differs, the authorisation does not.

The security model is deliberately narrow. A profile is a bearer credential:
anything holding the secret can obtain a certificate. That is unavoidable for
unattended device enrolment, so the containment is in how little a profile can
do — one CA, one template, optionally one name suffix, optionally a hard cap on
how many certificates it may ever issue. A leaked switch-fleet secret should
not be able to mint a certificate for the payroll server.
"""
from __future__ import annotations

import json
import logging
import secrets
from typing import Optional

import aiosqlite

from app.cert import issuance, x509_utils
from app.cert.crypto import decrypt_str

log = logging.getLogger("pktcert.enrollment")


class EnrollmentError(Exception):
    """Enrolment refused. `status` is the HTTP status the protocol layer should
    use; the message is safe to return to the device."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


async def authenticate(
    db: aiosqlite.Connection, protocol: str, secret: str, username: Optional[str] = None
):
    """Find the enabled profile matching these credentials, or raise.

    Compared with secrets.compare_digest so a wrong secret takes the same time
    as a right one — an enrolment endpoint is reachable by anything that can
    route to it, which makes it exactly the kind of endpoint worth guessing at.
    """
    async with db.execute(
        "SELECT * FROM enrollment_profiles WHERE protocol = ? AND enabled = 1", (protocol,)
    ) as cur:
        profiles = await cur.fetchall()

    matched = None
    for profile in profiles:
        if username is not None and (profile["username"] or "") != username:
            continue
        expected = decrypt_str(profile["secret_enc"])
        # Still compare on a mismatched username path above? No — but do
        # compare every remaining candidate rather than breaking early, so the
        # work done doesn't reveal how many profiles nearly matched.
        if expected and secrets.compare_digest(expected, secret):
            matched = profile

    if matched is None:
        raise EnrollmentError("Enrolment credentials not recognised", status=401)
    return matched


def _names_in_csr(csr) -> list[str]:
    from cryptography import x509

    names: list[str] = []
    for attr in csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
        if isinstance(attr.value, str):
            names.append(attr.value)
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names.extend(str(getattr(entry, "value", entry)) for entry in san)
    except x509.ExtensionNotFound:
        pass
    return names


# Baseline key strengths. The template's key_size governs only keys pktCert
# generates itself; an enrolled CSR arrives with whatever key the device chose,
# so without a floor here the CA will sign for a 512-bit RSA key it had no part
# in creating — and a certificate is the CA vouching for that key.
_MIN_RSA_BITS = 2048
_MIN_EC_BITS = 256


def _key_refusal(csr) -> Optional[str]:
    """Why this CSR's public key is too weak to certify, or None if it's fine."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

    pub = csr.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        if pub.key_size < _MIN_RSA_BITS:
            return f"the RSA key is {pub.key_size}-bit and the minimum is {_MIN_RSA_BITS}"
        return None
    if isinstance(pub, ec.EllipticCurvePublicKey):
        if pub.key_size < _MIN_EC_BITS:
            return f"the EC key is {pub.key_size}-bit and the minimum is {_MIN_EC_BITS}"
        return None
    # Ed25519 and Ed448 have no size to check — both are fixed at a safe
    # strength. Anything else (DSA, or a type this version of `cryptography`
    # doesn't model) is refused rather than assumed adequate.
    if isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return None
    return f"its key type ({type(pub).__name__}) is not accepted for enrolment"


def _name_allowed(name: str, suffix: str) -> bool:
    """Whether one subject name falls inside a profile's permitted namespace.

    Matched on a label boundary, not on the raw string. A plain `endswith`
    lets a profile scoped to 'example.com' issue for 'notexample.com' — an
    entirely different domain that merely shares the tail — which silently
    widens every profile whose suffix was written without a leading dot, and
    that is the natural way to write one.

    A leading dot keeps its conventional meaning of "subdomains only", so
    '.corp.example.com' still refuses the apex while 'corp.example.com'
    permits it.
    """
    name = name.lower().rstrip(".")
    if suffix.startswith("."):
        return name.endswith(suffix)
    return name == suffix or name.endswith("." + suffix)


def check_csr_allowed(profile, csr) -> None:
    """Policy check before signing. Raises EnrollmentError if refused."""
    if not csr.is_signature_valid:
        # Proof of possession: the CSR is self-signed with the key it asks to
        # have certified, so this signature is the only evidence the device
        # holds it.
        raise EnrollmentError("CSR signature is invalid — it was not signed by the key it presents")

    weak = _key_refusal(csr)
    if weak:
        raise EnrollmentError(f"This CSR cannot be certified because {weak}", status=403)

    if profile["max_certs"] is not None and profile["issued_count"] >= profile["max_certs"]:
        raise EnrollmentError(
            f"This enrolment profile has reached its limit of {profile['max_certs']} certificates",
            status=403,
        )

    suffix = (profile["allowed_name_suffix"] or "").strip().lower()
    if suffix:
        names = _names_in_csr(csr)
        if not names:
            raise EnrollmentError("CSR contains no subject name to check against this profile's policy", status=403)
        bad = [n for n in names if not _name_allowed(n, suffix)]
        if bad:
            raise EnrollmentError(
                f"This profile may only issue names ending in '{suffix}'; refused: {', '.join(bad)}",
                status=403,
            )


async def log_attempt(
    db: aiosqlite.Connection, *, profile_id: Optional[int], protocol: str, operation: str,
    client_ip: str, subject: str = "", outcome: str, detail: str = "",
    certificate_id: Optional[int] = None,
) -> None:
    await db.execute(
        """INSERT INTO enrollment_log
           (profile_id, protocol, operation, client_ip, subject, outcome, detail, certificate_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (profile_id, protocol, operation, client_ip, subject or None, outcome, detail or None, certificate_id),
    )
    await db.commit()


async def issue_from_csr(db: aiosqlite.Connection, profile, csr_pem: str, protocol: str):
    """Sign an enrolled CSR under a profile's CA and template.

    Goes through the same signing path as every other issuance — same
    extensions, same CRL distribution point, same AIA — so a device-enrolled
    certificate is indistinguishable from one issued through the UI.

    Runs check_csr_allowed() itself rather than trusting the caller to have
    done it. EST and SCEP both call it first and always have, but a protocol
    that forgets gets no name constraint and no key floor and still signs
    perfectly happily — the failure is silent, and the thing it silently
    disables is the only containment a profile has. The check is pure and
    cheap, so running it twice costs nothing and removes the footgun.
    """
    csr = x509_utils.csr_from_pem(csr_pem)
    check_csr_allowed(profile, csr)

    async with db.execute(
        "SELECT * FROM certificate_authorities WHERE id = ?", (profile["ca_id"],)
    ) as cur:
        ca_row = await cur.fetchone()
    if not ca_row:
        raise EnrollmentError("The CA for this enrolment profile no longer exists", status=500)
    if ca_row["status"] != "active":
        raise EnrollmentError(f"The CA for this profile is not active (status: {ca_row['status']})", status=503)
    refusal = issuance.signing_refusal(ca_row)
    if refusal:
        raise EnrollmentError(refusal, status=503)

    async with db.execute(
        "SELECT * FROM cert_templates WHERE id = ?", (profile["template_id"],)
    ) as cur:
        template_row = await cur.fetchone()
    if not template_row:
        raise EnrollmentError("The template for this enrolment profile no longer exists", status=500)

    base_url = await issuance.get_crl_base_url(db)
    crl_url = f"{base_url}/crl/{ca_row['id']}.crl"
    aia_url = f"{base_url}/aia/{ca_row['id']}.crt"

    # Claim the certificate slot before signing, not after. check_csr_allowed()
    # only reads issued_count, so two enrolments arriving together both see room
    # under the cap and both go on to sign — a limit of two issues three. EST
    # devices enrol one at a time and rarely expose it; anything that reconciles
    # in parallel does so immediately, which is why this matters before ACME.
    cur = await db.execute(
        """UPDATE enrollment_profiles
              SET issued_count = issued_count + 1, last_used_at = datetime('now')
            WHERE id = ? AND (max_certs IS NULL OR issued_count < max_certs)""",
        (profile["id"],),
    )
    if cur.rowcount != 1:
        raise EnrollmentError(
            f"This enrolment profile has reached its limit of {profile['max_certs']} certificates",
            status=403,
        )

    import asyncio

    def _sign() -> str:
        ca_cert = x509_utils.cert_from_pem(ca_row["cert_pem"])
        ca_key = x509_utils.key_from_pem(decrypt_str(ca_row["private_key_enc"]))
        cert = x509_utils.sign_certificate(
            csr, ca_cert, ca_key,
            validity_days=template_row["validity_days"],
            key_usage=json.loads(template_row["key_usage_json"]),
            extended_key_usage=json.loads(template_row["extended_key_usage_json"]),
            crl_url=crl_url,
            aia_url=aia_url,
        )
        return x509_utils.cert_to_pem(cert)

    try:
        cert_pem = await asyncio.to_thread(_sign)
        info = x509_utils.parse_certificate(cert_pem)

        # The device generated and holds the private key; pktCert never sees it.
        # That's the right shape for enrolment and is why there's no private_key_enc
        # here — the inventory records what was issued, not a copy of the secret.
        try:
            cur = await db.execute(
                """INSERT INTO certificates
                   (common_name, san_json, issuer, subject, serial_number, fingerprint_sha256,
                    not_before, not_after, key_algorithm, key_size, signature_algorithm,
                    status, source, cert_pem, ca_id, template_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'valid', 'enrolled', ?, ?, ?) RETURNING *""",
                (info["common_name"], json.dumps(info["san"]), info["issuer"], info["subject"],
                 info["serial_number"], info["fingerprint_sha256"], info["not_before"], info["not_after"],
                 info["key_algorithm"], info["key_size"], info["signature_algorithm"],
                 cert_pem, ca_row["id"], template_row["id"]),
            )
            row = await cur.fetchone()
        except aiosqlite.IntegrityError:
            raise EnrollmentError("A certificate with this fingerprint already exists", status=409)
    except Exception:
        # The slot was claimed before signing, so anything that fails between
        # there and here has to give it back — otherwise a profile quietly loses
        # capacity every time an enrolment errors, and a duplicate CSR retried
        # a few times exhausts a cap that was never actually used.
        await db.execute(
            "UPDATE enrollment_profiles SET issued_count = issued_count - 1 WHERE id = ?",
            (profile["id"],),
        )
        await db.commit()
        raise

    await db.execute(
        "INSERT INTO cert_events (certificate_id, ca_id, event_type, message) VALUES (?, ?, 'issued', ?)",
        (row["id"], ca_row["id"],
         f"Enrolled via {protocol.upper()} for '{info['common_name']}' using profile '{profile['name']}'"),
    )
    await db.commit()
    return row, cert_pem
