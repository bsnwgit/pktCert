"""
X.509 / PKI primitives used across the discovery scanner and the internal
CA issuance flow. Thin, deliberately synchronous wrappers around the
`cryptography` library — callers run these via asyncio.to_thread since key
generation and signing are CPU-bound.
"""
from __future__ import annotations

import datetime
import ipaddress
import ssl
import socket
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID, ExtendedKeyUsageOID

_KEY_USAGE_MAP = {
    "digital_signature": "digital_signature",
    "key_encipherment": "key_encipherment",
    "content_commitment": "content_commitment",
    "data_encipherment": "data_encipherment",
    "key_agreement": "key_agreement",
    "key_cert_sign": "key_cert_sign",
    "crl_sign": "crl_sign",
}

_EKU_MAP = {
    "server_auth": ExtendedKeyUsageOID.SERVER_AUTH,
    "client_auth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "code_signing": ExtendedKeyUsageOID.CODE_SIGNING,
    "email_protection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "ocsp_signing": ExtendedKeyUsageOID.OCSP_SIGNING,
    "time_stamping": ExtendedKeyUsageOID.TIME_STAMPING,
}

# RFC 5280 §5.3.1 reasonCode values. Relying parties act on these differently:
# key_compromise casts doubt on every signature that key ever made, while
# superseded or cessation_of_operation are routine lifecycle events. Publishing
# revocations without a code throws that distinction away.
#
# remove_from_crl is deliberately absent — it only has meaning in a delta CRL,
# for lifting a certificate_hold, and pktCert doesn't issue delta CRLs.
REASON_CODES = {
    "unspecified": x509.ReasonFlags.unspecified,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aa_compromise": x509.ReasonFlags.aa_compromise,
}


def generate_private_key(algorithm: str = "rsa", key_size: int = 2048):
    if algorithm == "ec":
        curve = {2048: ec.SECP256R1(), 3072: ec.SECP384R1(), 4096: ec.SECP521R1()}.get(key_size, ec.SECP256R1())
        return ec.generate_private_key(curve)
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size or 2048)


def key_to_pem(key, passphrase: Optional[str] = None) -> str:
    """Serialize a private key to PKCS#8 PEM. When a non-empty passphrase is
    given, the PEM itself is encrypted (BestAvailableEncryption) so that
    anything installing the key — e.g. a remote web server — must supply that
    passphrase. pktCert does not store the passphrase; it only hands the
    encrypted PEM back to the operator."""
    if passphrase:
        encryption = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    ).decode()


def key_from_pem(pem: str, passphrase: Optional[str] = None):
    """Load a PKCS#8/PKCS#1 private key PEM. `passphrase` is required for a
    key that was exported encrypted — which is how any properly stored CA key
    is kept, so importing one was previously impossible."""
    return serialization.load_pem_private_key(
        pem.encode(), password=passphrase.encode("utf-8") if passphrase else None
    )


def key_matches_certificate(key, cert: x509.Certificate) -> bool:
    """Does this private key actually belong to this certificate?

    Nothing else checks it: a CA imported with a mismatched key is accepted
    happily and then fails at the first signing attempt, or worse, produces
    certificates that no client can verify against the CA everyone trusts.
    Compares public numbers rather than serialised bytes so encoding
    differences don't read as a mismatch."""
    try:
        return key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ) == cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception:
        return False


def certificate_ca_problems(cert: x509.Certificate) -> list[str]:
    """Reasons this certificate can't act as a CA, empty if it can.

    Importing a leaf certificate as a "CA" used to be accepted without
    complaint. Every certificate it then issued would be rejected by any
    conforming client — the failure surfaces far away from the mistake, at
    every relying party rather than here."""
    problems: list[str] = []
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not bc.ca:
            problems.append("BasicConstraints says this is not a CA certificate (ca=False)")
    except x509.ExtensionNotFound:
        problems.append("no BasicConstraints extension — a CA certificate must assert ca=True")

    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not ku.key_cert_sign:
            problems.append("KeyUsage does not include keyCertSign, so it may not sign certificates")
    except x509.ExtensionNotFound:
        # KeyUsage is optional in X.509; absent means unrestricted, so this is
        # unusual for a CA but not itself invalid.
        pass

    return problems


def certificate_constraints(cert: x509.Certificate) -> tuple[Optional[int], Optional[dict]]:
    """Read back the path length and name constraints an existing CA carries,
    so an imported CA displays the same constraint information as a generated
    one instead of looking unconstrained."""
    path_length = None
    try:
        path_length = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length
    except x509.ExtensionNotFound:
        pass

    constraints = None
    try:
        nc = cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return path_length, None

    def _split(subtrees) -> tuple[list[str], list[str]]:
        dns, ips = [], []
        for entry in subtrees or []:
            if isinstance(entry, x509.DNSName):
                dns.append(entry.value)
            elif isinstance(entry, x509.IPAddress):
                ips.append(str(entry.value))
        return dns, ips

    permitted_dns, permitted_ip = _split(nc.permitted_subtrees)
    excluded_dns, excluded_ip = _split(nc.excluded_subtrees)
    constraints = {
        "permitted_dns": permitted_dns, "excluded_dns": excluded_dns,
        "permitted_ip": permitted_ip, "excluded_ip": excluded_ip,
    }
    return path_length, constraints


def cert_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def cert_from_pem(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode())


def load_pkcs12_bundle(data: bytes, passphrase: Optional[str]) -> tuple[str, Optional[str], str]:
    """Parse a PKCS#12 (.pfx/.p12) bundle — used for uploading an
    externally-issued certificate that wasn't exported as separate PEM
    files. Returns (cert_pem, key_pem_or_None, chain_pem)."""
    pw = passphrase.encode() if passphrase else None
    private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(data, pw)
    if certificate is None:
        raise ValueError("PKCS#12 bundle has no certificate")
    cert_pem = cert_to_pem(certificate)
    key_pem = key_to_pem(private_key) if private_key is not None else None
    chain_pem = cert_pem + "".join(cert_to_pem(c) for c in (additional_certs or []))
    return cert_pem, key_pem, chain_pem


def _build_key_usage(usages: list[str]) -> x509.KeyUsage:
    kwargs = {name: (name in usages) for name in _KEY_USAGE_MAP}
    # x509.KeyUsage requires these two even when unused
    kwargs.setdefault("encipher_only", False)
    kwargs.setdefault("decipher_only", False)
    return x509.KeyUsage(**kwargs)


def _san_list(sans: list[str]) -> list:
    entries = []
    for s in sans:
        s = s.strip()
        if not s:
            continue
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(s)))
        except ValueError:
            entries.append(x509.DNSName(s))
    return entries


def _build_name_constraints(constraints: dict) -> Optional[x509.NameConstraints]:
    """Turn {"permitted_dns": [...], "excluded_dns": [...], "permitted_ip": [...],
    "excluded_ip": [...]} into a NameConstraints extension, or None if empty.

    Name constraints are the single most valuable containment control for an
    internal CA: a CA constrained to ".corp.example.com" cannot mint a working
    certificate for a bank, even if its key is stolen. Without them, any CA in
    a trust store is a CA for the entire internet."""
    def _subtrees(dns_names: list[str], ip_ranges: list[str]) -> list:
        out: list = []
        for name in dns_names or []:
            name = name.strip()
            if name:
                out.append(x509.DNSName(name))
        for cidr in ip_ranges or []:
            cidr = cidr.strip()
            if cidr:
                out.append(x509.IPAddress(ipaddress.ip_network(cidr, strict=False)))
        return out

    permitted = _subtrees(constraints.get("permitted_dns", []), constraints.get("permitted_ip", []))
    excluded = _subtrees(constraints.get("excluded_dns", []), constraints.get("excluded_ip", []))
    if not permitted and not excluded:
        return None
    return x509.NameConstraints(
        permitted_subtrees=permitted or None,
        excluded_subtrees=excluded or None,
    )


def build_ca_certificate(
    name: str,
    key,
    ca_type: str = "root",
    validity_days: int = 3650,
    parent_cert: Optional[x509.Certificate] = None,
    parent_key=None,
    path_length: Optional[int] = None,
    name_constraints: Optional[dict] = None,
    aia_url: Optional[str] = None,
) -> x509.Certificate:
    """Self-signed root, or an intermediate signed by parent_cert/parent_key.

    path_length caps how many further CAs may appear below this one. An
    intermediate defaults to 0 — it may issue end-entity certificates but not
    another CA. Previously every CA was built with path_length=None, so any
    intermediate could mint an unlimited chain of further sub-CAs, which makes
    a single compromised intermediate as dangerous as the root.
    """
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer = parent_cert.subject if parent_cert is not None else subject
    signing_key = parent_key if parent_key is not None else key

    if path_length is None and ca_type == "intermediate":
        path_length = 0

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )

    if name_constraints:
        nc = _build_name_constraints(name_constraints)
        if nc is not None:
            # Critical, per RFC 5280 — a client that can't understand the
            # constraint must reject the chain rather than ignore the limit.
            builder = builder.add_extension(nc, critical=True)

    if parent_cert is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(parent_cert.public_key()), critical=False
        )
        if aia_url:
            builder = builder.add_extension(
                x509.AuthorityInformationAccess([
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(aia_url),
                    )
                ]),
                critical=False,
            )
    return builder.sign(signing_key, hashes.SHA256())


def generate_ca_csr(
    name: str,
    key,
    path_length: Optional[int] = 0,
    name_constraints: Optional[dict] = None,
) -> x509.CertificateSigningRequest:
    """Build a CSR for an intermediate CA, to be signed out-of-band by an
    offline root.

    The requested extensions are included in the CSR. A signing CA is free to
    ignore them — it is the signer, not the requester, that decides what a
    certificate says — but stating them means the operator at the offline
    machine can copy the intended constraints rather than reconstruct them
    from memory, which is where path-length and name-constraint mistakes
    creep in.
    """
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=path_length), critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False,
        ),
        critical=True,
    )
    if name_constraints:
        nc = _build_name_constraints(name_constraints)
        if nc is not None:
            builder = builder.add_extension(nc, critical=True)
    return builder.sign(key, hashes.SHA256())


def verify_certificate_signed_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Was `child` actually signed by `issuer`'s key?

    Used when a signed intermediate comes back from an offline root: without
    this, a certificate signed by the wrong CA (or a typo'd copy-paste from
    another machine) is accepted and every certificate issued beneath it fails
    verification at the relying party, far from the mistake."""
    try:
        issuer.public_key().verify(
            child.signature,
            child.tbs_certificate_bytes,
            *_verify_args(child, issuer.public_key()),
        )
        return True
    except Exception:
        return False


def _verify_args(child: x509.Certificate, issuer_public_key):
    """Signature-verification arguments differ by key type: RSA needs a
    padding, EC needs an ECDSA wrapper, Ed25519 takes neither."""
    from cryptography.hazmat.primitives.asymmetric import padding as _padding

    if isinstance(issuer_public_key, rsa.RSAPublicKey):
        return (_padding.PKCS1v15(), child.signature_hash_algorithm)
    if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
        return (ec.ECDSA(child.signature_hash_algorithm),)
    return ()


def generate_csr(common_name: str, sans: list[str], key) -> x509.CertificateSigningRequest:
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    )
    entries = _san_list(sans or [common_name])
    if entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(entries), critical=False)
    return builder.sign(key, hashes.SHA256())


def csr_to_pem(csr: x509.CertificateSigningRequest) -> str:
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def csr_from_pem(pem: str) -> x509.CertificateSigningRequest:
    return x509.load_pem_x509_csr(pem.encode())


def csr_der_to_pem(der: bytes) -> str:
    """Enrolment protocols carry PKCS#10 as raw DER; everything internal
    speaks PEM."""
    return x509.load_der_x509_csr(der).public_bytes(serialization.Encoding.PEM).decode()


def sign_certificate(
    csr: x509.CertificateSigningRequest,
    ca_cert: x509.Certificate,
    ca_key,
    validity_days: int = 365,
    key_usage: Optional[list[str]] = None,
    extended_key_usage: Optional[list[str]] = None,
    crl_url: Optional[str] = None,
    aia_url: Optional[str] = None,
) -> x509.Certificate:
    """Sign a CSR with the given CA, applying the template's usage extensions."""
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_build_key_usage(key_usage or ["digital_signature", "key_encipherment"]), critical=True)
    )

    eku_oids = [_EKU_MAP[e] for e in (extended_key_usage or ["server_auth"]) if e in _EKU_MAP]
    if eku_oids:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku_oids), critical=False)

    # Browsers and most modern TLS stacks ignore the CN for hostname matching
    # and look only at SAN, so a certificate whose CN is absent from its SAN
    # looks correct in every UI and still fails verification. The /issue path
    # merges the two before it builds its CSR, but a CSR generated elsewhere
    # (POST /api/certificates/csr) carries whatever SAN its author put there —
    # so enforce it here, where every issuance path passes through.
    san_entries: list = []
    try:
        san_entries = list(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        pass
    existing = {str(getattr(e, "value", e)) for e in san_entries}
    for attr in csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        cn = attr.value
        if isinstance(cn, str) and cn and cn not in existing:
            san_entries.extend(_san_list([cn]))
            existing.add(cn)
    if san_entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False
    )

    # Without this, nothing consuming the cert has any way to discover a
    # CRL exists — revoking a cert would only ever update pktCert's own
    # database, never anything the client trusting the cert can see.
    if crl_url:
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_url)],
                    relative_name=None, reasons=None, crl_issuer=None,
                )
            ]),
            critical=False,
        )

    # caIssuers tells a client where to fetch the issuing CA certificate when
    # it doesn't already have it. A server that sends only its leaf (very
    # common) is unverifiable without this — the client has a certificate
    # signed by an issuer it can't obtain, and chain building simply fails.
    if aia_url:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier(aia_url),
                )
            ]),
            critical=False,
        )

    return builder.sign(ca_key, hashes.SHA256())


def build_crl(ca_cert: x509.Certificate, ca_key, revoked: list[dict], crl_number: int) -> str:
    """revoked: list of {"serial_number": int, "revoked_at": datetime, "reason": str|None}
    where reason is a key of REASON_CODES."""
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=7))
        .add_extension(x509.CRLNumber(crl_number), critical=False)
    )
    for entry in revoked:
        entry_builder = (
            x509.RevokedCertificateBuilder()
            .serial_number(entry["serial_number"])
            .revocation_date(entry["revoked_at"])
        )
        # 'unspecified' is omitted deliberately: RFC 5280 §5.3.1 says the
        # reasonCode extension SHOULD be absent rather than present-and-
        # unspecified, since an explicit "unspecified" carries no more
        # information than no extension at all.
        reason = REASON_CODES.get((entry.get("reason") or "").strip())
        if reason is not None and reason != x509.ReasonFlags.unspecified:
            entry_builder = entry_builder.add_extension(x509.CRLReason(reason), critical=False)
        revoked_cert = entry_builder.build()
        builder = builder.add_revoked_certificate(revoked_cert)
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM).decode()


def crl_from_pem(pem: str) -> x509.CertificateRevocationList:
    return x509.load_pem_x509_crl(pem.encode())


def _name_to_str(name: x509.Name) -> str:
    return name.rfc4514_string()


def parse_certificate(pem: str) -> dict:
    """Extract the fields the discovery/inventory UI cares about from a PEM cert."""
    cert = cert_from_pem(pem)
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        cn = _name_to_str(cert.subject)

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(getattr(entry, "value", entry)) for entry in san_ext.value]
    except x509.ExtensionNotFound:
        pass

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key_algorithm, key_size = "rsa", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_algorithm, key_size = "ec", pub.key_size
    else:
        key_algorithm, key_size = "unknown", 0

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    return {
        "common_name": cn,
        "san": sans,
        "subject": _name_to_str(cert.subject),
        "issuer": _name_to_str(cert.issuer),
        "serial_number": format(cert.serial_number, "x"),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "key_algorithm": key_algorithm,
        "key_size": key_size,
        "signature_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown",
    }


def fetch_cert_chain(host: str, port: int, timeout: float = 5.0) -> tuple[str, str]:
    """Connect via TLS and return (leaf_pem, chain_pem). Chain may equal leaf
    if the peer doesn't send intermediates (common for simple servers)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der_chain: Optional[list[bytes]] = None
            try:
                # Python 3.13+ only; returns raw DER bytes per cert, unverified
                # since verify_mode is CERT_NONE above.
                der_chain = ssock.get_unverified_chain()
            except Exception:
                der_chain = None
            leaf_der = ssock.getpeercert(binary_form=True)

    leaf_pem = ssl.DER_cert_to_PEM_cert(leaf_der)
    if der_chain:
        chain_pem = "".join(ssl.DER_cert_to_PEM_cert(c) for c in der_chain)
    else:
        chain_pem = leaf_pem
    return leaf_pem, chain_pem
