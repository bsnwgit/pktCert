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
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

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


def generate_private_key(algorithm: str = "rsa", key_size: int = 2048):
    if algorithm == "ec":
        curve = {2048: ec.SECP256R1(), 3072: ec.SECP384R1(), 4096: ec.SECP521R1()}.get(key_size, ec.SECP256R1())
        return ec.generate_private_key(curve)
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size or 2048)


def key_to_pem(key) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def key_from_pem(pem: str):
    return serialization.load_pem_private_key(pem.encode(), password=None)


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


def build_ca_certificate(
    name: str,
    key,
    ca_type: str = "root",
    validity_days: int = 3650,
    parent_cert: Optional[x509.Certificate] = None,
    parent_key=None,
) -> x509.Certificate:
    """Self-signed root, or an intermediate signed by parent_cert/parent_key."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer = parent_cert.subject if parent_cert is not None else subject
    signing_key = parent_key if parent_key is not None else key

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
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
    if parent_cert is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(parent_cert.public_key()), critical=False
        )
    return builder.sign(signing_key, hashes.SHA256())


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


def sign_certificate(
    csr: x509.CertificateSigningRequest,
    ca_cert: x509.Certificate,
    ca_key,
    validity_days: int = 365,
    key_usage: Optional[list[str]] = None,
    extended_key_usage: Optional[list[str]] = None,
    crl_url: Optional[str] = None,
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

    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        builder = builder.add_extension(san_ext.value, critical=False)
    except x509.ExtensionNotFound:
        pass

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

    return builder.sign(ca_key, hashes.SHA256())


def build_crl(ca_cert: x509.Certificate, ca_key, revoked: list[dict], crl_number: int) -> str:
    """revoked: list of {"serial_number": int, "revoked_at": datetime, "reason": str|None}."""
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=7))
        .add_extension(x509.CRLNumber(crl_number), critical=False)
    )
    for entry in revoked:
        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(entry["serial_number"])
            .revocation_date(entry["revoked_at"])
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM).decode()


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
