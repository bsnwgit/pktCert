"""
app/cert/scep_messages.py
--------------------------
The SCEP wire format (RFC 8894): parsing a device's PKCSReq and building the
CertRep that answers it.

SCEP predates every convenience. A request is a PKCS#7 SignedData whose
content is a PKCS#7 EnvelopedData encrypted to the CA, and inside *that* is
the PKCS#10 certificate request. The device signs the outer layer with a
throwaway self-signed certificate it makes on the spot — it has no certificate
yet, so it can only vouch for itself.

Four attributes ride in the signature's authenticated attributes and carry the
actual protocol:

  messageType    19  = PKCSReq (enrol), 3 = CertRep (our answer)
  transactionID      device-chosen, echoed back so it can match the reply
  senderNonce        device-chosen; we echo it as recipientNonce
  pkiStatus          0 SUCCESS, 2 FAILURE, 3 PENDING — response only

`cryptography` handles the envelope (encrypt/decrypt) and the signing, but its
PKCS7SignatureBuilder cannot attach arbitrary authenticated attributes, which
is precisely what SCEP is made of. So the SignedData layer is assembled here
with asn1crypto, which models CMS properly, and the cryptographic operations
are still done by `cryptography`.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Optional

from asn1crypto import cms, core, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7

# SCEP's attribute OIDs, from Verisign's original allocation — unchanged since,
# and still what every implementation looks for.
OID_MESSAGE_TYPE = "2.16.840.1.113733.1.9.2"
OID_PKI_STATUS = "2.16.840.1.113733.1.9.3"
OID_FAIL_INFO = "2.16.840.1.113733.1.9.4"
OID_SENDER_NONCE = "2.16.840.1.113733.1.9.5"
OID_TRANSACTION_ID = "2.16.840.1.113733.1.9.7"
OID_RECIPIENT_NONCE = "2.16.840.1.113733.1.9.6"

# PKCS#9 challengePassword, where SCEP puts its shared secret.
_CHALLENGE_PASSWORD_OID = x509.ObjectIdentifier("1.2.840.113549.1.9.7")

MESSAGE_TYPE_PKCS_REQ = "19"
MESSAGE_TYPE_CERT_REP = "3"

PKI_STATUS_SUCCESS = "0"
PKI_STATUS_FAILURE = "2"

FAIL_INFO_BAD_REQUEST = "2"      # badRequest
FAIL_INFO_BAD_IDENTITY = "3"     # badIdentity — authentication failed


# asn1crypto types an attribute's values by its OID, so SCEP's attributes have
# to be registered before they can be built or read as anything but opaque
# bytes. Registering them means the rest of this module can hand over ordinary
# Python values and get correctly-typed DER back.

class _SetOfPrintableString(core.SetOf):
    _child_spec = core.PrintableString


class _SetOfOctetString(core.SetOf):
    _child_spec = core.OctetString


_SCEP_ATTRIBUTES = {
    OID_MESSAGE_TYPE: ("scep_message_type", _SetOfPrintableString),
    OID_PKI_STATUS: ("scep_pki_status", _SetOfPrintableString),
    OID_FAIL_INFO: ("scep_fail_info", _SetOfPrintableString),
    OID_SENDER_NONCE: ("scep_sender_nonce", _SetOfOctetString),
    OID_RECIPIENT_NONCE: ("scep_recipient_nonce", _SetOfOctetString),
    OID_TRANSACTION_ID: ("scep_transaction_id", _SetOfPrintableString),
}

for _oid, (_name, _spec) in _SCEP_ATTRIBUTES.items():
    cms.CMSAttributeType._map[_oid] = _name
    cms.CMSAttribute._oid_specs[_name] = _spec


class ScepError(Exception):
    """A SCEP request we can read but won't act on. Carries the failInfo code
    to return, because a device given a bare error learns nothing."""

    def __init__(self, message: str, fail_info: str = FAIL_INFO_BAD_REQUEST) -> None:
        super().__init__(message)
        self.fail_info = fail_info


@dataclass
class ScepRequest:
    message_type: str
    transaction_id: str
    sender_nonce: bytes
    csr_der: bytes
    signer_cert: x509.Certificate
    challenge_password: Optional[str]


def _attr_value(signed_attrs, oid: str) -> Optional[bytes]:
    for attr in signed_attrs:
        if attr["type"].dotted == oid:
            return attr["values"][0].native
    return None


def _printable(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("ascii", errors="replace")
    return str(value)


def _extract_challenge_password(csr: x509.CertificateSigningRequest) -> Optional[str]:
    """SCEP authenticates with a challengePassword attribute inside the CSR
    itself — there is nowhere else to put it, since the request arrives as one
    encrypted blob rather than an authenticated HTTP call.

    Read by iterating csr.attributes rather than via get_attribute_for_oid,
    which isn't present on every `cryptography` version this runs against. The
    exception handling here is deliberately narrow: an earlier broad
    `except Exception` swallowed an AttributeError and made every request look
    like it carried no password, which would have failed authentication for
    reasons nothing could diagnose.
    """
    for attribute in csr.attributes:
        if attribute.oid == _CHALLENGE_PASSWORD_OID:
            value = attribute.value
            return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
    return None


def parse_pki_message(der: bytes, ca_cert: x509.Certificate, ca_key) -> ScepRequest:
    """Unwrap a device's SCEP request: verify the outer signature, decrypt the
    envelope with the CA key, and pull out the PKCS#10 inside."""
    try:
        info = cms.ContentInfo.load(der)
        signed_data = info["content"]
    except Exception as e:
        raise ScepError(f"Not a readable PKCS#7 message: {e}")

    if info["content_type"].native != "signed_data":
        raise ScepError("SCEP request must be PKCS#7 SignedData")

    signer_infos = signed_data["signer_infos"]
    if len(signer_infos) != 1:
        raise ScepError("SCEP request must carry exactly one signer")
    signer_info = signer_infos[0]
    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs is core.VOID:
        raise ScepError("SCEP request carries no signed attributes")

    message_type = _printable(_attr_value(signed_attrs, OID_MESSAGE_TYPE))
    transaction_id = _printable(_attr_value(signed_attrs, OID_TRANSACTION_ID))
    sender_nonce = _attr_value(signed_attrs, OID_SENDER_NONCE)
    if not message_type or not transaction_id:
        raise ScepError("SCEP request is missing messageType or transactionID")

    certs = signed_data["certificates"]
    if certs is core.VOID or len(certs) == 0:
        raise ScepError("SCEP request carries no signer certificate")
    signer_cert = x509.load_der_x509_certificate(certs[0].chosen.dump())

    # The device signs with a self-signed certificate it just made, so this
    # proves only that whoever sent the request holds that key — which is all
    # it can prove before enrolment. Authorisation comes from the challenge
    # password inside the CSR.
    _verify_signature(signer_info, signed_attrs, signer_cert)

    encap = signed_data["encap_content_info"]["content"].native
    if not encap:
        raise ScepError("SCEP request has no enveloped content")

    try:
        csr_der = _decrypt_envelope(encap, ca_cert, ca_key)
    except ScepError:
        raise
    except Exception as e:
        raise ScepError(f"Could not decrypt the enveloped request: {e}")

    try:
        csr = x509.load_der_x509_csr(csr_der)
    except Exception as e:
        raise ScepError(f"Enveloped content is not a valid PKCS#10 request: {e}")

    return ScepRequest(
        message_type=message_type,
        transaction_id=transaction_id,
        sender_nonce=sender_nonce or b"",
        csr_der=csr_der,
        signer_cert=signer_cert,
        challenge_password=_extract_challenge_password(csr),
    )


def _decrypt_envelope(envelope_der: bytes, ca_cert: x509.Certificate, ca_key) -> bytes:
    """Decrypt the EnvelopedData holding the CSR.

    Uses cryptography's CMS decryption, which handles the content-encryption
    key unwrap and the symmetric decryption. NoAttributes/Text options are
    irrelevant here — the content is raw DER, not S/MIME text.
    """
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    ca_key_pem = ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    loaded_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    loaded_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    return pkcs7.pkcs7_decrypt_der(envelope_der, loaded_cert, loaded_key, options=[])


def _verify_signature(signer_info, signed_attrs, signer_cert: x509.Certificate) -> None:
    """Check the device's signature over its own signed attributes."""
    digest_alg = signer_info["digest_algorithm"]["algorithm"].native
    hash_map = {
        "md5": hashes.MD5(), "sha1": hashes.SHA1(), "sha224": hashes.SHA224(),
        "sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512(),
    }
    algorithm = hash_map.get(digest_alg)
    if algorithm is None:
        raise ScepError(f"Unsupported digest algorithm: {digest_alg}")

    # Signed attributes are signed in their SET OF form, not the tagged form
    # they appear in inside signerInfo.
    to_verify = signed_attrs.untag().dump()
    signature = signer_info["signature"].native
    public_key = signer_cert.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, to_verify, padding.PKCS1v15(), algorithm)
        else:
            from cryptography.hazmat.primitives.asymmetric import ec
            public_key.verify(signature, to_verify, ec.ECDSA(algorithm))
    except Exception:
        raise ScepError(
            "The signature on this SCEP request does not verify", FAIL_INFO_BAD_IDENTITY
        )


def _attribute(oid_or_name: str, value) -> cms.CMSAttribute:
    """Build one CMS attribute. asn1crypto picks the value's type from the
    registered OID, so `value` is an ordinary Python value."""
    return cms.CMSAttribute({"type": oid_or_name, "values": [value]})


def build_cert_rep(
    request: ScepRequest,
    issued_cert: Optional[x509.Certificate],
    ca_cert: x509.Certificate,
    ca_key,
    chain: Optional[list] = None,
    failure: Optional[str] = None,
) -> bytes:
    """Build the CertRep answering a request.

    On success the issued certificate goes back inside a degenerate PKCS#7,
    encrypted to the certificate the device signed with — the only key we know
    it holds — then wrapped in SignedData carrying the SCEP attributes.

    On failure the SignedData is returned with pkiStatus FAILURE and a
    failInfo, and no enveloped content: there is nothing to encrypt, and a
    device needs to be told *why* rather than left to time out.
    """
    signed_attrs = [
        _attribute("content_type", "data"),
        _attribute(OID_MESSAGE_TYPE, MESSAGE_TYPE_CERT_REP),
        _attribute(OID_TRANSACTION_ID, request.transaction_id),
        _attribute(OID_RECIPIENT_NONCE, request.sender_nonce),
        _attribute(OID_SENDER_NONCE, os.urandom(16)),
    ]

    if failure is not None:
        signed_attrs.append(_attribute(OID_PKI_STATUS, PKI_STATUS_FAILURE))
        signed_attrs.append(_attribute(OID_FAIL_INFO, failure))
        content = b""
    else:
        signed_attrs.append(_attribute(OID_PKI_STATUS, PKI_STATUS_SUCCESS))
        bundle = [issued_cert] + list(chain or [])
        degenerate = pkcs7.serialize_certificates(bundle, serialization.Encoding.DER)
        content = _encrypt_for(degenerate, request.signer_cert)

    return _sign_scep_response(content, signed_attrs, ca_cert, ca_key)


def _encrypt_for(data: bytes, recipient: x509.Certificate) -> bytes:
    """Envelope the response to the certificate the device signed with.

    PKCS7Options.Binary is not optional here. Without it the library applies
    S/MIME canonicalisation, turning every 0x0A byte in the DER into 0x0D 0x0A
    — silently corrupting the certificate bundle by a variable number of bytes,
    so the device receives something that isn't valid DER and fails with no
    useful diagnostic. SCEP carries binary, not text.
    """
    builder = (
        pkcs7.PKCS7EnvelopeBuilder()
        .set_data(data)
        .add_recipient(recipient)
    )
    return builder.encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])


def _sign_scep_response(content: bytes, signed_attrs: list, ca_cert: x509.Certificate, ca_key) -> bytes:
    """Assemble SignedData by hand, because the SCEP attributes have to go in
    the signature and no high-level builder will put them there."""
    digest = hashlib.sha256(content).digest()
    attrs = list(signed_attrs)
    attrs.append(_attribute("message_digest", digest))
    attrs.append(_attribute("signing_time", cms.Time({"utc_time": datetime.now(timezone.utc)})))

    signed_attr_set = cms.CMSAttributes(attrs)
    to_sign = signed_attr_set.dump()

    if isinstance(ca_key, rsa.RSAPrivateKey):
        signature = ca_key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())
        signature_algorithm = {"algorithm": "rsassa_pkcs1v15"}
    else:
        from cryptography.hazmat.primitives.asymmetric import ec
        signature = ca_key.sign(to_sign, ec.ECDSA(hashes.SHA256()))
        signature_algorithm = {"algorithm": "sha256_ecdsa"}

    ca_asn1 = asn1_x509.Certificate.load(ca_cert.public_bytes(serialization.Encoding.DER))

    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": ca_asn1["tbs_certificate"]["issuer"],
                "serial_number": ca_asn1["tbs_certificate"]["serial_number"],
            })
        }),
        "digest_algorithm": {"algorithm": "sha256"},
        "signed_attrs": signed_attr_set,
        "signature_algorithm": signature_algorithm,
        "signature": signature,
    })

    signed_data = cms.SignedData({
        "version": "v1",
        "digest_algorithms": [{"algorithm": "sha256"}],
        "encap_content_info": {"content_type": "data", "content": content},
        "certificates": [ca_asn1],
        "signer_infos": [signer_info],
    })

    return cms.ContentInfo({
        "content_type": "signed_data",
        "content": signed_data,
    }).dump()
