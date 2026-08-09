"""
Fernet-based encryption for secrets at rest: CA private keys
(certificate_authorities.private_key_enc), issued-certificate private keys
generated server-side (certificates.private_key_enc), and per-user external
API keys (user_api_keys.api_key).

credential_key is generated once by install.sh (Fernet.generate_key()) and
written to config.yaml, the same way secret_key is handled for JWT signing.
CA private keys are never returned by any API response — only decrypted
in-process for signing operations.
"""
from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings


def _fernet() -> Fernet:
    settings = get_settings()
    key = settings.credential_key
    if not key:
        raise RuntimeError(
            "credential_key is not configured — set it in config.yaml "
            "(generate with: python3 -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\")"
        )
    return Fernet(key.encode())


def encrypt_str(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt_str(token: str | None) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        return ""
