"""
app/cert/dns/
--------------
DNS providers for dns-01 validation, registered by name.

Adding a provider is a module in this package and one line in _PROVIDERS.
Nothing above this layer knows which one is in use — the ACME client asks for
a provider by the name stored on the request and gets something that can
publish a TXT record.

The registry is deliberately the same shape as the notification channels in
app/notifications.py: a dict lookup returning None for an unknown name, so a
stored provider that no longer exists surfaces as a clear message rather than
an import error at startup.
"""
from __future__ import annotations

from typing import Optional

from app.cert.dns.base import (  # noqa: F401  — re-exported as this package's API
    ChallengeRecord,
    DnsError,
    DnsProvider,
    challenge_name,
)
from app.cert.dns.cloudflare import CloudflareProvider

_PROVIDERS: dict[str, type[DnsProvider]] = {
    CloudflareProvider.name: CloudflareProvider,
}


def get_provider(name: str, credential: str) -> DnsProvider:
    """Build a provider by registry name, or raise DnsError naming what exists."""
    cls = _PROVIDERS.get((name or "").strip().lower())
    if cls is None:
        raise DnsError(
            f"unknown DNS provider '{name}' — this build supports: "
            f"{', '.join(sorted(_PROVIDERS)) or 'none'}"
        )
    return cls(credential)


def describe_providers() -> list[dict]:
    """What the UI offers in the provider dropdown, so the list cannot drift
    from what the code can actually construct."""
    return [
        {
            "name": cls.name,
            "label": cls.label,
            "credential_help": cls.credential_help,
            "automatic": cls.automatic,
        }
        for cls in sorted(_PROVIDERS.values(), key=lambda c: c.label)
    ]


def provider_names() -> list[str]:
    return sorted(_PROVIDERS)


def lookup(name: str) -> Optional[type[DnsProvider]]:
    return _PROVIDERS.get((name or "").strip().lower())
