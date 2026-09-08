"""
app/cert/dns/base.py
---------------------
What a DNS provider has to be able to do for dns-01, and the challenge-record
lifetime that every provider shares.

dns-01 is the only ACME challenge that works for the general case: http-01
needs the name reachable from the public internet on port 80, which internal
hosts are not, and it cannot produce a wildcard at all. dns-01 needs only
control of the zone.

Which means the zone credential is the interesting part, and it differs per
provider — an API token, an access key pair, a TSIG key, or a human. So the
provider is pluggable, registered by name in this package's __init__, in the
same shape as the notification channels in app/notifications.py. Adding one is
a new module and a registry entry; nothing above this layer changes.

A provider credential is a live credential for the whole zone — anything
holding it can repoint the domain. Implementations must never log it, and must
raise errors that do not quote the request that carried it.
"""
from __future__ import annotations

import asyncio
from typing import Optional


class DnsError(Exception):
    """A DNS operation failed. Shown to an operator, so it must describe the
    problem without ever containing the credential."""


class DnsProvider:
    """One zone-editing backend.

    Implementations are constructed with whatever credential their `settings`
    carry and are used for the lifetime of a single order.
    """

    #: Registry key, and what is stored in dns_providers.provider.
    name = ""
    #: Human-facing label for the provider dropdown.
    label = ""
    #: What the operator has to supply. Rendered as the credential field's help.
    credential_help = ""
    #: False for providers that cannot create records themselves and need a
    #: human to publish the value — those pause an order rather than driving it.
    automatic = True

    def __init__(self, credential: str) -> None:
        self.credential = credential

    async def create_txt(self, identifier: str, value: str) -> str:
        """Publish `value` at _acme-challenge.<identifier>. Returns an opaque
        handle used to remove it again."""
        raise NotImplementedError

    async def delete_txt(self, identifier: str, handle: str) -> None:
        """Remove a record created by create_txt. Must not raise — cleanup
        failing cannot be allowed to fail an order that otherwise succeeded,
        and a leftover TXT record is untidy rather than harmful."""
        raise NotImplementedError

    async def check(self) -> str:
        """Verify the credential works, for the 'Test' button. Returns a short
        description of what it can reach."""
        raise NotImplementedError


def challenge_name(identifier: str) -> str:
    """Where the TXT record goes. The wildcard prefix is stripped: a wildcard
    is proved at the base name, which is also why `*.x` and `x` in one order
    produce two authorizations answering at the same place."""
    return f"_acme-challenge.{identifier.lstrip('*.')}"


# How long to wait for a published record to become answerable, and how often
# to look. Telling the CA to validate before the record resolves spends a
# validation attempt, and those are rate-limited — Let's Encrypt counts
# failures as well as successes.
PROPAGATION_TIMEOUT = 120.0
PROPAGATION_INTERVAL = 5.0


async def await_propagation(resolver, record_name: str, expected: str,
                            timeout: float = PROPAGATION_TIMEOUT) -> None:
    """Block until `record_name` answers with `expected`, or raise.

    `resolver` is an async callable returning the TXT values currently visible
    for a name — passed in rather than imported so a provider can check against
    its own authoritative servers where it has them, and so tests can drive it
    without a network.
    """
    waited = 0.0
    while waited < timeout:
        if expected in await resolver(record_name):
            return
        await asyncio.sleep(PROPAGATION_INTERVAL)
        waited += PROPAGATION_INTERVAL
    raise DnsError(f"the TXT record at {record_name} did not become visible within {int(timeout)}s")


class ChallengeRecord:
    """One challenge record's lifetime, provider-independent.

    Created on enter, removed on exit whatever happened in between: an order
    that fails mid-flight must not leave a working challenge answer published
    in the zone.
    """

    def __init__(self, provider: DnsProvider, identifier: str, value: str) -> None:
        self._provider = provider
        self._identifier = identifier
        self._value = value
        self._handle: Optional[str] = None
        self.record_name = challenge_name(identifier)

    async def __aenter__(self) -> "ChallengeRecord":
        self._handle = await self._provider.create_txt(self._identifier, self._value)
        return self

    async def __aexit__(self, *_exc) -> None:
        if self._handle is not None:
            await self._provider.delete_txt(self._identifier, self._handle)
