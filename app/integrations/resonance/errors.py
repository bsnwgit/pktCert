"""
Typed errors for the resonance embed client.

Resonance answers every failure as {"error": "<human sentence>"} with no
machine-readable code field, so the status code is the only thing worth
branching on. These classes do that branching once, and each carries the
sentence an admin should see — the difference between "it doesn't work" and
"you have pointed this at the admin port" is most of the support burden.

`config_error` marks failures that retrying cannot fix. The client opens its
breaker fast on those, because resonance applies a geometric per-IP backoff to
repeated bad-key attempts and a pkt app is a single IP: continuing to knock
would take the widget down for every user at once.
"""
from __future__ import annotations


class ResonanceError(Exception):
    """Base for every resonance failure. `admin_message` is user-facing."""

    status: int | None = None
    config_error: bool = False
    admin_message: str = "Resonance request failed."

    def __init__(self, detail: str = "", *, admin_message: str | None = None):
        self.detail = detail
        if admin_message:
            self.admin_message = admin_message
        super().__init__(self.admin_message if not detail else f"{self.admin_message} ({detail})")


class ResonanceNotConfigured(ResonanceError):
    config_error = True
    admin_message = "Resonance is not configured — set the server address and key."


class ResonanceBadRequest(ResonanceError):
    """400 — includes the case where the key names people and no user id was sent."""

    status = 400
    config_error = True
    admin_message = "Resonance rejected the request — this key expects a named person."


class ResonanceUnauthorized(ResonanceError):
    """401 — resonance answers the same way for a bad id and a bad secret, on purpose."""

    status = 401
    config_error = True
    admin_message = "Key not recognised — check for a truncated or mistyped paste."


class ResonanceKeyDisabled(ResonanceError):
    status = 403
    config_error = True
    admin_message = "This key is disabled in resonance."


class ResonanceWrongPort(ResonanceError):
    """404 — the single most common misconfiguration, and the least obvious."""

    status = 404
    config_error = True
    admin_message = (
        "That address is the resonance admin port. Use the embed server address instead."
    )


class ResonanceBackoff(ResonanceError):
    """429 — resonance is rate-limiting this source IP after failed key attempts."""

    status = 429
    config_error = True
    admin_message = (
        "Resonance is refusing attempts from this server after earlier failures. "
        "Fix the key, then wait for the backoff to clear."
    )


class ResonanceUnreachable(ResonanceError):
    """Network-level failure — transient until proven otherwise."""

    admin_message = "Could not reach the resonance server."


class ResonanceBreakerOpen(ResonanceError):
    """Raised locally, without calling out, while the breaker is open."""

    admin_message = "Paused after repeated failures."


class ResonanceRateLimited(ResonanceError):
    """Raised locally by our own limiter, not by resonance."""

    status = 429
    admin_message = "Too many session requests — slow down."


_BY_STATUS: dict[int, type[ResonanceError]] = {
    400: ResonanceBadRequest,
    401: ResonanceUnauthorized,
    403: ResonanceKeyDisabled,
    404: ResonanceWrongPort,
    429: ResonanceBackoff,
}


def for_status(status: int, detail: str = "") -> ResonanceError:
    """Map an HTTP status from /embed/session onto a typed error."""
    cls = _BY_STATUS.get(status)
    if cls is not None:
        return cls(detail)
    return ResonanceError(
        detail, admin_message=f"Resonance returned an unexpected status ({status})."
    )
