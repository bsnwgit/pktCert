"""
app/cert/alert_conditions.py
-----------------------------
What a certificate alert rule can watch for, and the parameters each condition
takes.

Every condition declares its own parameters here, and both the evaluator and
the UI read that declaration — the Alerts page renders parameter fields from
CONDITIONS rather than hardcoding them, so adding a condition needs no frontend
change at all.

Two things every condition gets for free:

  * **parameters** — what "too short", "too long" or "too soon" means for this
    installation, instead of a number baked into the code.
  * **scope** — which certificates it applies to. Narrow rules are the useful
    ones: "short keys on certificates we issued" is actionable, while "every
    short key anywhere in the discovery inventory" is noise on day one and
    ignored by day three.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import aiosqlite


@dataclass
class Param:
    key: str
    label: str
    type: str                       # int | string | multiselect
    default: Any
    hint: str = ""
    options: list[str] = field(default_factory=list)
    min: Optional[int] = None
    max: Optional[int] = None

    def as_dict(self) -> dict:
        return {
            "key": self.key, "label": self.label, "type": self.type,
            "default": self.default, "hint": self.hint,
            "options": self.options, "min": self.min, "max": self.max,
        }


@dataclass
class Condition:
    key: str
    label: str
    description: str
    target: str                     # certificate | ca | scan_target | system
    params: list[Param] = field(default_factory=list)
    scoped: bool = True             # does the certificate scope filter apply?

    def as_dict(self) -> dict:
        return {
            "key": self.key, "label": self.label, "description": self.description,
            "target": self.target, "scoped": self.scoped,
            "params": [p.as_dict() for p in self.params],
        }


# ── Scope ───────────────────────────────────────────────────────────────────

def scope_clause(scope: dict) -> tuple[str, list]:
    """Turn a rule's scope into a SQL fragment over the certificates table.

    Everything is optional; an empty scope means "every certificate", which is
    the old behaviour and still the default.
    """
    clauses, params = [], []
    if scope.get("ca_id"):
        clauses.append("c.ca_id = ?")
        params.append(int(scope["ca_id"]))
    if scope.get("source"):
        clauses.append("c.source = ?")
        params.append(str(scope["source"]))
    if scope.get("name_like"):
        clauses.append("c.common_name LIKE ?")
        params.append(f"%{scope['name_like']}%")
    if scope.get("host_like"):
        clauses.append("c.host LIKE ?")
        params.append(f"%{scope['host_like']}%")
    return (" AND " + " AND ".join(clauses) if clauses else ""), params


# Certificates that are dead or already replaced shouldn't raise anything: a
# revoked certificate's problems are moot, and a superseded one's replacement
# already exists. Every certificate condition starts from this.
_LIVE = "c.status NOT IN ('revoked', 'superseded')"


def _params(rule) -> dict:
    try:
        return json.loads(rule["params_json"] or "{}")
    except (TypeError, ValueError, IndexError, KeyError):
        return {}


def _scope(rule) -> dict:
    try:
        return json.loads(rule["scope_json"] or "{}")
    except (TypeError, ValueError, IndexError, KeyError):
        return {}


def param_int(rule, key: str, default: int) -> int:
    """A parameter, falling back to the rule's legacy `threshold` column and
    then to the condition's own default. Rules written before parameters
    existed keep working with no migration and no change of meaning."""
    value = _params(rule).get(key)
    if value is None and rule["threshold"] is not None:
        value = rule["threshold"]
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def param_list(rule, key: str, default: list[str]) -> list[str]:
    value = _params(rule).get(key)
    if isinstance(value, list) and value:
        return [str(v).lower() for v in value]
    return default


# ── Certificate conditions ──────────────────────────────────────────────────
#
# Each returns rows of (id, common_name, message). The engine turns those into
# alert events; conditions never write.

async def _query(db: aiosqlite.Connection, rule, where: str, extra_params: list | None = None):
    scope_sql, scope_params = scope_clause(_scope(rule))
    sql = (
        "SELECT c.id, c.common_name, c.host, c.not_after, c.key_algorithm, c.key_size, "
        "c.signature_algorithm, c.issuer, c.subject, c.san_json, c.first_seen_at, c.source "
        f"FROM certificates c WHERE {_LIVE} AND ({where}){scope_sql}"
    )
    async with db.execute(sql, [*(extra_params or []), *scope_params]) as cur:
        return await cur.fetchall()


async def cert_expiring(db, rule):
    days = param_int(rule, "days", 30)
    rows = await _query(
        db, rule,
        "c.not_after IS NOT NULL AND c.not_after < datetime('now', ?) AND c.not_after >= datetime('now')",
        [f"+{days} days"],
    )
    return [(r["id"], f"Certificate '{r['common_name']}' expires {r['not_after']}") for r in rows]


async def cert_expired(db, rule):
    rows = await _query(db, rule, "c.not_after IS NOT NULL AND c.not_after < datetime('now')")
    return [(r["id"], f"Certificate '{r['common_name']}' expired {r['not_after']}") for r in rows]


async def cert_revoked(db, rule):
    # The one condition that deliberately looks at revoked certificates.
    scope_sql, scope_params = scope_clause(_scope(rule))
    async with db.execute(
        "SELECT c.id, c.common_name, c.revoked_reason_code FROM certificates c "
        f"WHERE c.status = 'revoked'{scope_sql}", scope_params,
    ) as cur:
        rows = await cur.fetchall()
    return [
        (r["id"], f"Certificate '{r['common_name']}' was revoked"
                  + (f" ({r['revoked_reason_code']})" if r["revoked_reason_code"] else ""))
        for r in rows
    ]


async def weak_key(db, rule):
    """A key too short to be worth the certificate wrapped around it. RSA and
    EC are judged separately because their bit counts aren't comparable — 256
    EC bits is strong, 256 RSA bits is a toy."""
    min_rsa = param_int(rule, "min_rsa_bits", 2048)
    min_ec = param_int(rule, "min_ec_bits", 256)
    rows = await _query(
        db, rule,
        "(c.key_algorithm = 'rsa' AND c.key_size < ?) OR (c.key_algorithm = 'ec' AND c.key_size < ?)",
        [min_rsa, min_ec],
    )
    return [
        (r["id"], f"Certificate '{r['common_name']}' uses a {r['key_size']}-bit "
                  f"{(r['key_algorithm'] or '').upper()} key")
        for r in rows
    ]


async def weak_signature(db, rule):
    forbidden = param_list(rule, "forbidden", ["md5", "sha1"])
    placeholders = ",".join("?" for _ in forbidden)
    rows = await _query(
        db, rule, f"lower(c.signature_algorithm) IN ({placeholders})", list(forbidden)
    )
    return [
        (r["id"], f"Certificate '{r['common_name']}' is signed with {r['signature_algorithm']}")
        for r in rows
    ]


async def self_signed(db, rule):
    rows = await _query(db, rule, "c.issuer != '' AND c.issuer = c.subject")
    return [(r["id"], f"Certificate '{r['common_name']}' is self-signed") for r in rows]


async def long_validity(db, rule):
    """Validity longer than policy allows. The public-CA ceiling is 398 days;
    a certificate valid for years is one you cannot rotate out of trouble
    quickly."""
    max_days = param_int(rule, "max_days", 398)
    rows = await _query(
        db, rule,
        "c.not_before IS NOT NULL AND c.not_after IS NOT NULL "
        "AND julianday(c.not_after) - julianday(c.not_before) > ?",
        [max_days],
    )
    return [
        (r["id"], f"Certificate '{r['common_name']}' is valid for more than {max_days} days")
        for r in rows
    ]


async def wildcard_certificate(db, rule):
    rows = await _query(db, rule, "c.common_name LIKE '*%' OR c.san_json LIKE '%\"*.%'")
    return [(r["id"], f"Certificate '{r['common_name']}' is a wildcard certificate") for r in rows]


async def untrusted_issuer(db, rule):
    """Discovered certificates issued by something that isn't one of our own
    CAs — the ones nobody here can renew, revoke, or account for."""
    async with db.execute("SELECT subject FROM certificate_authorities") as cur:
        our_subjects = {r["subject"] for r in await cur.fetchall() if r["subject"]}

    rows = await _query(db, rule, "c.source IN ('scan', 'ct') AND c.issuer != ''")
    out = []
    for r in rows:
        if r["issuer"] not in our_subjects:
            out.append((r["id"], f"Certificate '{r['common_name']}' was issued by '{r['issuer']}', "
                                 f"which is not one of your CAs"))
    return out


async def newly_discovered(db, rule):
    hours = param_int(rule, "within_hours", 24)
    rows = await _query(
        db, rule,
        "c.source IN ('scan', 'ct') AND c.first_seen_at >= datetime('now', ?)",
        [f"-{hours} hours"],
    )
    return [
        (r["id"], f"New certificate discovered: '{r['common_name']}'"
                  + (f" on {r['host']}" if r["host"] else ""))
        for r in rows
    ]


async def host_certificate_changed(db, rule):
    """More than one live certificate seen on the same host:port inside the
    window — the certificate on that host was replaced. Usually a routine
    rotation; occasionally the first sign that something replaced it for you."""
    hours = param_int(rule, "within_hours", 24)
    scope_sql, scope_params = scope_clause(_scope(rule))
    async with db.execute(
        "SELECT c.id, c.common_name, c.host, c.port FROM certificates c "
        f"WHERE {_LIVE} AND c.host IS NOT NULL AND c.last_seen_at >= datetime('now', ?)"
        f"{scope_sql} ORDER BY c.host, c.port, c.first_seen_at DESC",
        [f"-{hours} hours", *scope_params],
    ) as cur:
        rows = await cur.fetchall()

    by_endpoint: dict[tuple, list] = {}
    for r in rows:
        by_endpoint.setdefault((r["host"], r["port"]), []).append(r)
    out = []
    for (host, port), certs in by_endpoint.items():
        if len(certs) > 1:
            newest = certs[0]
            out.append((newest["id"],
                        f"{len(certs)} different certificates seen on {host}:{port} in the last "
                        f"{hours}h — the certificate there changed"))
    return out


# ── Non-certificate conditions ──────────────────────────────────────────────

async def ca_expiring(db, rule):
    days = param_int(rule, "days", 90)
    async with db.execute(
        "SELECT id, name, not_after FROM certificate_authorities "
        "WHERE status = 'active' AND not_after != '' AND not_after < datetime('now', ?) "
        "AND not_after >= datetime('now')",
        (f"+{days} days",),
    ) as cur:
        rows = await cur.fetchall()
    return [(r["id"], f"CA '{r['name']}' expires {r['not_after']}") for r in rows]


async def crl_stale(db, rule):
    """A CRL that has lapsed, or is about to. When one expires before its
    replacement is published, relying parties stop being able to check
    revocation at all — for every certificate that CA ever issued."""
    days = param_int(rule, "days", 2)
    async with db.execute(
        """SELECT ca.id, ca.name, p.next_update
           FROM certificate_authorities ca
           LEFT JOIN crl_publications p ON p.ca_id = ca.id
           WHERE ca.status = 'active'"""
    ) as cur:
        rows = await cur.fetchall()

    out = []
    for r in rows:
        if not r["next_update"]:
            # Never published. Only worth flagging for a CA that has actually
            # revoked something — otherwise every new CA alerts on day one.
            async with db.execute(
                "SELECT COUNT(*) FROM certificates WHERE ca_id = ? AND status = 'revoked'", (r["id"],)
            ) as c2:
                revoked = (await c2.fetchone())[0]
            if revoked:
                out.append((r["id"], f"CA '{r['name']}' has {revoked} revoked certificate(s) but has "
                                     f"never published a CRL"))
            continue
        async with db.execute("SELECT datetime('now', ?) < ?", (f"+{days} days", r["next_update"])) as c2:
            still_fresh = (await c2.fetchone())[0]
        if not still_fresh:
            out.append((r["id"], f"CA '{r['name']}' CRL expires {r['next_update']}"))
    return out


async def scan_target_unreachable(db, rule):
    async with db.execute(
        "SELECT id, name, last_error FROM scan_targets WHERE enabled = 1 AND last_status = 'error'"
    ) as cur:
        rows = await cur.fetchall()
    return [(None, f"Scan target '{r['name']}' unreachable: {r['last_error'] or 'unknown error'}") for r in rows]


async def enrollment_failures(db, rule):
    """Repeated refused enrolments — a misconfigured device, or something
    working through guesses at an enrolment secret."""
    count = param_int(rule, "count", 5)
    window = param_int(rule, "window_minutes", 60)
    async with db.execute(
        """SELECT client_ip, COUNT(*) AS n FROM enrollment_log
           WHERE outcome = 'denied' AND created_at >= datetime('now', ?)
           GROUP BY client_ip HAVING n >= ?""",
        (f"-{window} minutes", count),
    ) as cur:
        rows = await cur.fetchall()
    return [
        (None, f"{r['n']} refused enrolment attempts from {r['client_ip']} in the last {window} minutes")
        for r in rows
    ]


# ── Registry ────────────────────────────────────────────────────────────────

CONDITIONS: dict[str, Condition] = {
    c.key: c for c in [
        Condition("cert_expiring", "Certificate expiring", "A certificate is approaching its expiry date.",
                  "certificate", [Param("days", "Warn this many days before expiry", "int", 30, min=1, max=3650)]),
        Condition("cert_expired", "Certificate expired", "A certificate's expiry date has passed.", "certificate"),
        Condition("cert_revoked", "Certificate revoked", "A certificate was revoked. Fires once; revocation is terminal.",
                  "certificate"),
        Condition("weak_key", "Weak key", "A key shorter than your policy allows.", "certificate", [
            Param("min_rsa_bits", "Minimum RSA key size", "int", 2048, "Anything shorter alerts.", min=512, max=16384),
            Param("min_ec_bits", "Minimum EC key size", "int", 256, "EC and RSA bit counts are not comparable.", min=128, max=1024),
        ]),
        Condition("weak_signature", "Weak signature algorithm", "A certificate signed with a broken hash.",
                  "certificate", [
                      Param("forbidden", "Signature algorithms to flag", "multiselect", ["md5", "sha1"],
                            options=["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]),
                  ]),
        Condition("self_signed", "Self-signed certificate", "Issuer and subject are the same — no CA vouches for it.",
                  "certificate"),
        Condition("long_validity", "Validity too long", "A certificate valid for longer than policy allows.",
                  "certificate", [
                      Param("max_days", "Maximum validity in days", "int", 398,
                            "398 days is the public-CA ceiling.", min=1, max=7300),
                  ]),
        Condition("wildcard_certificate", "Wildcard certificate", "A certificate covering *.something.",
                  "certificate"),
        Condition("untrusted_issuer", "Issuer not one of yours",
                  "A discovered certificate issued by a CA you don't control — nobody here can renew or revoke it.",
                  "certificate"),
        Condition("newly_discovered", "Newly discovered certificate",
                  "A certificate discovery has just found for the first time.", "certificate", [
                      Param("within_hours", "Discovered within the last (hours)", "int", 24, min=1, max=8760),
                  ]),
        Condition("host_certificate_changed", "Certificate changed on a host",
                  "More than one certificate seen on the same host and port — it was replaced.", "certificate", [
                      Param("within_hours", "Look back (hours)", "int", 24, min=1, max=8760),
                  ]),
        Condition("ca_expiring", "CA expiring", "A certificate authority is approaching expiry.", "ca", [
            Param("days", "Warn this many days before expiry", "int", 90,
                  "CAs need far more lead time than leaf certificates.", min=1, max=3650),
        ], scoped=False),
        Condition("crl_stale", "CRL stale or unpublished",
                  "A CA's CRL has lapsed or is about to, so revocation checking stops working.", "ca", [
                      Param("days", "Warn this many days before the CRL expires", "int", 2, min=1, max=365),
                  ], scoped=False),
        Condition("scan_target_unreachable", "Scan target unreachable",
                  "A discovery target failed its last scan.", "scan_target", scoped=False),
        Condition("enrollment_failures", "Repeated enrolment failures",
                  "Refused device enrolments from one address — a misconfigured device, or guessing at a secret.",
                  "system", [
                      Param("count", "Failures before alerting", "int", 5, min=1, max=1000),
                      Param("window_minutes", "Within (minutes)", "int", 60, min=1, max=10080),
                  ], scoped=False),
    ]
}

# key -> (evaluator, whether the returned id is a certificate id or a CA id)
EVALUATORS: dict[str, tuple[Callable, str]] = {
    "cert_expiring": (cert_expiring, "certificate"),
    "cert_expired": (cert_expired, "certificate"),
    "cert_revoked": (cert_revoked, "certificate"),
    "weak_key": (weak_key, "certificate"),
    "weak_signature": (weak_signature, "certificate"),
    "self_signed": (self_signed, "certificate"),
    "long_validity": (long_validity, "certificate"),
    "wildcard_certificate": (wildcard_certificate, "certificate"),
    "untrusted_issuer": (untrusted_issuer, "certificate"),
    "newly_discovered": (newly_discovered, "certificate"),
    "host_certificate_changed": (host_certificate_changed, "certificate"),
    "ca_expiring": (ca_expiring, "ca"),
    "crl_stale": (crl_stale, "ca"),
    "scan_target_unreachable": (scan_target_unreachable, "none"),
    "enrollment_failures": (enrollment_failures, "none"),
}

# Conditions that describe a state which cannot improve, so an open alert must
# not auto-resolve just because the query stops matching.
TERMINAL = {"cert_revoked"}
