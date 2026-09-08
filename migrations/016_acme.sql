-- 016 — ACME (RFC 8555) enrolment.
--
-- EST and SCEP cover network gear. Nothing on a Linux host or in a cluster
-- speaks either: Caddy, Traefik, cert-manager, certbot and acme.sh all speak
-- ACME, and they speak it unattended. Adding it is what lets the internal CA
-- serve the servers rather than only the switches.
--
-- Issuance itself is unchanged — an ACME order ends in the same
-- enrollment.issue_from_csr() call as an EST enrolment, under the same
-- profile, CA and template. Everything here is the protocol's own state: the
-- account that asked, the order it placed, and the challenges it answered.

-- ── Accounts ────────────────────────────────────────────────────────────────
-- An account is a public key, bound at registration to an enrolment profile
-- through External Account Binding (RFC 8555 §7.3.4). The binding is what
-- keeps this from being an open CA: without it, anything that can reach the
-- endpoint mints a certificate for any internal name it likes.
CREATE TABLE IF NOT EXISTS acme_accounts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id      INTEGER NOT NULL REFERENCES enrollment_profiles(id) ON DELETE CASCADE,
    -- RFC 7638 thumbprint of the account key. The natural identity for an
    -- account: clients rotate contacts freely but the key is what signs.
    jwk_thumbprint  TEXT NOT NULL UNIQUE,
    jwk_json        TEXT NOT NULL,
    contact_json    TEXT NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'valid',   -- valid | deactivated | revoked
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_acme_accounts_profile ON acme_accounts(profile_id);

-- ── Orders ──────────────────────────────────────────────────────────────────
-- replaces_cert_id carries ARI's `replaces` field where the client sends one.
-- Without it a renewal is indistinguishable from a first issuance, and the
-- inventory fills with unlinked generations of the same name — four a year at
-- 90-day validity — while the certificate each one replaced goes on raising
-- expiry alerts nobody can act on.
CREATE TABLE IF NOT EXISTS acme_orders (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id       INTEGER NOT NULL REFERENCES acme_accounts(id) ON DELETE CASCADE,
    status           TEXT NOT NULL DEFAULT 'pending',  -- pending | ready | processing | valid | invalid
    identifiers_json TEXT NOT NULL DEFAULT '[]',
    csr_pem          TEXT,
    certificate_id   INTEGER REFERENCES certificates(id) ON DELETE SET NULL,
    replaces_cert_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL,
    error_json       TEXT,
    expires_at       TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_acme_orders_account ON acme_orders(account_id);

-- ── Authorizations and challenges ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS acme_authorizations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id    INTEGER NOT NULL REFERENCES acme_orders(id) ON DELETE CASCADE,
    identifier  TEXT NOT NULL,
    wildcard    INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'pending',      -- pending | valid | invalid
    expires_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_acme_authz_order ON acme_authorizations(order_id);

CREATE TABLE IF NOT EXISTS acme_challenges (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    authz_id     INTEGER NOT NULL REFERENCES acme_authorizations(id) ON DELETE CASCADE,
    type         TEXT NOT NULL,                       -- http-01 | dns-01
    token        TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',     -- pending | processing | valid | invalid
    error_json   TEXT,
    validated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_acme_challenges_authz ON acme_challenges(authz_id);

-- ── Nonces ──────────────────────────────────────────────────────────────────
-- Anti-replay. Issued once, consumed once. Kept in the database rather than in
-- memory so a restart mid-order doesn't invalidate every outstanding nonce —
-- clients recover from badNonce, but there is no reason to make them.
CREATE TABLE IF NOT EXISTS acme_nonces (
    nonce      TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_acme_nonces_expiry ON acme_nonces(expires_at);

-- ── Profile columns ─────────────────────────────────────────────────────────
-- A wildcard sits inside a suffix constraint legitimately — '*.example.com' is
-- within 'example.com' and is not an escape — but it is one certificate
-- covering every name in the namespace, and under ACME any client holding the
-- profile secret can simply ask for it. Under EST that stayed theoretical,
-- because a device enrols for the name in its own config; in a Caddyfile it is
-- one line. Off by default, and only consulted for ACME.
ALTER TABLE enrollment_profiles ADD COLUMN allow_wildcard INTEGER NOT NULL DEFAULT 0;

-- max_certs is a lifetime counter, which is the right shape for EST — a fleet
-- of 40 switches enrols 40 times, ever. Forty ACME hosts at 90-day validity
-- consume 160 slots a year, so the same number sized on EST intuition strands
-- a fleet mid-renewal with nobody awake to raise it. ACME profiles are bounded
-- by a rate instead: orders per rolling hour, 0 meaning unlimited.
ALTER TABLE enrollment_profiles ADD COLUMN max_orders_per_hour INTEGER NOT NULL DEFAULT 0;

-- Which ACME order produced a certificate, where one did.
ALTER TABLE certificates ADD COLUMN acme_order_id INTEGER REFERENCES acme_orders(id) ON DELETE SET NULL;
