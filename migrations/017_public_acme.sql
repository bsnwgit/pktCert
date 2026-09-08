-- 017 — public certificate acquisition (ACME client).
--
-- 016 made pktCert an ACME *server*, so internal hosts can enrol against the
-- internal CA. This is the opposite direction: pktCert as an ACME *client*,
-- obtaining certificates from a publicly-trusted CA — Let's Encrypt by
-- default — for names the organisation actually owns.
--
-- The two share a wire format and nothing else. Public trust comes from the
-- issuing CA being in browser and OS root stores, which an internal root can
-- never be, so a certificate that outside users trust natively has to come
-- from outside. This is the half that produces one.
--
-- Validation is dns-01 throughout. http-01 would require every name to be
-- reachable from the public internet on port 80, which internal hosts are not;
-- dns-01 only requires control of the zone, and it is also the only challenge
-- that can produce a wildcard.
--
-- Nothing here is specific to one CA or one DNS operator. The directory URL
-- decides which CA issues, and the provider key decides which DNS backend
-- proves the name — both are stored per row, because this ships to people
-- whose registrar, DNS host and choice of CA are all their own.

-- ── DNS providers ───────────────────────────────────────────────────────────
-- Credentials for writing the _acme-challenge TXT record.
--
-- `provider` is a registry key from app/cert/dns/, not a fixed set: which
-- backends exist is a property of the build, so there is no default and no
-- CHECK constraint here. A stored value naming a provider this build doesn't
-- have surfaces as a clear message from the registry rather than a schema
-- error, which is what allows a provider to be added or removed without a
-- migration.
--
-- The credential is a live, zone-wide secret — anything holding it can
-- repoint the domain. Fernet-encrypted at rest like every other secret
-- pktCert holds, and never returned by the API.
CREATE TABLE IF NOT EXISTS dns_providers (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT NOT NULL UNIQUE,
    provider       TEXT NOT NULL,
    credential_enc TEXT NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 1,
    last_used_at   TEXT,
    last_error     TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── The ACME account held with the public CA ────────────────────────────────
-- One per directory URL. The account key is generated here and never leaves;
-- losing it means losing the ability to revoke through the account, so it is
-- encrypted rather than regenerated per order.
--
-- directory_url is deliberately not a fixed constant: the same client speaks
-- to Let's Encrypt staging and production, and to ZeroSSL, Google and Buypass,
-- which differ only by URL and whether they demand external account binding.
CREATE TABLE IF NOT EXISTS public_acme_accounts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT NOT NULL UNIQUE,
    directory_url  TEXT NOT NULL,
    -- 'staging' | 'production'. Recorded rather than inferred from the URL so
    -- the UI can be loud about which one is in use — Let's Encrypt's
    -- production rate limits are unforgiving and a mistake here is measured in
    -- days of lockout, not minutes.
    environment    TEXT NOT NULL DEFAULT 'staging',
    account_key_enc TEXT NOT NULL,
    account_url    TEXT,
    contact_json   TEXT NOT NULL DEFAULT '[]',
    eab_kid        TEXT,
    eab_hmac_enc   TEXT,
    terms_agreed_at TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Managed public certificates ─────────────────────────────────────────────
-- What pktCert has been asked to keep alive. One row per certificate it is
-- responsible for, carrying the names, the provider that proves them, and the
-- renewal window — the certificate itself lands in `certificates` like
-- everything else, so discovery, expiry alerting and the inventory all apply.
--
-- Unlike the ACME server side, pktCert generates and holds the private key
-- here, so it genuinely can renew these itself rather than only noticing that
-- someone else should have.
CREATE TABLE IF NOT EXISTS public_cert_requests (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    account_id       INTEGER NOT NULL REFERENCES public_acme_accounts(id) ON DELETE CASCADE,
    dns_provider_id  INTEGER NOT NULL REFERENCES dns_providers(id) ON DELETE RESTRICT,
    identifiers_json TEXT NOT NULL DEFAULT '[]',
    -- 2048 means P-256 for EC, as everywhere else in the app — x509_utils maps
    -- the RSA sizes onto curves so one pair of fields describes both.
    key_algorithm    TEXT NOT NULL DEFAULT 'ec',
    key_size         INTEGER NOT NULL DEFAULT 2048,
    -- Renew this many days before expiry. Let's Encrypt issues for 90 days and
    -- advises renewing at 30; short-lived profiles need a much tighter window,
    -- which is why this is per-request rather than a constant.
    renew_before_days INTEGER NOT NULL DEFAULT 30,
    auto_renew       INTEGER NOT NULL DEFAULT 1,
    enabled          INTEGER NOT NULL DEFAULT 1,
    status           TEXT NOT NULL DEFAULT 'pending',  -- pending | valid | failed
    last_error       TEXT,
    last_attempt_at  TEXT,
    certificate_id   INTEGER REFERENCES certificates(id) ON DELETE SET NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_public_reqs_enabled ON public_cert_requests(enabled, auto_renew);

-- Which managed request produced a certificate, where one did. Public
-- certificates carry no ca_id — the issuer is outside pktCert entirely — so
-- this is what ties an inventory row back to what maintains it.
ALTER TABLE certificates ADD COLUMN public_request_id INTEGER REFERENCES public_cert_requests(id) ON DELETE SET NULL;
