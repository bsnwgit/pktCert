-- 012 — protocol-based enrolment (EST, SCEP).
--
-- Issuance so far has required a human: open the UI, fill the form, copy the
-- certificate and key onto the device. That doesn't scale past a handful of
-- servers and it doesn't work at all for network gear, which is the bulk of
-- what a network-tooling suite actually manages. Switches, routers, firewalls
-- and VPN clients enrol themselves — over SCEP if they're older, EST if
-- they're newer.
--
-- An enrolment profile is the unit of authorisation: a shared secret, bound to
-- one CA and one template, that a device presents to obtain a certificate.
-- Deliberately narrow — a device authenticating with a profile can only ever
-- get the kind of certificate that profile describes, from the CA it names,
-- for a name the profile permits.
CREATE TABLE IF NOT EXISTS enrollment_profiles (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    protocol      TEXT NOT NULL,                    -- est | scep
    ca_id         INTEGER NOT NULL REFERENCES certificate_authorities(id) ON DELETE CASCADE,
    template_id   INTEGER NOT NULL REFERENCES cert_templates(id) ON DELETE CASCADE,

    -- EST uses HTTP Basic, so it needs a username; SCEP has only a challenge
    -- password, so username is unused there.
    username      TEXT,
    -- Fernet-encrypted at rest like every other secret pktCert holds. It is a
    -- bearer credential: anything holding it can obtain a certificate from
    -- this profile, which is why profiles are narrow and revocable.
    secret_enc    TEXT NOT NULL,

    enabled       INTEGER NOT NULL DEFAULT 1,

    -- Optional containment. A device enrolling over a shared secret should not
    -- be able to ask for any name it likes: a profile for the access-switch
    -- fleet has no business issuing a certificate for the payroll server.
    -- Matched as a case-insensitive suffix against the CSR's CN and every SAN.
    allowed_name_suffix TEXT,
    -- Optional ceiling on how many certificates this profile may ever issue,
    -- so a leaked secret has a bounded blast radius.
    max_certs     INTEGER,
    issued_count  INTEGER NOT NULL DEFAULT 0,

    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at  TEXT
);

-- Every enrolment attempt, accepted or refused. A device fleet enrolling
-- itself is exactly the situation where you need to be able to answer "what
-- asked for this certificate, and from where" months later.
CREATE TABLE IF NOT EXISTS enrollment_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id     INTEGER REFERENCES enrollment_profiles(id) ON DELETE SET NULL,
    protocol       TEXT NOT NULL,
    operation      TEXT NOT NULL,                   -- simpleenroll | simplereenroll | cacerts | pkioperation
    client_ip      TEXT,
    subject        TEXT,
    outcome        TEXT NOT NULL,                   -- issued | denied | error
    detail         TEXT,
    certificate_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_enrollment_log_created ON enrollment_log(created_at);
CREATE INDEX IF NOT EXISTS idx_enrollment_log_profile ON enrollment_log(profile_id);
