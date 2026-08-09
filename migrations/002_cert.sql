-- pktCert domain schema — certificate discovery/inventory and internal
-- CA/PKI issuance.

-- ── Certificate Authorities (root or intermediate) ──────────────────────────
-- private_key_enc is Fernet-encrypted (app/cert/crypto.py) and is never
-- returned by any API response — decrypted only in-process for signing.
CREATE TABLE IF NOT EXISTS certificate_authorities (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT NOT NULL,
    ca_type             TEXT NOT NULL DEFAULT 'root',   -- root | intermediate
    parent_ca_id        INTEGER REFERENCES certificate_authorities(id) ON DELETE SET NULL,
    subject             TEXT NOT NULL,
    cert_pem            TEXT NOT NULL,
    private_key_enc     TEXT NOT NULL,
    key_algorithm       TEXT NOT NULL DEFAULT 'rsa',    -- rsa | ec
    key_size            INTEGER NOT NULL DEFAULT 4096,
    signature_algorithm TEXT NOT NULL DEFAULT 'sha256',
    not_before          TEXT NOT NULL,
    not_after           TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'active', -- active | expired | revoked
    crl_number          INTEGER NOT NULL DEFAULT 0,
    source              TEXT NOT NULL DEFAULT 'generated', -- generated | imported
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cas_parent ON certificate_authorities(parent_ca_id);

-- ── Issuance templates ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cert_templates (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    name                  TEXT NOT NULL UNIQUE,
    key_algorithm         TEXT NOT NULL DEFAULT 'rsa',   -- rsa | ec
    key_size              INTEGER NOT NULL DEFAULT 2048,
    validity_days         INTEGER NOT NULL DEFAULT 365,
    key_usage_json        TEXT NOT NULL DEFAULT '["digital_signature","key_encipherment"]',
    extended_key_usage_json TEXT NOT NULL DEFAULT '["server_auth"]',
    default_ca_id         INTEGER REFERENCES certificate_authorities(id) ON DELETE SET NULL,
    created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Scan targets (active TLS discovery) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_targets (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    host             TEXT,                             -- single host (mutually exclusive with cidr)
    cidr             TEXT,                             -- CIDR range, expanded at scan time
    ports            TEXT NOT NULL DEFAULT '443',       -- comma-separated port list
    schedule_minutes INTEGER NOT NULL DEFAULT 1440,     -- 0 = manual only
    enabled          INTEGER NOT NULL DEFAULT 1,
    last_scan_at     TEXT,
    last_status      TEXT NOT NULL DEFAULT 'unknown',   -- ok | error | unknown
    last_error       TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Certificates (unified inventory: scanned, CT-discovered, or issued) ─────
CREATE TABLE IF NOT EXISTS certificates (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    common_name          TEXT NOT NULL,
    san_json             TEXT NOT NULL DEFAULT '[]',
    issuer               TEXT NOT NULL DEFAULT '',
    subject              TEXT NOT NULL DEFAULT '',
    serial_number        TEXT NOT NULL DEFAULT '',
    fingerprint_sha256   TEXT NOT NULL UNIQUE,
    not_before           TEXT,
    not_after             TEXT,
    key_algorithm        TEXT,
    key_size             INTEGER,
    signature_algorithm  TEXT,
    status               TEXT NOT NULL DEFAULT 'unknown', -- valid | expiring | expired | revoked | unknown
    source               TEXT NOT NULL DEFAULT 'scan',     -- scan | ct | issued
    scan_target_id       INTEGER REFERENCES scan_targets(id) ON DELETE SET NULL,
    host                 TEXT,
    port                 INTEGER,
    cert_pem             TEXT,
    chain_pem            TEXT,
    private_key_enc      TEXT,        -- only set for issued certs where pktCert generated the keypair
    ca_id                INTEGER REFERENCES certificate_authorities(id) ON DELETE SET NULL,
    template_id          INTEGER REFERENCES cert_templates(id) ON DELETE SET NULL,
    first_seen_at        TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at         TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at           TEXT,
    revoked_reason       TEXT,
    created_at           TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_certificates_ca ON certificates(ca_id);
CREATE INDEX IF NOT EXISTS idx_certificates_common_name ON certificates(common_name);

-- ── Audit trail ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cert_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id INTEGER REFERENCES certificates(id) ON DELETE CASCADE,
    ca_id          INTEGER REFERENCES certificate_authorities(id) ON DELETE CASCADE,
    event_type     TEXT NOT NULL, -- discovered | issued | renewed | revoked | expiring_soon | scan_failed
    message        TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cert_events_cert ON cert_events(certificate_id);
CREATE INDEX IF NOT EXISTS idx_cert_events_created ON cert_events(created_at);

-- ── Alerting ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alert_rules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT NOT NULL,
    condition_type TEXT NOT NULL,   -- cert_expiring | cert_expired | cert_revoked | ca_expiring | scan_target_unreachable
    threshold      REAL,            -- days-before-expiry, for the *_expiring types
    severity       TEXT NOT NULL DEFAULT 'warning',   -- info | warning | critical
    enabled        INTEGER NOT NULL DEFAULT 1,
    cooldown_min   INTEGER NOT NULL DEFAULT 15,
    channels       TEXT NOT NULL DEFAULT '["inapp"]',
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alert_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id          INTEGER REFERENCES alert_rules(id) ON DELETE SET NULL,
    certificate_id   INTEGER REFERENCES certificates(id) ON DELETE SET NULL,
    ca_id            INTEGER REFERENCES certificate_authorities(id) ON DELETE SET NULL,
    severity         TEXT NOT NULL DEFAULT 'warning',
    message          TEXT NOT NULL,
    value            REAL,
    threshold        REAL,
    active           INTEGER NOT NULL DEFAULT 1,
    acked            INTEGER NOT NULL DEFAULT 0,
    acked_by         TEXT,
    acked_at         TEXT,
    resolved         INTEGER NOT NULL DEFAULT 0,
    auto_resolved    INTEGER NOT NULL DEFAULT 0,
    resolved_at      TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_alert_events_active ON alert_events(active, acked);

-- Seed a sensible default issuance template so "Issue Certificate" works
-- out of the box once a CA exists.
INSERT OR IGNORE INTO cert_templates (id, name, key_algorithm, key_size, validity_days, key_usage_json, extended_key_usage_json)
VALUES (1, 'Standard TLS Server (RSA-2048, 1yr)', 'rsa', 2048, 365,
        '["digital_signature","key_encipherment"]', '["server_auth"]');
