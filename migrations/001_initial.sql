-- pktCert initial schema — common tables shared across the pkt* suite.
-- Cert-domain tables (scan_targets, certificates, certificate_authorities,
-- cert_templates, cert_events, alert_rules, alert_events) are in
-- 002_cert.sql.

CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    username          TEXT NOT NULL UNIQUE,
    email             TEXT NOT NULL UNIQUE,
    hashed_password   TEXT NOT NULL,
    role              TEXT NOT NULL DEFAULT 'viewer',   -- admin | analyst | viewer
    is_active         INTEGER NOT NULL DEFAULT 1,
    auth_provider     TEXT NOT NULL DEFAULT 'local',     -- local | saml
    is_default_admin  INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    last_login        TEXT
);

-- Generic key/value store for runtime settings (JSON-encoded values),
-- mirrors the pattern used across the pkt* suite.
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS app_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    level       TEXT NOT NULL,
    level_no    INTEGER NOT NULL,
    logger      TEXT NOT NULL,
    message     TEXT NOT NULL,
    exc_info    TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_app_logs_created ON app_logs(created_at);

-- Per-user external API keys (Certificate Transparency / cert-search
-- providers), keyed by username rather than user id — suite-proxy
-- (pktHub) requests share a single pseudo user id of 0 across every
-- hub-authenticated identity.
CREATE TABLE IF NOT EXISTS user_api_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL,
    provider    TEXT NOT NULL,
    api_key     TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (username, provider)
);
