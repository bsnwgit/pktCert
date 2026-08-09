-- Restores the suite-wide User Keys / Sibling Integrations surface that
-- every pkt* app carries (IP Lookup provider display preferences, and
-- named outbound connections to sibling apps) so pktCert matches the rest
-- of the suite exactly, not just its own domain-specific tables.

-- Per-user display preference: which ipinfo.io/ipapi.is/MXToolbox response
-- sections render in the IP Lookup modal. JSON array of field keys; NULL
-- means "not customized" — treat as all enabled.
ALTER TABLE user_api_keys ADD COLUMN enabled_fields TEXT DEFAULT NULL;

-- Per-user preference: use ipapi.is's free tier (1,000 req/day, no key
-- required) instead of a stored personal key.
ALTER TABLE user_api_keys ADD COLUMN free_tier INTEGER NOT NULL DEFAULT 0;

-- Per-provider preference: show this provider's section in the IP Lookup
-- modal at all. No row yet means never configured/toggled, defaults shown.
ALTER TABLE user_api_keys ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;

-- Named, reusable outbound connections to sibling pkt* apps (e.g. pktIPAM,
-- for internal-IP lookups over Suite Integration — see app/api/ip_info.py
-- and app/api/integrations.py). Multiple named instances per app_name are
-- supported from the start since this is a fresh app with no singleton
-- history to migrate away from.
CREATE TABLE IF NOT EXISTS integrations (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL UNIQUE,
    app_name          TEXT NOT NULL DEFAULT 'pktipam',
    base_url          TEXT NOT NULL DEFAULT '',
    suite_token       TEXT NOT NULL DEFAULT '',
    enabled           INTEGER NOT NULL DEFAULT 1,
    health_status     TEXT NOT NULL DEFAULT 'unknown',
    last_health_check TEXT,
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_integrations_app_name ON integrations(app_name);
