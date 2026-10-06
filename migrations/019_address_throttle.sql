-- Per-address login throttle: one row per failed credential check, and one row
-- per address that has been blocked. See app/auth/throttle.py.
CREATE TABLE IF NOT EXISTS address_failures (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    ts      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_address_failures_addr_ts ON address_failures(address, ts);

CREATE TABLE IF NOT EXISTS address_blocks (
    address       TEXT PRIMARY KEY,
    blocked_until TEXT NOT NULL
);
