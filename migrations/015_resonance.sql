-- pktCert — resonance embed integration
--
-- Three pieces of state the embed integration needs to survive a restart, all
-- deliberately in SQLite rather than in-process: the worker count is
-- configurable, and an in-process counter silently multiplies its own limit
-- once there is more than one worker.
--
-- resonance_rate      — fixed-window counters for /api/resonance/code.
-- resonance_breaker   — one row. A rejected key makes resonance apply a
--                       geometric per-IP backoff (to 300s); this app is a
--                       single IP, so continuing to call with a bad key would
--                       take the widget down for every user at once. The
--                       breaker stops calling instead, and the Settings panel
--                       reads this row so a paused integration says so rather
--                       than looking like a feature that quietly does nothing.
-- resonance_load_failures — embed.js gives up permanently and silently when its
--                       script fails to load (ad blocker, wrong URL, resonance
--                       down), so a broken widget is invisible to the admin.
--                       The mount reports failures here. Keyed by day+user+
--                       reason so the table is bounded by users x reasons x
--                       retained days, not by how often a loop retries.

CREATE TABLE IF NOT EXISTS resonance_rate (
    bucket       TEXT PRIMARY KEY,             -- 'u:<username>' or 'global'
    window_start TEXT NOT NULL,                -- ISO8601 start of the current window
    count        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS resonance_breaker (
    id                   INTEGER PRIMARY KEY CHECK (id = 1),
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    open_until           TEXT,                 -- NULL when closed; ISO8601 while paused
    last_error           TEXT NOT NULL DEFAULT '',
    last_failure_at      TEXT
);

INSERT OR IGNORE INTO resonance_breaker (id) VALUES (1);

CREATE TABLE IF NOT EXISTS resonance_load_failures (
    day       TEXT NOT NULL,                   -- YYYY-MM-DD
    username  TEXT NOT NULL DEFAULT '',
    reason    TEXT NOT NULL DEFAULT '',        -- script_error | code_error | frame_timeout
    count     INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (day, username, reason)
);

CREATE INDEX IF NOT EXISTS idx_resonance_load_failures_day
    ON resonance_load_failures(day DESC);
