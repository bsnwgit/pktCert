-- Certificate Transparency check history: one row per crt.sh validation, so the
-- CT Checks page can show every user what has been checked, by whom, and what
-- came back. Never holds a PEM — only what identifies the certificate and the
-- verdict. See app/cert/ct_history.py.
CREATE TABLE IF NOT EXISTS ct_checks (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    checked_at         TEXT NOT NULL DEFAULT (datetime('now')),
    checked_by         TEXT NOT NULL,
    source             TEXT NOT NULL,       -- inventory | pem | host
    certificate_id     INTEGER REFERENCES certificates(id) ON DELETE SET NULL,
    common_name        TEXT NOT NULL DEFAULT '',
    issuer             TEXT NOT NULL DEFAULT '',
    serial_number      TEXT NOT NULL DEFAULT '',
    fingerprint_sha256 TEXT NOT NULL DEFAULT '',
    not_after          TEXT,
    fetched_from       TEXT,
    verdict            TEXT NOT NULL,
    unexpected_count   INTEGER NOT NULL DEFAULT 0,
    result_json        TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_ct_checks_checked_at ON ct_checks(checked_at);
CREATE INDEX IF NOT EXISTS idx_ct_checks_fingerprint ON ct_checks(fingerprint_sha256);
