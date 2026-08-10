-- 010 — separation of duties: an approval queue for issuance and revocation.
--
-- One admin role currently does everything: request a certificate, approve it,
-- issue it, revoke it, and reveal its private key. Regulated environments
-- require those split, so that no single person can mint a trusted identity
-- unobserved — the "four eyes" rule.
--
-- OFF BY DEFAULT. A small team where everyone is trusted equally gains nothing
-- from an approval queue and loses a step on every issuance, so with the
-- feature disabled (require_issuance_approval / require_revocation_approval
-- both unset) issuance behaves exactly as it did before this migration:
-- immediate, no queue, no extra clicks. Nothing here activates until an admin
-- turns it on in Settings -> Cert Settings.
--
-- When enabled, POST /api/certificates/issue and .../revoke stop acting
-- directly and record a pending request here instead. A DIFFERENT admin then
-- approves it, and the approval is what performs the real issuance or
-- revocation. Self-approval is refused — one person clicking twice is not two
-- pairs of eyes, and permitting it would make the whole control decorative.
CREATE TABLE IF NOT EXISTS cert_requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    request_type    TEXT NOT NULL,                       -- issue | revoke
    status          TEXT NOT NULL DEFAULT 'pending',     -- pending | approved | rejected | cancelled

    -- Issuance parameters (request_type = 'issue')
    common_name     TEXT,
    sans_json       TEXT NOT NULL DEFAULT '[]',
    ca_id           INTEGER REFERENCES certificate_authorities(id) ON DELETE SET NULL,
    template_id     INTEGER REFERENCES cert_templates(id) ON DELETE SET NULL,
    auto_renew      INTEGER NOT NULL DEFAULT 0,
    auto_renew_days INTEGER NOT NULL DEFAULT 30,

    -- Revocation parameters (request_type = 'revoke')
    certificate_id  INTEGER REFERENCES certificates(id) ON DELETE CASCADE,
    reason          TEXT,
    reason_code     TEXT,

    -- Who asked, who decided. Names are denormalised on purpose: an audit
    -- record must stay readable after the user account is deleted.
    requested_by    TEXT NOT NULL,
    requested_by_id INTEGER,
    justification   TEXT,
    requested_at    TEXT NOT NULL DEFAULT (datetime('now')),
    decided_by      TEXT,
    decided_by_id   INTEGER,
    decided_at      TEXT,
    decision_note   TEXT,

    -- What the approval produced, for issuance requests.
    resulting_certificate_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_cert_requests_status ON cert_requests(status, requested_at);
