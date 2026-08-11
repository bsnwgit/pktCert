-- 008 — certificate renewal.
--
-- Until now pktCert could issue a certificate and revoke it, but never renew
-- one: the only way to replace an expiring cert was to issue a fresh one by
-- hand and remember, yourself, that it superseded something. Renewal is the
-- bulk of real certificate lifecycle work — issuance happens once per
-- service, renewal happens every year of its life.
--
-- renewed_from_id / renewed_to_id chain the generations together so an
-- inventory row can answer "what replaced this?" and "what did this replace?".
-- Both are SET NULL on delete rather than CASCADE: losing one generation must
-- not delete the rest of the chain.
ALTER TABLE certificates ADD COLUMN renewed_from_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL;
ALTER TABLE certificates ADD COLUMN renewed_to_id   INTEGER REFERENCES certificates(id) ON DELETE SET NULL;

-- auto_renew: renew this certificate automatically once it comes within
-- auto_renew_days of expiry (app/cert/renewal.py). Off by default —
-- auto-renewal generates a new keypair server-side, and the operator still
-- has to install it, so it must be opted into per certificate.
ALTER TABLE certificates ADD COLUMN auto_renew      INTEGER NOT NULL DEFAULT 0;
ALTER TABLE certificates ADD COLUMN auto_renew_days INTEGER NOT NULL DEFAULT 30;

-- Renewing marks the previous certificate 'superseded' — a new status
-- alongside valid/expiring/expired/revoked. It stays in the inventory
-- (it's still deployed and still trusted until it expires) but stops
-- generating expiry alerts, because the replacement already exists.
CREATE INDEX IF NOT EXISTS idx_certificates_auto_renew ON certificates(auto_renew, not_after);
