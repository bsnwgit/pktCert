-- 009 — machine-readable revocation reasons, and CA constraint metadata.
--
-- certificates.revoked_reason has always been free text ("replaced the load
-- balancer", "laptop stolen") and never reached the CRL at all. RFC 5280
-- defines a reasonCode CRL entry extension, and relying parties treat those
-- codes differently: keyCompromise means every signature that key ever made
-- is suspect, while cessationOfOperation or superseded are routine.
-- Publishing every revocation as an undifferentiated serial number throws
-- that distinction away.
--
-- revoked_reason_code holds the RFC 5280 name (unspecified, keyCompromise,
-- ca_compromise, affiliation_changed, superseded, cessation_of_operation,
-- certificate_hold, privilege_withdrawn, aa_compromise). The free-text
-- revoked_reason stays as the human note alongside it.
ALTER TABLE certificates ADD COLUMN revoked_reason_code TEXT;

-- Constraint metadata recorded at CA generation, kept so the UI can show what
-- a CA was constrained to without re-parsing its certificate every time. The
-- constraints themselves live in the CA certificate where they're enforced —
-- these columns are a record of what was requested, not the enforcement.
ALTER TABLE certificate_authorities ADD COLUMN path_length INTEGER;
ALTER TABLE certificate_authorities ADD COLUMN name_constraints_json TEXT;
