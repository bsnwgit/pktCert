-- External certificates: user-uploaded certs issued by other/outside CAs
-- (source = 'external'), each optionally carrying a private key and an
-- install/use passcode (e.g. a PFX export password, or a note the ops
-- team needs to install the cert) — both Fernet-encrypted at rest via
-- app/cert/crypto.py, same as internally-issued private keys and CA keys.
-- Reading either secret requires re-entering the current password
-- (POST /api/certificates/{id}/reveal-secret) — see app/api/certificates.py.
ALTER TABLE certificates ADD COLUMN passcode_enc TEXT;
