-- 005 — two additive columns:
--
-- certificates.key_encrypted: 1 when the stored/exported private key PEM is
-- itself passphrase-encrypted (PKCS#8 BestAvailableEncryption) so that
-- installing it on a remote server requires entering that passphrase. The
-- passphrase is chosen at issue time and is NEVER stored by pktCert — this
-- flag only records that protection is in effect so the UI can badge it and
-- prompt the operator accordingly. Independent of the always-on Fernet
-- encryption at rest (private_key_enc).
ALTER TABLE certificates ADD COLUMN key_encrypted INTEGER NOT NULL DEFAULT 0;

-- integrations.verify_tls: whether outbound suite calls to this sibling app
-- verify the server's TLS certificate. Defaults to 1 (secure). An operator
-- can turn it off per-connection for an internal app that serves a
-- self-signed cert, rather than the old global verify=False.
ALTER TABLE integrations ADD COLUMN verify_tls INTEGER NOT NULL DEFAULT 1;
