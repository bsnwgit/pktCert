-- 011 — offline root CA support.
--
-- Until now every CA pktCert knew about had its private key in pktCert: a
-- server compromise handed over the root, and with it the ability to
-- impersonate anything in the trust store, permanently. A root cannot be
-- rotated quickly — it's installed on every machine that trusts you — so it
-- is exactly the key that should never sit on an internet-facing service.
--
-- The standard answer is an offline root: the root's private key lives on
-- a machine (or a USB stick in a safe) that never touches the network.
-- pktCert holds only the root CERTIFICATE, generates an intermediate keypair
-- and CSR, and you carry that CSR to the offline machine, sign it there, and
-- bring back the signed intermediate. Day-to-day issuance then uses the
-- intermediate — and a server compromise costs an intermediate you can
-- revoke, rather than the root everybody trusts.
--
-- key_storage:
--   'local'   — the private key is in private_key_enc (all existing CAs)
--   'offline' — pktCert holds no private key for this CA at all
--
-- An offline CA cannot sign, which includes signing its own CRL. That's not a
-- gap to paper over — it is the point — so revocations under an offline root
-- are published by signing the CRL on the offline machine and uploading it
-- here (uploaded_crl_pem), where it is served at the usual distribution point.
ALTER TABLE certificate_authorities ADD COLUMN key_storage TEXT NOT NULL DEFAULT 'local';

-- The CSR for an intermediate awaiting out-of-band signature. Kept so it can
-- be re-downloaded — the round trip to an offline machine is rarely done in
-- one sitting, and regenerating the CSR would mean a different key.
ALTER TABLE certificate_authorities ADD COLUMN csr_pem TEXT;

-- A CRL signed elsewhere (by the offline root) and uploaded for publication.
ALTER TABLE certificate_authorities ADD COLUMN uploaded_crl_pem TEXT;

-- certificate_authorities.status gains 'pending_signature': an intermediate
-- whose key exists here and whose CSR is waiting to come back signed. It
-- cannot issue anything until its certificate is imported.
