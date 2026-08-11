-- 006 — published-CRL store.
--
-- Before this migration the two CRL endpoints each built their own CRL on
-- demand: GET /api/cas/{id}/crl signed with crl_number+1 and incremented the
-- counter, while the public distribution point GET /crl/{ca_id}.crl signed
-- with the CA's *current* crl_number and never wrote. Revoke a certificate
-- and the public DP would then publish a CRL whose content differed from the
-- one the admin route had already issued under that same CRLNumber.
--
-- RFC 5280 §5.2.3 requires CRLNumber to be a monotonically increasing
-- sequence, unique per issued CRL: a relying party that has cached CRL number
-- N is entitled to ignore any later CRL numbered N, so the newly revoked
-- serial could stay invisible indefinitely.
--
-- This table makes the issued CRL a stored artifact rather than something
-- each endpoint re-derives. One row per CA holds the most recently issued
-- CRL, its number, and a fingerprint of the revoked set it covers. Both
-- endpoints now serve this row and only issue a new CRL — bumping the number
-- exactly once — when the revoked set changes or the published copy nears
-- its nextUpdate. See app/cert/crl_manager.py.
CREATE TABLE IF NOT EXISTS crl_publications (
    ca_id       INTEGER PRIMARY KEY REFERENCES certificate_authorities(id) ON DELETE CASCADE,
    crl_number  INTEGER NOT NULL,
    revoked_fp  TEXT    NOT NULL,   -- sha256 over the revoked (serial, revoked_at) set
    crl_pem     TEXT    NOT NULL,   -- the signed CRL exactly as published
    this_update TEXT    NOT NULL,
    next_update TEXT    NOT NULL,
    issued_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);
