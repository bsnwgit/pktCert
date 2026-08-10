# pktCert — PKI & Discovery Reference

Deep-dive on how pktCert's two halves actually work: the internal CA/PKI
(generating and using your own certificate authorities) and discovery
(finding certificates you didn't issue yourself). For day-to-day usage see
[USER_GUIDE.md](USER_GUIDE.md); for install/ops see
[ADMIN_GUIDE.md](ADMIN_GUIDE.md).

## Certificate Authorities

A CA is either:

- **root** — self-signed, `issuer == subject`. This is your trust anchor.
- **intermediate** — signed by a parent CA (root or another intermediate)
  you already have in the inventory. `parent_ca_id` records the chain.

**Generating a new CA** (`POST /api/cas/generate`): pktCert creates the
keypair server-side (`app/cert/x509_utils.generate_private_key`), builds a
`BasicConstraints(ca=True)` certificate with `key_cert_sign`/`crl_sign`
key usage, and signs it — with its own key if root, with the parent CA's
key if intermediate. RSA (2048/4096) and EC (P-256/P-384/P-521) are both
supported.

**Importing an existing CA** (`POST /api/cas/import`): paste an existing
certificate + private key PEM pair. Useful for bringing an
already-established internal CA under pktCert's management, or for a CA
whose root key you deliberately keep offline and only import the day-to-day
signing intermediate.

The import is validated before anything is stored:

- the private key must actually belong to the certificate
- the certificate must assert `BasicConstraints(ca=True)`
- if it carries a KeyUsage extension, it must include `keyCertSign`
- a passphrase-encrypted key is accepted via `key_passphrase` (which is how
  any properly stored CA key is kept)

None of this was checked before, so a leaf certificate imported as a "CA", or
a certificate paired with an unrelated key, was accepted without complaint —
and the failure then surfaced far from the mistake: at signing time, or at
every relying party trying to verify something that CA had issued.

Path length and name constraints are read back out of an imported CA's
certificate, so it displays the same constraint information as a generated
one rather than appearing unconstrained.

**Private keys are never returned by any API response.** They're
Fernet-encrypted at rest (`certificate_authorities.private_key_enc`,
`app/cert/crypto.py`) using the `credential_key` from `config.yaml`, and
are only ever decrypted in-process, immediately before a signing
operation, then discarded.

**Retiring a CA.** `PATCH /api/cas/{id}/status` disables a CA: it stops
issuing, but it stays in the inventory, keeps publishing its CRL, and stays
fetchable at its AIA URL — because the certificates it already issued are
still deployed and still being validated. This is what retiring a CA should
look like, and it's almost always what you want.

**Deleting a CA** (`DELETE /api/cas/{id}`) only works on a CA that has never
issued a certificate, and has no intermediates beneath it.

The old rule allowed deletion once no *non-revoked* certificates remained,
which is precisely backwards: revoked certificates are the ones that most
need their CA alive, since deleting it destroys the only key that can sign
the CRL carrying their revocations — while those certificates are still out
there being trusted. It also cascaded away the CA's entire audit history.

### Constraints: path length and name constraints

Two optional limits, both set when the CA is generated and both baked into
the CA certificate itself, where a relying party enforces them — they cannot
be changed afterwards without reissuing the CA.

**Path length** caps how many further CAs may sit below this one. An
intermediate defaults to `0`: it may issue end-entity certificates but not
another CA. A root is unconstrained by default. Every CA used to be built
with no limit at all, which made any intermediate capable of minting an
unlimited chain of further sub-CAs — a stolen intermediate key was then as
dangerous as the root.

**Name constraints** limit what names a CA may certify at all. A CA
constrained to `.corp.example.com` cannot mint a working certificate for
anything outside it, even if its private key is stolen — a conforming client
rejects the chain. This is the strongest containment available for an
internal CA, and it's why an unconstrained CA in a trust store is effectively
a CA for the entire internet. Set as permitted/excluded DNS suffixes and IP
CIDR ranges, and marked critical: a client that can't understand the
constraint must reject the chain rather than ignore the limit.

## Chain building: the AIA endpoint

Every certificate pktCert issues carries an Authority Information Access
extension whose `caIssuers` URL points at `GET /aia/{ca_id}.crt`, and each
intermediate points at its parent the same way.

This matters more than it sounds. A TLS server that sends only its leaf
certificate and no intermediates is extremely common. Without a `caIssuers`
URL, a client holding that leaf has a certificate signed by an issuer it has
no way to obtain, so chain building fails and the certificate looks broken
even though everything about it is correct. AIA is how the client finds the
missing link.

The endpoint is unauthenticated for the same reason the CRL is: a CA
certificate is public by definition — it's the thing you install in a trust
store. It serves DER (`application/pkix-cert`), which is what Windows, macOS
and OpenSSL fetch; `?format=pem` returns PEM for humans copying it into a
config file.

## Offline root

A root CA is the one key that should never sit on a network-facing service.
It can't be rotated quickly — it's installed in the trust store of every
machine that trusts you — so a server compromise that reaches it is close to
unrecoverable.

pktCert supports keeping it out entirely. It holds the root **certificate**
only; the private key stays on a machine that never touches the network (or a
USB stick in a safe). Day-to-day issuance runs off an intermediate, so a
compromise of this server costs an intermediate you can revoke rather than the
root everybody trusts.

The ceremony, in three moves:

1. **Register the root** — `POST /api/cas/import-root-cert`, or
   Certificate Authorities → Add CA → **Offline Root**. Certificate only, no
   key. `key_storage` is recorded as `offline`.
2. **Request an intermediate** — `POST /api/cas/request-intermediate`.
   pktCert generates the intermediate keypair *here* and produces a CSR. The
   CA is created in status `pending_signature` and can issue nothing. Only the
   CSR travels; the private key never leaves. The CSR states the intended
   BasicConstraints/KeyUsage/NameConstraints so the operator at the offline
   machine can copy the intended limits rather than reconstruct them.
3. **Bring back the signed certificate** — `POST /api/cas/{id}/import-signed-cert`.

That last step is checked before anything is stored, because a mistake there
surfaces far away — at every relying party, not here:

- the certificate must match the private key pktCert generated
- it must be a CA certificate (`BasicConstraints(ca=True)`, `keyCertSign`)
- its issuer must be the expected parent, **and** its signature must actually
  verify against that parent's key — a certificate can name the right issuer
  without having been signed by it

The CSR can be re-downloaded (`GET /api/cas/{id}/csr`) for as long as the CA
is pending. The round trip to an air-gapped machine is rarely done in one
sitting, and regenerating the CSR would produce a different key.

### What an offline CA cannot do

It cannot sign. That includes signing its own CRL — which is the point, not an
oversight. So revocations under an offline root are published by signing the
CRL on the machine that holds the key and uploading it
(`POST /api/cas/{id}/upload-crl`, or **Publish CRL** in the UI). The upload is
verified to have been issued by that CA and to carry a signature that verifies
against its certificate, then served at the CA's normal distribution point
like any other.

Until a CRL has been uploaded, the admin route returns 409 with an
explanation, and the public distribution point returns 404 — to a relying
party that is simply "no CRL published here".

Attempting to issue from an offline CA, or from an intermediate still awaiting
its signature, is refused with a message saying which case applies. The
auto-renewal loop skips both.

## Issuance Templates

A template (`cert_templates` table) is a reusable signing profile:

| Field | Meaning |
|---|---|
| `key_algorithm` / `key_size` | `rsa` (2048/4096) or `ec` (2048→P-256, 3072→P-384, 4096→P-521 in the UI's mapping) |
| `validity_days` | How long an issued cert is valid for |
| `key_usage` | X.509 KeyUsage extension flags, e.g. `digital_signature`, `key_encipherment` |
| `extended_key_usage` | EKU OIDs, e.g. `server_auth`, `client_auth`, `code_signing` |
| `default_ca_id` | Optional pre-fill for the issuance form |

A default template ("Standard TLS Server", RSA-2048, 1 year, server auth)
is seeded by `migrations/002_cert.sql` so issuance works immediately after
a CA exists — no template setup required for the common case.

## Issuing a certificate

`POST /api/certificates/issue` — given a CA, a template, a Common Name,
optional SANs, and an optional `key_passphrase`:

1. Generate a fresh keypair matching the template's algorithm/size.
2. Build a CSR from that keypair (`x509_utils.generate_csr`).
3. Sign it with the CA's key, applying the template's validity/key-usage/EKU
   (`x509_utils.sign_certificate`).
4. Store the cert (plaintext PEM — public data) and the private key
   (Fernet-encrypted) in `certificates`, `source = 'issued'`.
5. Return the private key **once**, in the direct response to this call —
   that's not treated as a secret *reveal* (the caller already has it in
   hand, it was never hidden from them), but it's also the last time it's
   shown without re-authenticating. See
   [Secrets & step-up re-auth](#secrets--step-up-re-auth) below.

### Optional private-key passphrase

The issue dialog offers **"Protect the private key with a passphrase"**
(API: `key_passphrase`). When set, the key PEM produced at step 4 — both
the copy returned to you and the copy stored for later download — is
itself encrypted with that passphrase (PKCS#8
`BestAvailableEncryption`), so installing it on a server requires
entering it.

pktCert does **not** store the passphrase. It records only the
`key_encrypted` flag (migration `005`) so the UI can badge the
certificate. A lost passphrase means a lost key — reissue.

Don't confuse this with the Fernet encryption at rest applied to every
stored private key: that is always on, managed by pktCert, and invisible
to you. This passphrase is yours, and it travels with the exported PEM.
Leave the box unticked and issuance behaves exactly as before.

## Signing an external CSR

`POST /api/certificates/csr` — same CA+template signing path, but the
keypair and CSR are generated by the requester, not pktCert, so the
private key never leaves their machine. pktCert only ever sees and stores
the resulting certificate.

The CSR's own signature is verified before anything is signed. A CSR is
self-signed with the very key it asks to have certified, so that signature
is the only proof the requester actually holds the private key for the
public key being bound to their name — without the check, anyone could
paste someone else's public key into a CSR and be issued a certificate for
it. A CSR that fails verification is rejected with HTTP 400.

Certificates from this route get the same CRL Distribution Point as the
`/issue` route, and the same guarantee that the Common Name also appears in
the SAN (see below).

### CN is always in the SAN

Browsers and most modern TLS stacks ignore the Common Name for hostname
matching and look only at the Subject Alternative Name. A certificate whose
CN is missing from its SAN therefore looks entirely correct in every UI —
right issuer, right name, valid dates — and still fails hostname
verification at connection time.

`x509_utils.sign_certificate` merges the CN into the SAN set for every
issuance path, so this holds whether pktCert generated the CSR or the
requester supplied their own.

## Renewal

`POST /api/certificates/{id}/renew` issues a replacement carrying the same
subject and SANs, from the same CA and template, and links the two
generations together (`renewed_from_id` / `renewed_to_id`).

Renewal always generates a **fresh keypair**. Re-certifying the same public
key would carry any compromise of the old key straight into the new
certificate, and pktCert has no way to know how widely that key has been
copied since it was issued.

The previous certificate is marked **`superseded`**, not revoked. It is
still deployed and still trusted by everything that has it, and revoking it
at the moment of renewal would break the running service instantly —
before anyone has installed the replacement. A superseded certificate stays
in the inventory but stops raising expiry alerts, because the thing those
alerts would be asking for already exists. Revoke it yourself once the new
one is in place.

Only certificates pktCert issued can be renewed. A discovered or
externally-issued certificate has to be replaced at whatever CA issued it.

### Automatic renewal

`PATCH /api/certificates/{id}/auto-renew` opts a single certificate in, with
its own window (`auto_renew_days`, default 30). `app/cert/renewal.py` checks
every 10 minutes and renews anything inside its window, through the same
issuance path as a manual renewal — an auto-renewed certificate is
indistinguishable from a hand-issued one.

Auto-renewal does **not** install anything. The new certificate and its key
are stored in pktCert; getting them onto the server that serves them is
still a human step. That's precisely why it's opt-in per certificate rather
than a global default: it removes the "nobody noticed it was expiring"
failure, not the deployment step.

An auto-renewal gets no key passphrase — there is nobody at a keyboard to
supply or receive one. The key is still Fernet-encrypted at rest like every
other stored key, and retrievable through the usual step-up re-auth.

## Separation of duties (optional)

**Off by default.** With it off, issuing and revoking behave exactly as they
always have: immediate, no queue, no extra step. A small team where everyone is
trusted equally gains nothing from an approval workflow and pays for it on
every issuance, so it has to be opted into — Settings → Cert Settings, one
toggle for issuance and one for revocation.

With it on, `POST /api/certificates/issue` and `.../revoke` stop acting. They
record a pending request (`cert_requests`, migration `010`) and return HTTP
202 with its id. A **different** admin then approves it via
`POST /api/approvals/{id}/approve`, and *that* is what performs the real
issuance or revocation — through the same `app/cert/issuance.py` path as a
direct call, so an approved certificate is indistinguishable from a directly
issued one.

Self-approval is refused. One person clicking twice is not two pairs of eyes,
and permitting it would make the control decorative — which is worse than not
having it at all, because it still looks like a control in an audit. The
practical consequence: **an install with a single admin account cannot approve
anything**, and should leave this off. The Approvals page says so directly when
it detects that situation.

Withdrawing a pending request is always allowed, by its requester or any admin.
Cancelling can only ever prevent an action, never cause one, so it isn't a way
around the two-person rule.

On an approved issuance no key passphrase is applied — the requester isn't
present to choose one, and the approver shouldn't invent a secret on their
behalf. The key is Fernet-encrypted at rest as always, and the requester
retrieves it through the usual step-up re-auth.

## Revocation & CRLs

`POST /api/certificates/{id}/revoke` marks a certificate `revoked`
(terminal — no un-revoke) and records a `cert_events` entry.

Revocation takes an RFC 5280 **reason code** (`reason_code`) alongside the
free-text note, and that code is published in the CRL entry. Relying parties
act on it: `key_compromise` casts doubt on every signature that key ever
made, while `superseded` or `cessation_of_operation` are routine lifecycle
events. Publishing every revocation as an undifferentiated serial number
throws that distinction away. The free-text `reason` stays an internal note
and never leaves the database.

`unspecified` deliberately emits no reasonCode extension at all — RFC 5280
§5.3.1 says it SHOULD be absent rather than present-and-unspecified, since an
explicit "unspecified" carries no more information than no extension.

A CRL is **issued once and stored**, not rebuilt per request.
`app/cert/crl_manager.py` owns that, and both CRL routes serve the same
stored artifact:

- `GET /api/cas/{id}/crl` — authenticated, returns PEM plus the CRL's
  number and validity window for the admin UI.
- `GET /crl/{ca_id}.crl` — the unauthenticated distribution point baked
  into every issued certificate, returns DER with cache headers. It has no
  login by design: any relying party validating one of these certificates
  must be able to fetch it.

A new CRL is issued — consuming exactly one new `CRLNumber` — only when
there is something new to say: the revoked set changed, or the published
copy has come within a day of its `nextUpdate` and needs re-signing before
it goes stale. Anything else serves the stored copy byte-for-byte, so
anonymous polling of the public DP costs neither a CA signing operation nor
a database write.

**Why it works this way.** RFC 5280 §5.2.3 makes `CRLNumber` a
monotonically increasing sequence, unique per issued CRL: a client holding
number N is entitled to ignore any later CRL that also claims number N.
Before this design the two routes each built their own CRL — the admin
route signed with `crl_number + 1` and incremented the counter on every
view, the public route signed with the current `crl_number` and never
wrote — so revoking a certificate published a second, different CRL under a
number the admin route had already used, and a client that had cached the
first one could stay blind to the revocation indefinitely. Storing the
issued CRL removes the divergence: there is only ever one CRL per number.

A database created before migration `006` keeps whatever `crl_number` the
old route left on the CA row; the first CRL issued after upgrading
continues past it rather than replaying numbers already published.

There is no OCSP responder — revocation status is only available via CRL
(see the README's Known Gaps section).

## Secrets & step-up re-auth

Two kinds of secret exist per certificate: the private key
(`private_key_enc`, set for issued certs and for uploaded certs that
included a key) and an install/use passcode (`passcode_enc`, set only for
uploaded external certs). Both:

- are Fernet-encrypted at rest with the same `credential_key`
- are never included in list/detail JSON or a plain `GET`
- can only be read via `POST /api/certificates/{id}/reveal-secret`, which
  requires the caller's *current* password and logs a `cert_events` entry
  (`secret_accessed`) on every success

This is uniform regardless of `source` — an internally issued key and an
uploaded external key are protected identically.

## Discovery: active scanning

`app/cert/scanner.py` runs a background loop (`ScanEngine`, ~30s tick)
that finds `scan_targets` whose `schedule_minutes` window has elapsed and
scans them; `POST /api/scan-targets/{id}/scan-now` calls the exact same
`scan_target_once()` function out-of-band, so there's one implementation
of "what a scan does," not two.

A target is a single `host` or a `cidr` (expanded to individual addresses,
capped at 4096 per run) plus a comma-separated `ports` list. For each
host:port pair, pktCert opens a TLS connection with certificate
verification disabled (`ssl.CERT_NONE` — the goal is to inventory
whatever's presented, not validate trust), reads the leaf certificate (and
chain, where the peer offers one — chain retrieval needs Python 3.13+;
older runtimes get the leaf only), and upserts it into `certificates` by
SHA-256 fingerprint: an already-known cert just gets `last_seen_at` and
its `scan_target_id`/`host`/`port` updated, a new one is inserted with
`source = 'scan'`.

## Discovery: Certificate Transparency search

`app/cert/ct_search.py` provides two lookups, keyed by domain:

- `search_crtsh` — queries crt.sh's public JSON API, no key required.
- `search_censys` — queries Censys's host search API, requires a personal
  `api_id:api_secret` key under Settings → User Keys → Censys.

Neither is currently wired into a scheduled background job — the
`discovery_ct_auto_enabled` / `discovery_ct_watched_domains` settings
(Settings → Discovery & Alerts) describe the intended automatic-search
behavior; CT search today is available via the underlying functions for
manual/scripted use. Automatic periodic CT search is tracked as fast-follow
work.

## Certificate status lifecycle

`app/cert/alert_engine.py`'s `_refresh_statuses()` runs every tick
alongside alert evaluation:

- `not_after < now` → `expired` (unless already `revoked` or `superseded`)
- `not_after < now + 30 days` → `expiring`
- otherwise → `valid`

`revoked` is set only by an explicit revoke call, and `superseded` only by
renewal. Neither is ever overwritten by this automatic refresh, and neither
raises expiry alerts — a revoked certificate is already dead, and a
superseded one has already been replaced.
