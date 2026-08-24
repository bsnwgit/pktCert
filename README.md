# pktCert

<p align="center">
  <img src="lockup-256h.png" alt="pktCert" height="64">
</p>

Enterprise certificate management — part of the pkt suite. Discovers and
inventories TLS certificates across your network (active port scans and
Certificate Transparency log search), tracks expiration, and doubles as an
internal CA/PKI: generate or import root/intermediate CAs, define issuance
templates, issue and revoke certificates, and serve CRLs. Surfaces it
through a React UI with alerting. Every
page/section has a "?" help button (same pattern across the whole pkt*
suite) with a short in-context explainer — no separate user manual.

**Default port:** `8763` (HTTP)

**Deployment status:** built, verified end-to-end, and installed as a live
systemd service on an internal Linux host.

---

## Documentation

This README is the technical reference. For task-oriented guides (also
readable in-app via the **Documentation** link in the sidebar, no repo
checkout needed):

- [docs/USER_GUIDE.md](docs/USER_GUIDE.md) — day-to-day usage: inventory, scanning, issuing certs
- [docs/ADMIN_GUIDE.md](docs/ADMIN_GUIDE.md) — install, configure, operate
- [docs/PKI-and-Discovery.md](docs/PKI-and-Discovery.md) — CA hierarchy, templates, CSR signing, and CT search in depth

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Frontend Build & Deploy](#frontend-build--deploy)
- [Discovery: Scan Targets](#discovery-scan-targets)
- [Discovery: Certificate Transparency Search](#discovery-certificate-transparency-search)
- [Certificate Inventory](#certificate-inventory)
- [Certificate Authorities](#certificate-authorities)
- [Offline Root CA](#offline-root-ca)
- [Issuance Templates](#issuance-templates)
- [Issuing & Revoking Certificates](#issuing--revoking-certificates)
- [Renewal](#renewal)
- [Separation of Duties](#separation-of-duties)
- [Device Enrolment (EST and SCEP)](#device-enrolment-est-and-scep)
- [External Certificates & Secret Storage](#external-certificates--secret-storage)
- [Settings Layout](#settings-layout)
- [Configuration Reference](#configuration-reference)
- [Running & Managing the Service](#running--managing-the-service)
- [Roles & Auth](#roles--auth)
- [Alerting](#alerting)
- [Suite Integration](#suite-integration)
- [User Keys & IP Lookup](#user-keys--ip-lookup)
- [pktHub NOC Widgets](#pkthub-noc-widgets)
- [Backup & Restore](#backup--restore)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Contributing](#contributing)
- [Known Gaps / Fast-Follow Work](#known-gaps--fast-follow-work)
- [Log Forwarding](#log-forwarding)

---

## Quick Start

```bash
git clone git@github.com:bsnwgit/pktCert.git
cd pktCert
bash install.sh
```

The installer prompts for an install directory (default `/opt/pktcert`) and
a port (default `8763`), sets up a Python virtualenv, initializes the
SQLite database, seeds an admin account with a randomly generated password,
builds the React frontend (if `npm` is available), and installs/starts a
systemd service. Credentials print once at the end — save them.

## Architecture

- **Backend:** FastAPI + aiosqlite (single SQLite database file), served by
  Uvicorn. `app/server.py` is the systemd entrypoint — it reads host/port/SSL
  from `config.yaml` at process start, so a Settings → General port change
  only needs a restart, not a unit-file edit.
- **Frontend:** React 18 + TypeScript + Vite + Tailwind, built to
  `frontend/dist` and served directly by FastAPI as a SPA (no separate
  static-file server needed).
- **Cert/PKI engine (`app/cert/`):** `x509_utils.py` wraps the `cryptography`
  library for all key generation, CSR/cert signing, and CRL building;
  `issuance.py` is the single path every issued certificate goes through;
  `crl_manager.py` owns CRL publication and numbering; `renewal.py` runs the
  auto-renewal loop; `scanner.py` runs the active TLS discovery loop;
  `ct_search.py` queries crt.sh/Censys; `alert_conditions.py` declares what a
  rule can watch for and `alert_engine.py` evaluates them;
  `enrollment.py` + `scep_messages.py` back the EST/SCEP endpoints.
- **Auth:** local JWT (bcrypt-hashed passwords) or SAML 2.0 SSO, plus an
  inbound Suite Token path so pktHub can proxy in with users pre-authenticated.

## Requirements

- Python 3.10+ (SCEP additionally needs `asn1crypto` — pure Python, in
  `requirements.txt`; an existing install needs
  `pip install -r requirements.txt` in its venv before SCEP will start)
- Node.js + npm (only needed to build the frontend — see [Frontend Build &
  Deploy](#frontend-build--deploy) if unavailable at install time)
- Ubuntu 22.04/24.04 LTS (install.sh targets apt; other distros need manual
  package installation)

## Installation

See [Quick Start](#quick-start). Every install.sh prompt has an environment
variable override for non-interactive/scripted installs — see the header
comment in `install.sh` for the full list (`PKTCERT_INSTALL_DIR`,
`PKTCERT_PORT`, `PKTCERT_SERVICE_USER`, `PKTCERT_SERVICE_GROUP`).

## Frontend Build & Deploy

```bash
cd frontend
npm install
npm run build
```

`install.sh` does this automatically when `npm` is present. If it isn't,
copy `frontend/dist` into `<install_dir>/frontend/dist` manually and
restart the service.

## Discovery: Scan Targets

A Scan Target is a single host or CIDR range plus a port list. On its own
schedule (or on-demand via "Scan Now"), pktCert opens a TLS connection to
every host:port pair, reads the live certificate (and chain, where the peer
offers one), and adds/updates it in the inventory. A CIDR scan is capped at
4096 addresses per run.

## Discovery: Certificate Transparency Search

Alongside active scanning, pktCert can search Certificate Transparency logs
for certificates matching domains you care about — crt.sh needs no API key;
Censys is optional and requires a personal API ID/Secret pair under
Settings → User Keys. Default scan schedule/ports and CT watched domains
live under Settings → Discovery & Alerts.

## Certificate Inventory

The Certificates page is the unified view of everything pktCert knows
about — scanned, CT-discovered, internally issued, enrolled by a device, or
uploaded from an external CA. Status (valid/expiring/expired/revoked/
superseded) updates automatically as certificates approach or pass their
expiration date.

Revoked certificates are hidden by default — they can't be renewed, don't
expire in any way that matters, and only accumulate. The count of what's
hidden is shown beside the filters; the checkbox brings them back, and
selecting "Revoked" in the status filter shows them regardless.

## Certificate Authorities

Generate a new root (self-signed) or intermediate (signed by a root you
control) CA, or import an existing cert+key pair. Imports are validated —
the key must match the certificate, and the certificate must actually be
usable as a CA. CA private keys are Fernet-encrypted at rest and are **never**
returned by any API response; they're decrypted only in-process, for signing.

CAs can be **constrained** at creation: a path length capping how many CAs may
sit beneath them (intermediates default to 0), and NameConstraints limiting
what names they may certify at all. A CA restricted to `.corp.example.com`
cannot mint a working certificate for anything else even if its key is stolen.

Each CA publishes a CRL at `/crl/{id}.crl` and its certificate at
`/aia/{id}.crt` — both unauthenticated, both referenced by extensions inside
every certificate it issues, so relying parties can check revocation and build
a chain.

Retire a CA by **disabling** it: it stops issuing but keeps publishing its CRL,
because the certificates it already issued are still deployed. Deleting is only
possible for a CA that never issued anything.

## Offline Root CA

The root's private key can stay out of pktCert entirely. Register the root by
**certificate only**, generate an intermediate keypair and CSR here, sign that
CSR on the machine holding the root key, and import the result. Day-to-day
issuance runs off the intermediate, so a compromise of this server costs an
intermediate you can revoke rather than the root every machine trusts.

An offline CA cannot sign — including its own CRL, which is the point.
Revocations under it are published by signing the CRL where the key lives and
uploading it. See
[PKI-and-Discovery.md](docs/PKI-and-Discovery.md#offline-root).

## Issuance Templates

A template defines what a newly issued certificate looks like: key
algorithm/size, validity period, and the key usage / extended key usage
extensions written into it. Pick one whenever issuing a certificate or
signing an uploaded CSR.

## Issuing & Revoking Certificates

From the Certificates page, "+ Issue Certificate" generates a keypair
server-side, builds a CSR, and signs it with the selected CA/template — the
private key is shown once at issuance for you to copy, then stored
encrypted for later download. Signing an externally-generated CSR (so the
private key never leaves the requester's machine) is available via the API
(`POST /api/certificates/csr`). Revoking a certificate is terminal, marks it
in the inventory, and includes it in its CA's next CRL.

## Renewal

`POST /api/certificates/{id}/renew` reissues the same subject and SANs from
the same CA and template, always with a **fresh keypair** — re-certifying the
old public key would carry any compromise of it into the replacement.

The previous certificate is marked **superseded**, not revoked: it stays valid
so the running service keeps working until someone installs the replacement,
and stops raising expiry alerts because that replacement already exists.

Auto-renewal is opt-in per certificate with its own window. It does not
install anything — it removes the "nobody noticed" failure, not the deployment
step.

## Separation of Duties

Optional and **off by default**. When enabled per action (Settings → Cert
Settings), issuing or revoking records a request instead of acting, and a
*different* admin approves it — the approval is what performs the operation.
Self-approval is refused, so a single-admin install should leave this off; the
Approvals page detects that case and says so.

## Device Enrolment (EST and SCEP)

Devices request their own certificates over EST (RFC 7030) at
`/.well-known/est/{cacerts,simpleenroll,simplereenroll,csrattrs}` — the device
generates its own key and pktCert never sees it.

Authorisation is an **enrolment profile**: a shared secret bound to one CA and
one template, optionally restricted to a name suffix and a maximum number of
certificates. Managed under Settings → Enrolment; the secret is shown once and
encrypted at rest thereafter.

EST requires TLS, and enrolment over plain HTTP is refused — the request
carries a secret that yields a trusted certificate.

**SCEP** (RFC 8894) is served at `/scep` for the hardware that doesn't speak
EST — which is most network equipment: Cisco IOS and ASA, Juniper, Palo Alto,
Fortinet, and MDM platforms pushing certificates to laptops and phones. A
device authenticates with the profile secret as its *challenge password*;
there is no username. SCEP does not require TLS, because its request body is
already encrypted to the CA's public key.

SCEP failures are returned as signed CertRep messages with a `pkiStatus` and
`failInfo`, not as HTTP errors — a device that receives a bare 403 with no
CertRep typically retries forever.

### Passphrase-protecting the private key

The issue dialog has an optional **"Protect the private key with a
passphrase"** checkbox. Tick it and enter (plus confirm) a passphrase, and
the private key PEM that pktCert hands back — and stores for later
download — is itself encrypted with it (PKCS#8, `BestAvailableEncryption`).
Anything that installs the key afterwards, e.g. a web server loading it at
startup, must supply that passphrase.

**pktCert never stores the passphrase.** It records only a
`key_encrypted` flag so the UI can badge the certificate (🔒 next to the
key algorithm on the detail view, and a warning on the issuance result).
If the passphrase is lost, the key cannot be recovered — reissue instead.

This is independent of the Fernet encryption at rest that protects
*every* stored private key: that one is always on and is transparent to
you, whereas this passphrase travels with the exported PEM. Over the API,
pass `key_passphrase` in the `POST /api/certificates/issue` body; omit it
(or send an empty string) for an unencrypted key, which stays the default.

## External Certificates & Secret Storage

Certificates issued by an outside CA (purchased, Let's Encrypt, etc.) can
be uploaded directly — "+ Upload External Certificate" on the Certificates
page accepts either separate PEM cert/key files or a single PKCS#12
(.pfx/.p12) bundle, plus an optional free-text **install/use passcode**
(e.g. a PFX export password, or a note ops needs to install the cert).

Both the private key and the passcode are Fernet-encrypted at rest and are
**never** returned by a plain `GET` — reading either one requires
`POST /api/certificates/{id}/reveal-secret` with your *current* password
re-entered (step-up re-auth), and every successful reveal is written to
the audit log (`cert_events`). This bar applies equally to internally
issued certificates and externally uploaded ones — there's one security
model for every stored secret, not a weaker one for uploads.

## Settings Layout

Settings is organized into two **sections**, chosen from a section bar
above the tab bar:

| Section | Tabs |
|---|---|
| **pktCert** | Cert Settings · Cert Keys · Templates · Discovery & Alerts |

Common holds the settings identical across every pkt* app; pktCert holds
this app's own. Selecting a section swaps the tab bar beneath it, so only
one group's tabs is visible at a time — these previously shared a single
long row separated by a thin divider. Deep links such as
`/settings?tab=certsettings` (where the CRL base URL lives) still work and
select the section automatically.

---

## Configuration Reference

See `config.example.yaml` for every startup/infrastructure setting
(host/port, JWT secret, `credential_key` for encryption at rest, CORS,
logging, SSL directory). Everything else (scan defaults, CA/template/alert
data) lives in the app itself, editable from the UI.

**`cors_origins` fails closed.** With nothing configured, pktCert allows
*no* cross-origin requests rather than defaulting to `*`. The SPA is
served same-origin so it is unaffected; the old `*` default combined with
credentialed requests would have let any site call the API with a
logged-in user's cookies. `config.example.yaml` ships a scoped origin and
`install.sh` substitutes your real one — if you're calling the API from a
genuinely different origin, list it there explicitly.

## Running & Managing the Service

```bash
sudo systemctl status pktcert
sudo systemctl restart pktcert
sudo journalctl -u pktcert -f
```

## Roles & Auth

Three roles: `admin` (full access, including CA/PKI issuance and
revocation), `analyst` (manage Scan Targets, ack/resolve alerts),
`viewer` (read-only). Local accounts or SAML 2.0 SSO — see Settings →
Security → Auth.

**Password policy.** Local passwords must be at least 8 characters. The
rule is enforced identically on every path that sets one — admin creating
a user, admin editing a user, admin resetting a password, and a user
changing their own — from a single `password_problem()` check in
`app/auth/local.py`.

**Login throttling.** Five failed attempts for the same
(client IP, username) pair within a rolling 5-minute window start
returning `429 Too Many Requests` until the window clears; a successful
login resets the counter immediately. bcrypt is deliberately slow, but on
its own it doesn't stop a patient guessing loop. The counter is
process-local (pktCert runs `workers=1`, so one process sees every
attempt) and resets on restart — it's a speed bump against password
spraying, not a substitute for an edge WAF or fail2ban.

## Alerting

Fifteen conditions, each with its own parameters, so the limits are yours
rather than ones baked into the code: expiry windows, minimum key sizes,
which signature algorithms count as broken, how long a validity period is too
long — plus self-signed, wildcard, unknown-issuer, newly-discovered,
certificate-changed-on-a-host, stale CRL, and repeated enrolment failures.
Conditions are declared in `app/cert/alert_conditions.py` and the Alerts page
renders its parameter inputs from that declaration, so a new condition needs
no frontend change. Full table in
[PKI-and-Discovery.md](docs/PKI-and-Discovery.md#alerting-conditions-parameters-and-scope).

Rules also take a **scope** — one CA, one source, a name or host pattern.
Empty means everything.

**Repeat behaviour.** An alert stays quiet while it is open and untouched.
Acknowledging or resolving dismisses it, and a dismissed alert whose cause is
still present raises again on the next evaluation — clearing the board must
not silence a live problem. Fix the underlying issue and nothing re-fires; the
open event auto-resolves instead. Revocation is the exception: it records
something that already happened, so acknowledging one is final.

Notification channels are per rule: in-app, email, Slack, PagerDuty, webhook,
TraceCat. Anything other than in-app must be configured under
Settings → Notifications first; a rule targeting an unconfigured channel is
recorded as *skipped* rather than failed.

## Suite Integration

Settings → Security → Suite Integration covers both directions: the
inbound Suite Token pktHub uses to proxy into pktCert with users already
signed in, and outbound **Sibling pkt Apps** connections (named, reusable
— e.g. pktIPAM, to resolve a scanned certificate's host against pktIPAM's
internal address inventory over the same authenticated channel).

**Outbound TLS verification is per-connection and on by default.** Each
sibling connection carries a `verify_tls` flag (added by migration `005`,
defaulting to `1`). A suite token is a full-access credential, so pktCert
verifies the target's certificate before sending it — previously every
outbound suite call passed `verify=False` unconditionally, which made
those tokens interceptable on the wire. If one internal app genuinely
serves a self-signed certificate, turn verification off for *that*
connection alone rather than globally; the better fix is to issue that app
a certificate from one of your own CAs here and leave verification on.

## User Keys & IP Lookup

Settings → User Keys holds per-user, personal (never shared, never
admin-visible) API keys for two things: the suite-wide IP Lookup provider
set (AbuseIPDB, ipinfo.io, ipapi.is, MXToolbox, IPQualityScore — the same
providers every pkt* app exposes, for looking up any IP that shows up in
the data, e.g. a scanned certificate's host) and **Censys**, a
pktCert-specific provider for Certificate Transparency / cert search
(entered as `api_id:api_secret`). crt.sh needs no key and is used
automatically wherever CT search runs.

## pktHub NOC Widgets

pktCert exposes three widgets for pktHub's NOC Builder dashboards:
Certificate Summary (status tile counts), Expiring Certificates (soonest
first), and Active Alerts — see `GET /api/widgets/manifest`.

## Backup & Restore

Settings → Data → Backups covers scheduled/manual snapshots and full
export/import bundles (SQLite database + `config.yaml`).

### Backup integrity

Database snapshots are taken through SQLite's own online-backup API and then
verified with `PRAGMA integrity_check`; a snapshot that does not pass is logged
loudly and not counted as usable.

This matters more than it sounds. The database runs in WAL mode, so at any
instant the committed state is split between the `.db` file and its `-wal`
sidecar. The previous implementation copied the `.db` alone with `shutil.copy2`,
which captures neither a consistent snapshot nor the most recent commits — the
worst possible failure mode for the one artifact you reach for in an emergency,
because it looks like a backup either way.


## Troubleshooting

Check `sudo journalctl -u pktcert -f` for startup errors. A blank page after
install usually means the frontend wasn't built — see [Frontend Build &
Deploy](#frontend-build--deploy).

## Development

Run the backend directly against a local `config.yaml`:

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
PKTCERT_CONFIG=./config.yaml uvicorn app.main:app --reload --port 8763
```

Run the frontend dev server separately with `npm run dev` inside
`frontend/` (proxy `/api` to the backend port in `vite.config.ts`).

### Tests

Each suite runs against the real routes in a throwaway temp database. No test
framework needed; they use only what `requirements.txt` installs.

```bash
python3 tests/test_pki_correctness.py
```

```bash
python3 tests/test_alert_notifications.py
```

```bash
python3 tests/test_renewal.py
```

```bash
python3 tests/test_chain_and_constraints.py
```

```bash
python3 tests/test_ca_lifecycle.py
```

```bash
python3 tests/test_approvals.py
```

```bash
python3 tests/test_offline_root.py
```

```bash
python3 tests/test_est.py
```

```bash
python3 tests/test_scep.py
```

```bash
python3 tests/test_alert_conditions.py
```

```bash
python3 tests/test_export_stepup.py
```

- **test_pki_correctness** — CRL Distribution Points on every issuance path,
  CSR proof-of-possession, CN-in-SAN, RFC 5280 CRL numbering
- **test_alert_notifications** — real delivery to a live HTTP receiver,
  delivery logging, no re-notification while an event stays open
- **test_renewal** — subject/SAN preservation, fresh keys, supersede-not-revoke,
  and the auto-renewal window
- **test_chain_and_constraints** — AIA chain building, CA path length and name
  constraints, RFC 5280 revocation reason codes
- **test_ca_lifecycle** — CA import validation (key/cert pairing, CA-ness,
  encrypted keys) and disable-rather-than-delete retirement
- **test_approvals** — separation of duties: off-by-default behaviour, the
  two-person rule, and that approval is what performs the operation
- **test_offline_root** — the whole offline ceremony, with the root key held
  only in the test and never given to the app
- **test_est** — RFC 7030 enrolment: PKCS#7 responses, profile policy, secret rotation
- **test_scep** — RFC 8894 enrolment driven by a real SCEP client built in the test
- **test_alert_conditions** — that a parameter changes the outcome and a scope
  genuinely narrows, plus that pre-parameter rules keep working
- **test_export_stepup** — password re-entry before the backup bundle downloads

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Known Gaps / Fast-Follow Work

- No ACME protocol server (RFC 8555) — issuance is UI/API-driven, or via
  EST/SCEP for devices.
- No OCSP responder — revocation status is only available via CRL.
- CA private keys for online CAs are encrypted at rest with a key in
  `config.yaml` on the same host; no PKCS#11/HSM support. An offline root
  (key held outside pktCert entirely) is supported — see the PKI reference.
- No hardware-backed key storage; see PKCS#11/HSM below.
- The audit trail (`cert_events`) is ordinary mutable rows, not tamper-evident,
  and has no SIEM/syslog export.
- Templates enforce no policy ceiling — no maximum validity, no allowed-domain
  restriction, no CAA check, no certificate linting on issuance.
- No PKCS#12 export (import works); PEM only.
- Discovery records what a certificate is but grades nothing — no chain-validity,
  hostname-match, weak-key or weak-signature verdict — and doesn't cover
  STARTTLS protocols or filesystem/keystore certificate stores.
- Censys is the only optional CT-search provider beyond crt.sh, and CT search is
  a one-shot lookup rather than continuous monitoring for unauthorised issuance.

## Resonance (embedded assistant)

Resonance is the suite's shared assistant. It mounts as a launcher in the bottom corner of every
authenticated page, but the assistant itself runs on the resonance server, not inside pktCert.
Configure it under **Settings → Resonance** (admin only); every field ships blank, so a fresh
install shows nothing until it is pointed at a resonance server of its own.

`app/integrations/resonance/` and `frontend/src/resonance/` are **vendored** — copied between
pkt\\* apps byte-for-byte except for `APP_SLUG`. They are deliberately not a published package,
because `install.sh` builds a venv on customer hosts and a private index would put a credentialed
network dependency in the middle of every install. pktLog is the reference implementation.

```
browser                 pktCert                       resonance
embed.js  ──GET──▶  /api/resonance/code  ──POST──▶  /embed/session
          ◀─code──                        ◀─code───
frame ──────────────────────────────────────────────▶  /embed?c=<code>
```

pktCert vouches for whoever is signed in and receives a short-lived, single-use code. The key is
encrypted at rest, never reaches the browser, and resonance never sees a pktCert credential.
`GET /api/resonance/code` is the one cookie-authenticated route in the app — `embed.js` fetches it
itself, outside the SPA, and the access token lives in memory — so `Sec-Fetch-Site` and `Origin`
are both checked before the cookie is honoured.

**The data surface.** Two documents let resonance discover what it may call, both public because
they carry names rather than data:

| path | what it is |
|---|---|
| `/.well-known/resonance.json` | the grant — the operations this install permits |
| `/api/resonance/openapi.json` | those operations' OpenAPI, narrowed from the app's own |
| `/api/resonance/docs` | the shipped guides, for resonance to ingest (suite token or admin) |

Point resonance's **READ SPEC** at `/api/resonance/openapi.json`. The published operations are:

- `listCertificates`
- `getCertificate`
- `listCertificateAuthorities`
- `getCertificateSummary`
- `listCertRequests`
- `listAlertEvents`
- `listAlertRules`
- `searchApplicationLog`
- `ackAlertEvent`  *(writes)*
- `ackAllAlertEvents`  *(writes)*
- `toggleAlertRule`  *(writes)*

Every call is made by pktCert's own page, same-origin, on the session of the person already signed
in, so nothing here reaches data that person could not already open. Which operations exist is
fixed in `app/api/resonance_data.py`, not configurable per install. Write operations are withheld
from the grant entirely until an administrator sets a role to **Read and write**.

**Never exposed:** a private key, a passcode, or the PEM of any certificate — key possession is reported as a boolean and nothing more. Nothing here issues a certificate, revokes one, signs a CSR, or creates or edits a CA. **The approval queue is read-only on purpose**: approving a request in pktCert *is* the issuance or the revocation, so that decision stays with a person.

## Log Forwarding

pktCert writes its own application log to the in-app **Logs** page. It can also
ship that log to a syslog collector — normally **pktLog**, which listens on
port `5514` — so this app's events sit alongside the rest of the estate.

Settings keys (Settings → Data → Log Forwarding in apps that expose the UI;
otherwise via `PUT /api/settings`):

| Key | Default | Meaning |
|---|---|---|
| `log_forward_enabled` | `false` | Turn forwarding on |
| `log_forward_host` | `""` | Collector hostname or IP |
| `log_forward_port` | `5514` | pktLog's syslog port |
| `log_forward_protocol` | `udp` | `udp` or `tcp` |
| `log_forward_level` | `INFO` | Minimum level forwarded |
| `log_forward_app_name` | `pktcert` | APP-NAME in the syslog message |

Admin endpoints:

- `GET  /api/system/log-forward/status` — delivery counters (sent, dropped, errors)
- `POST /api/system/log-forward/test` — send one test line without saving settings
- `POST /api/system/log-forward/reload` — apply settings changes without a restart

**Format is RFC 5424, deliberately.** pktLog parses both 3164 and 5424, but
3164 timestamps carry no timezone and the collector has to guess the offset —
which has produced wrong timestamps in this suite before. 5424 carries a full
offset, so there is nothing to guess.

**Delivery is fire-and-forget** on a background thread, with counters. Log
forwarding must never block or crash the thing it observes: a dropped line is a
nuisance, a stalled collector loop is an outage. If the collector is
unreachable, lines are dropped and counted rather than raised.

### If forwarded logs never arrive

**pktLog drops syslog from sources that are not registered.** Its
`collector_registry` gates what is allowed to persist, so the sending host's IP
must be present *and enabled* under pktLog's Settings → Collectors. Until then
the messages are accepted on the wire and silently discarded — the sender sees
a successful send either way, because UDP cannot tell it otherwise. pktLog also
caches that registry for five minutes, so a newly enabled source is not live
immediately.

Use the **Send test message** button (or the `test` endpoint) to confirm the
path end to end rather than assuming it works.

