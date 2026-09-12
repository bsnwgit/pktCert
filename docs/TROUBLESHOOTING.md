# pktCert — Troubleshooting

Symptom, cause, and the command that proves which cause it is.

`<INSTALL_DIR>` is the install directory (`/opt/pktcert` by default).
The PKI model itself is in [PKI-and-Discovery.md](PKI-and-Discovery.md); the
Let's Encrypt / Cloudflare path is in
[LetsEncrypt-Cloudflare.md](LetsEncrypt-Cloudflare.md).

---

## Contents

- [The first five minutes](#the-first-five-minutes)
- [The service will not start](#the-service-will-not-start)
- [The service runs but nothing answers](#the-service-runs-but-nothing-answers)
- [The UI is blank, stale, or 404](#the-ui-is-blank-stale-or-404)
- [Login, accounts and lockout](#login-accounts-and-lockout)
- [Discovery finds nothing](#discovery-finds-nothing)
- [Issuance and approvals](#issuance-and-approvals)
- [ACME](#acme)
- [SCEP](#scep)
- [EST](#est)
- [CRL and AIA](#crl-and-aia)
- [Offline roots](#offline-roots)
- [Renewal and expiry alerts](#renewal-and-expiry-alerts)
- [Suite integration](#suite-integration)
- [A config change did not take effect](#a-config-change-did-not-take-effect)
- [TLS / HTTPS](#tls--https)
- [Backup, upgrades and uninstall](#backup-upgrades-and-uninstall)
- [Running the tests](#running-the-tests)
- [What to capture before reporting a problem](#what-to-capture-before-reporting-a-problem)

---

## The first five minutes

```bash
sudo systemctl status pktcert --no-pager
```

```bash
sudo journalctl -u pktcert -n 100 --no-pager
```

```bash
sudo tail -n 100 <INSTALL_DIR>/logs/pktcert.log
```

```bash
sudo ss -ltnp | grep 8763
```

```bash
curl -s http://127.0.0.1:8763/api/health
```

```bash
curl -s http://127.0.0.1:8763/acme/directory
```

| What you see | Go to |
|---|---|
| `inactive (dead)` or `failed` | [The service will not start](#the-service-will-not-start) |
| Running, nothing on 8763 | [The service runs but nothing answers](#the-service-runs-but-nothing-answers) |
| Health 200, UI blank or 404 | [The UI is blank, stale, or 404](#the-ui-is-blank-stale-or-404) |
| Health 200, no certificates | [Discovery finds nothing](#discovery-finds-nothing) |
| A client cannot enrol | [ACME](#acme), [SCEP](#scep) or [EST](#est) |

ACME, SCEP, EST, CRL and AIA are all served **outside `/api` and outside the
SPA**, at fixed paths their clients are built to expect. A 404 on one of those
is not the same problem as a 404 on the UI.

| Protocol | Path |
|---|---|
| ACME | `/acme/directory` |
| SCEP | `/scep?operation=GetCACaps` |
| EST | `/.well-known/est/cacerts` |
| CRL | `/crl/{ca_id}.crl` |

---

## The service will not start

```bash
sudo journalctl -u pktcert -n 200 --no-pager
sudo tail -n 200 <INSTALL_DIR>/logs/pktcert.log
```

Reproduce in the foreground:

```bash
sudo -u <service-user> \
  PKTCERT_CONFIG=<INSTALL_DIR>/config.yaml \
  PKTCERT_INSTALL_DIR=<INSTALL_DIR> \
  <INSTALL_DIR>/venv/bin/python -m app.server
```

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError` | venv missing packages, or built against a different Python | `<INSTALL_DIR>/venv/bin/pip install -r requirements.txt` |
| `yaml.scanner.ScannerError` | `config.yaml` is not valid YAML | `python3 -c "import yaml; yaml.safe_load(open('<INSTALL_DIR>/config.yaml'))"` |
| Complaint about `secret_key` / `credential_key` | Left at `CHANGE_ME_…` | `openssl rand -hex 32`; and `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `Address already in use` | Something else holds 8763 | `sudo ss -ltnp \| grep 8763` |
| **Fernet `InvalidToken`** | `credential_key` changed | **CA private keys are encrypted with it.** See [A config change did not take effect](#a-config-change-did-not-take-effect) — this is the most serious version of that failure in the whole suite |
| `Permission denied` on DB or logs | Install dir not owned by the service user | `sudo chown -R <service-user>:<service-group> <INSTALL_DIR>` |

`Restart=on-failure`, burst limit 3 in 60s. The unit sets
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, which matters if you move the app to
port 80 or 443 — see [ACME](#acme) for why you might.

---

## The service runs but nothing answers

```bash
sudo ss -ltnp | grep 8763
curl -sv http://127.0.0.1:8763/api/health
```

`host:` and `port:` come from `config.yaml` at every process start — a port
change needs a restart, never a unit edit. Bound to `127.0.0.1` is loopback
only.

Moving the port breaks every enrolled client that holds a URL: ACME directory
URLs, SCEP and EST endpoints, and any CRL distribution point already baked into
issued certificates. **A CRL DP in an issued certificate cannot be changed
retroactively** — plan port and hostname changes before issuing.

---

## The UI is blank, stale, or 404

| Symptom | Cause | Fix |
|---|---|---|
| `{"detail":"Not Found"}` at the root | The frontend was never built | `cd frontend && npm install && npm run build`, then restart. Node.js 20.x LTS is a prerequisite `install.sh` does not install |
| Blank page, console 404s on `/assets/*` | `dist` stale or half-built | Rebuild, then hard-refresh |
| Old UI after an upgrade | Cached `index.html` pinning old bundles | Hard refresh (Ctrl/Cmd-Shift-R) |
| Every API call 401 | Session expired | See [Login, accounts and lockout](#login-accounts-and-lockout) |
| `/acme/...` or `/scep` returns the SPA | Routing regression | Those are mounted outside the SPA catch-all deliberately; if the HTML page comes back instead, the mount order is wrong |

---

## Login, accounts and lockout

bcrypt plus JWT. Roles `admin` / `analyst` / `viewer`.

| Symptom | Cause | Fix |
|---|---|---|
| 401 immediately after logging in | Clock skew invalidates the token's `exp` | `timedatectl`; fix NTP |
| **429 "Too many failed login attempts"** | Five failed attempts for that IP + username within 5 minutes | Wait for the window, or restart the service to reset the counters |
| Password rejected as too short | Minimum 8 characters on every path that sets a password | Use a longer one |
| **`reveal-secret` always returns 401** | The caller arrived suite-proxied and therefore has no local password | Log in as a real local admin on this app |
| Cannot export a private key | Export is step-up authenticated by design | Re-authenticate; do not look for a way around it |
| Locked out of every account | No admin session left | Reset the hash against SQLite using the app's own venv for bcrypt |

```bash
<INSTALL_DIR>/venv/bin/python -c "import bcrypt; print(bcrypt.hashpw(b'NewPassword1!', bcrypt.gensalt()).decode())"
```

---

## Discovery finds nothing

Two independent mechanisms: active port scanning, and Certificate Transparency
log search. They fail for different reasons.

### Active scans

The Scan Targets page carries `last_scan_at`, `last_status` and `last_error`
per target. **Scan Now** (`POST /api/scan-targets/{id}/scan-now`) runs one
immediately and returns the current error.

| Symptom | Cause |
|---|---|
| `last_status: error` | Whatever `last_error` says — work that, not the symptom |
| Scans succeed, nothing found | Nothing is listening on the scanned ports, or a firewall is dropping the probes |
| Only some hosts return certificates | Those are the ones presenting TLS on a scanned port |
| Times out on a large range | Scanning a wide CIDR is slow. Narrow the target |

Prove it outside the app, from the app host:

```bash
openssl s_client -connect <HOST>:443 -servername <HOST> </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
```

If that fails, pktCert cannot see the certificate either — the problem is the
network or the host, not discovery.

### Certificate Transparency search

| Symptom | Cause |
|---|---|
| No CT results | No egress from this host to the CT endpoints |
| No CT results for an internal domain | Correct — internally-issued certificates are not in public CT logs. CT only finds publicly-issued ones |
| Fewer results than expected | CT search is bounded by what the logs return for that domain |

---

## Issuance and approvals

**Issuance runs through an approvals flow.** A certificate that has not appeared
is very often a request sitting unapproved, not a failure.

| Symptom | Cause |
|---|---|
| Requested a certificate, nothing issued | It is awaiting approval — check the Approvals page |
| Cannot issue at all | No active CA with a usable private key, or no template the request matches |
| Issuance rejected on names | A name or path constraint on the CA. That is the constraint doing its job — check the CA's constraints against the requested SANs |
| Issued certificate has the wrong lifetime or key usage | The template, not the request. Templates decide issuance policy |
| An offline root cannot issue | Correct — it holds no private key here. See [Offline roots](#offline-roots) |
| Private key export refuses | Step-up authentication, and passphrase protection if the certificate was issued with it |

Migration `005` added `certificates.key_encrypted`, recording whether an issued
certificate's exported private key is passphrase-protected. Rows predating it
default to `0`, which is accurate — they were issued before the option existed.

---

## ACME

Served at `/acme/...` (RFC 8555), outside `/api` and outside the SPA, so a
client built against Let's Encrypt points at pktCert by changing one directory
URL.

```bash
curl -s http://<APP_SERVER_IP>:8763/acme/directory
```

### EAB is mandatory

The directory advertises `externalAccountRequired: true`. **An account cannot be
created without External Account Binding**, and the EAB binds it to an
enrollment profile. The profile secret is the EAB MAC key, handed to the
operator.

| Symptom | Cause | Fix |
|---|---|---|
| `externalAccountRequired` error on registration | The client sent no EAB | Configure the client with the EAB key ID and MAC key from the enrollment profile |
| EAB verification fails | Wrong MAC key, or the wrong key id | Re-copy both from the profile |
| Client "works with Let's Encrypt" but not here | Public ACME does not require EAB; this does, deliberately — an internal ACME server that signs whatever it is asked is not a CA | Supply the EAB |

Common client flags: `certbot --eab-kid … --eab-hmac-key …`, `acme.sh
--server <directory> --eab-kid … --eab-hmac-key …`.

### Only http-01 is validated

Orders offer `http-01` and `dns-01`. **Only `http-01` is actually validated by
this server.** Answering a `dns-01` challenge returns:

```
<type> is offered but not yet validated by this server; use http-01
```

**Wildcards therefore cannot be issued over ACME today.** A wildcard identifier
can only be proven through DNS, so the order offers `dns-01` alone — and that
challenge cannot complete. This is a current limitation, not a misconfiguration
to hunt.

For a wildcard, issue it through the UI or another enrolment path instead.

### http-01 is fixed at port 80

RFC 8555 §8.3 fixes `http-01` at port 80. Validation fetches
`http://<identifier>/.well-known/acme-challenge/<token>` — **on port 80, not on
pktCert's port**.

| Symptom | Cause |
|---|---|
| Challenge fails, client served the token correctly | Whatever answers port 80 on that identifier is not the client. Check for a reverse proxy or another web server in front |
| Challenge fails on an internal host | pktCert must be able to reach the identifier on port 80. That is an outbound path from *this* server |
| Challenge fails for a name that does not resolve here | The identifier must resolve, from this server, to the host being validated |

### Other ACME failure modes

| Symptom | Cause |
|---|---|
| 405 or "malformed" on a fetch | Resource fetches are **POST-as-GET** — a POST with an empty-string payload, not a GET. A hand-rolled client using GET will fail |
| Replay errors | Nonces are single-use — fetch a fresh one from `HEAD /acme/new-nonce` |
| Order expires before finalize | Orders carry a TTL; restart the order |
| Revocation refused | The account must own the certificate |

---

## SCEP

Served at `/scep` (RFC 8894) — one endpoint distinguished by an `operation`
query parameter, because SCEP was designed for devices with minimal HTTP
stacks.

```bash
curl -s "http://<APP_SERVER_IP>:8763/scep?operation=GetCACaps"
curl -s "http://<APP_SERVER_IP>:8763/scep?operation=GetCACert" -o cacert.der
```

| Operation | Method |
|---|---|
| `GetCACert` | GET |
| `GetCACaps` | GET |
| `PKIOperation` | GET (base64 in the query string) or **POST (binary body — preferred)** |

| Symptom | Cause |
|---|---|
| Device fails with no useful error | SCEP errors are terse by protocol. Read the app log, which has the real reason |
| Enrolment rejected | No matching enrollment profile, or the profile is disabled |
| Very long request fails over GET | Base64 in a query string hits URL length limits. Use POST if the device supports it |
| Device does not trust the issued certificate | It needs the CA from `GetCACert` installed as a trust anchor first |
| Works for one device type, not another | SCEP implementations vary widely — compare what `GetCACaps` advertises against what the device expects |

SCEP exists here because it is what network equipment actually speaks — Cisco
IOS and ASA, Juniper, Palo Alto, Fortinet, and MDM pushing certificates to
laptops and phones. EST is better in every respect where the client supports it.

---

## EST

Served at `/.well-known/est/...` (RFC 7030). The paths are fixed by the RFC —
a device looks there and nowhere else.

```bash
curl -s http://<APP_SERVER_IP>:8763/.well-known/est/cacerts
```

| Operation | Purpose |
|---|---|
| `GET /cacerts` | The CA chain, so a device can install the trust anchor before enrolling |
| `POST /simpleenroll` | PKCS#10 in, certificate out |
| `POST /simplereenroll` | The same, for renewal |
| `GET /csrattrs` | What the server would like to see in a CSR |

Everything is base64 with `Content-Transfer-Encoding: base64` and PKCS#7.

| Symptom | Cause |
|---|---|
| Device rejects the response | It is expecting binary where base64 is sent, or vice versa. Check `Content-Transfer-Encoding` handling on the client |
| `simpleenroll` fails | Bad PKCS#10, or a profile mismatch — the app log has the parse error |
| Renewal fails but enrolment worked | `simplereenroll` authenticates with the existing certificate; if that expired, re-enrol instead |
| Path 404s | The path is fixed by the RFC and must not be rewritten by a reverse proxy |

---

## CRL and AIA

The public CRL is served unauthenticated at `/crl/{ca_id}.crl`.

```bash
curl -s http://<APP_SERVER_IP>:8763/crl/1.crl -o crl.der
openssl crl -inform DER -in crl.der -noout -text | head -20
```

| Symptom | Cause |
|---|---|
| CRL 404s | Wrong `ca_id`, or that CA has never published one |
| CRL is stale | The publication job has not run — check CRL publication settings and the notification/publication log |
| A revoked certificate is still accepted | The relying party cached the old CRL, or is not checking at all |
| Clients cannot fetch the CRL | The CRL distribution point baked into the certificate must be reachable **by the relying party**, not just by you. A DP pointing at an internal address fails for external clients |
| AIA fetch fails | Same class of problem — the URL in the certificate must resolve and be reachable from wherever validation happens |
| An appliance hangs importing a certificate, reporting nothing | `/aia` and `/crl` were reachable by you but answering the appliance with a redirect. Managed mode used to bounce every path it did not explicitly allow, so a client following the AIA URL to build the chain received pktHub's HTML instead of a certificate. QNAP's QTS shows "Applying" and never finishes. Both paths are exempt from the lock now |

Verify the chain endpoints answer a *machine*, not a browser — content type matters
as much as the status:

```bash
curl -s -o /dev/null -w '%{http_code} %{content_type}\n' http://<APP_SERVER_IP>:8763/aia/1.crt
curl -s -o /dev/null -w '%{http_code} %{content_type}\n' http://<APP_SERVER_IP>:8763/crl/1.crl
```

`200 application/pkix-cert` and `200 application/pkix-crl`. A `302` means something
in front is redirecting them, and every certificate naming those URLs is affected —
including ones already issued, which cannot be re-pointed.

The distribution point is written into certificates at issuance. Changing the
app's hostname or port afterwards does not update already-issued certificates.

---

## Offline roots

An offline root is registered **by certificate alone, with no private key on
this server**. The intermediate keypair and CSR are generated here, the CSR is
taken to the offline machine and signed there, and the signed certificate comes
back.

| Symptom | Cause |
|---|---|
| The root cannot sign anything | Correct, and the entire point — it holds no key here |
| Lost the pending intermediate's CSR | Re-download it; the pending intermediate keeps it |
| The returned certificate is rejected on upload | It must match the pending intermediate's key and be signed by the registered root |
| **Revocation under an offline root does not publish a CRL** | An offline CA cannot sign its own CRL here. Revocations under an offline root are published by a different route — check the CA's CRL settings rather than waiting for one to appear |

---

## Renewal and expiry alerts

| Symptom | Cause |
|---|---|
| Certificates not auto-renewing | Renewal is per-certificate; check it is enabled on that one |
| Renewal fails | Whatever issuance would fail with — CA availability, template match, approvals |
| No expiry warnings | Notification channels, or the alert thresholds. Senders never raise, so a broken channel is silent |
| Warnings for certificates you do not care about | Discovery inventories everything it finds; scope the scan targets |

---

## Suite integration

| Symptom | Cause |
|---|---|
| **A sibling app's health check fails with a TLS error** | Since migration `005`, `integrations.verify_tls` defaults to `1` (verify). A sibling serving a self-signed certificate that used to work will start failing after that upgrade | 
| | Fix the sibling's certificate, or clear **verify TLS** for just that connection |
| Suite-proxied user cannot reveal a secret or download | The step-up password is checked against the local pktCert account whose username matches the one pktHub sends. Create a local account of that name — the password is then theirs, and the check means what it means on a direct login. Without one, the error says so rather than reporting the password as wrong |
| Downloading through pktHub reloads the frame into a second sidebar | Fixed. A failed step-up used to be read as an expired session, and the redirect to `/login` navigated the iframe and dropped `?chromeless=1` |
| Everything broke after rotating a token | The suite token is shared; every consumer needs updating |

---

## A config change did not take effect

**Wrong file.** Env vars beat `config.yaml` silently:

```bash
systemctl show pktcert -p Environment
```

**Not restarted.** Nothing in `config.yaml` is re-read live, and restoring a
backed-up `config.yaml` never restarts the service.

**The setting is not in `config.yaml`.** That file holds startup and
infrastructure only — host, port, workers, secrets, paths, `ssl_dir`. Scan
targets, certificate authorities, templates, enrollment profiles, approvals and
alert rules all live in **SQLite** and are managed in the UI.

### `credential_key` changed or was lost

This is more serious here than anywhere else in the suite: **CA private keys are
encrypted with `credential_key`.** Lose it and the CA cannot sign — not the
certificates it issued, not its CRLs, nothing. There is no recovery path that
does not involve the old key.

Restore the old key. If it is genuinely gone, the CA must be replaced and
everything it issued re-issued. This is why `uninstall.sh` keeps `config.yaml`
by default, and why `config.yaml` is worth backing up separately and securely.

---

## TLS / HTTPS

`ssl_dir` defaults to `<INSTALL_DIR>/ssl`.

| Symptom | Cause | Fix |
|---|---|---|
| Still HTTP after uploading a cert | Not restarted | Restart |
| Will not start after upload | Key does not match the cert | Compare `openssl x509 -noout -modulus -in cert.pem \| openssl md5` with `openssl rsa -noout -modulus -in key.pem \| openssl md5` |
| **PFX upload fails: "Could not parse PKCS#12 bundle"** | Wrong passphrase, or a corrupt/unsupported bundle | The bundle is parsed in-process rather than shelled out to `openssl`, so the error is the parser's — not a missing binary |
| Enrolment clients break after enabling HTTPS | They hold the old scheme in their configured URL | Update every client's directory/endpoint URL |
| **An appliance refuses the private key, or imports it and stays on HTTP** | It reads only the traditional key format. pktCert writes PKCS#8 — `BEGIN PRIVATE KEY` — which is right nearly everywhere; some appliances want PKCS#1, `BEGIN RSA PRIVATE KEY`, and decline the other without saying so | Use **Download Private Key (PKCS#1)** on the certificate. Converting by hand needs `openssl rsa -in key.pem -out key-pkcs1.pem -traditional` — without `-traditional`, OpenSSL 3 writes PKCS#8 straight back out and the file only looks converted |
| The browser still shows the old certificate after swapping it | A resumed TLS session, not a bad certificate | Quit the browser fully, or use a private window. `openssl s_client -connect host:443 -servername host` opens a fresh connection and shows what is genuinely being served |

```bash
curl -k https://127.0.0.1:8763/api/health
```

---

## Backup, upgrades and uninstall

**Back up `config.yaml` separately and securely.** It holds `credential_key`,
without which the CA keys in the database are useless. A database backup alone
is not a recoverable backup of a CA.

Backups write timestamped `backup_*` directories. A restored `config.yaml` never
restarts the service. **Never copy a live SQLite database with `cp`** — take
`pktcert.db`, `-wal` and `-shm` with the service stopped.

Upgrade:

```bash
git pull
cd frontend && npm install && npm run build && cd ..
sudo systemctl restart pktcert
```

Migrations run on startup and are tracked in `_migrations`. Notable ones:

- `005` — adds `certificates.key_encrypted` and `integrations.verify_tls`. Both
  additive with safe defaults, but `verify_tls` defaulting to on changes
  behaviour for self-signed siblings.

Re-running `install.sh` is better when a release drops or renames a file; data
is kept, and `PKTCERT_REMOVE_EXISTING=1` (or `0`) answers its prompt from a
script.

Uninstall:

```bash
bash <INSTALL_DIR>/uninstall.sh
```

Data is kept by default — `config.yaml`, `pktcert.db` and its `-wal`/`-shm`,
`logs/`, `backups/` and `ssl/`. `--purge` deletes them and **destroys the CA**;
it is not recoverable. `--dry-run` prints what would go; `--yes` skips prompts;
`--dir PATH` if the unit is already gone.

**Never mirror over an install directory with `rsync --delete`.**

---

## Running the tests

This project has real tests, and they are worth running before believing a fix.

They are standalone scripts, not pytest cases: each writes its own `config.yaml`
to a temp directory and sets `PKTCERT_CONFIG` / `PKTCERT_INSTALL_DIR` before
importing the app. That is what keeps a run off the live database — and it is
why they cannot share a process. Under `pytest` the first module's config wins
and collection dies in `seed_admin`.

From the repo root, each in its own process:

```bash
for f in tests/*.py; do python3 "$f" || echo "FAILED: $f"; done
```

A single one:

```bash
python3 tests/test_chain_and_constraints.py
```

Exit status is the result; a pass prints its own summary.

Coverage includes chain and constraint validation, offline root handling,
renewal, EST enrolment and step-up-authenticated export. **A change that makes
those pass by relaxing an assertion is a regression, not a fix.**

---

## What to capture before reporting a problem

1. `VERSION`, and how it was installed.
2. `systemctl status pktcert` plus the last 200 lines of **both** the journal and
   `logs/pktcert.log`.
3. `config.yaml` **with `secret_key`, `credential_key` and passwords removed** —
   never paste `credential_key` anywhere.
4. Which path is failing: the UI, `/api`, `/acme`, `/scep`, `/.well-known/est`
   or `/crl`. They are separate mounts with separate failure modes.
5. For discovery: the target's `last_error`, and whether
   `openssl s_client` reaches the host from this server.
6. For ACME: the client, whether EAB is configured, and whether the identifier
   is a wildcard.
7. For SCEP or EST: the device model, and the app log around the attempt — the
   protocol-level error the device shows is usually useless on its own.

Never paste private keys, `credential_key`, EAB MAC keys, or an unredacted
`config.yaml`.
