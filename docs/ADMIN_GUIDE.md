# pktCert — Administrator Guide

Covers installing, configuring, and operating pktCert. For day-to-day
usage (Certificates, Scan Targets, CAs, Alerts), see
[USER_GUIDE.md](USER_GUIDE.md). See the [README](../README.md) for the
full technical reference and
[docs/PKI-and-Discovery.md](PKI-and-Discovery.md) for CA/template/CSR/CT
search details.

## Installation

```bash
git clone git@github.com:bsnwgit/pktCert.git
cd pktCert
bash install.sh
```

Prompts for install directory and port, handles the venv, `config.yaml` +
secret keys, DB migrations, admin user, frontend build, and systemd
service. Open the app port in your firewall and log in with the printed
admin credentials — they're shown once, at the end of the installer's
output, and are not recoverable afterward (see
[Lost admin password](#lost-admin-password) below if that happens).

## First-time setup checklist

1. **Change the admin password.**
2. **Generate or import a root CA** (Certificate Authorities → + Add CA)
   if you plan to issue certificates internally.
3. **Create an issuance template** (Templates) — a default one is seeded
   automatically (RSA-2048, 1 year, server auth), add more as needed.
4. **Add Scan Targets** for hosts/ranges you want discovered automatically.
5. **Set discovery defaults** (Settings → Discovery & Alerts) — default
   scan schedule/ports, CT auto-discovery watched domains, expiry warning
   threshold.
6. **Set the CRL base URL** (Settings → Cert Settings) *before* issuing
   anything you want revocation-checkable — it's baked into each certificate
   at issuance, so changing it later has no effect on certificates already
   signed.
7. **Set up alert rules** (Alerts → Rules) and notification channels. Note
   that channels other than in-app must be configured under
   Settings → Notifications first.
8. **Set up backups** (Settings → Data → Backups) and confirm a manual run
   succeeds — and back up `config.yaml` separately, since snapshots
   deliberately exclude it (see [Backup & Restore](#backup--restore)).
9. **Create accounts** for your team.

## Finding your way around Settings

Settings has a section bar above its tab bar with two buttons:

- **pktCert** — Cert Settings, Cert Keys, Templates, Enrolment, Discovery & Alerts. This app's own.

Only the selected section's tabs appear in the row below, so switch sections if a tab isn't where you expect it; they previously shared a single row split by a thin divider. Deep links to a specific tab select the right section automatically.

## Users & roles

`admin` (full access, including CA/PKI issuance, revocation, secret
reveal, and Settings), `analyst` (manage Scan Targets, ack/resolve
alerts), `viewer` (read-only). Local auth is always available; layer SAML
SSO on top via Settings if needed. When pktHub proxies a request with a
valid suite token, its `X-Suite-Role` header maps directly onto these same
three roles.

### Password policy and login throttling

Local passwords must be **at least 8 characters**, enforced identically
whether an admin creates a user, edits one, resets a password, or a user
changes their own.

Five failed logins for the same (client IP, username) pair inside a
rolling 5-minute window return **429 Too Many Requests** until the window
clears; one successful login resets the counter. This is a speed bump
against password spraying and credential stuffing — it's process-local
and resets when the service restarts, so keep your usual edge protections
(WAF, fail2ban, network ACLs) in place rather than relying on it alone.
Note that a user who genuinely forgot their password can lock themselves
out for a few minutes; that's expected, and waiting clears it.

## Secret storage & step-up re-auth

Every private key and install passcode (CA keys, issued-certificate keys,
externally-uploaded keys/passcodes) is Fernet-encrypted at rest using
`credential_key` from `config.yaml` — generated once by `install.sh`, back
it up along with your database backups; losing it makes every stored
secret permanently unrecoverable.

No secret is ever returned by a plain `GET`. Reading a private key or
passcode requires `POST /api/certificates/{id}/reveal-secret` with the
caller's *current* password re-entered, and every successful reveal is
logged to `cert_events`. Suite-proxied requests (`X-Suite-Token`, no local
password) can never complete this — they must log in as a real local
admin to reveal a secret.

## Discovery engine

**Scan Targets** run on their own schedule via a background loop
(`app/cert/scanner.py`, ~30s tick) that checks which targets are due, and
the same code path is used for the manual "Scan Now" button. A CIDR
target is capped at 4096 expanded addresses per run.

**Certificate Transparency search** (`app/cert/ct_search.py`) queries
crt.sh (no key needed) and, if a key is set under Settings → User Keys,
Censys. See [PKI-and-Discovery.md](PKI-and-Discovery.md) for details on
what's normalized into the inventory from each source.

## CA / PKI issuance

Root and intermediate CAs, issuance templates, direct issuance, and CSR
signing are all covered in depth in
[PKI-and-Discovery.md](PKI-and-Discovery.md). The short version:
`app/cert/x509_utils.py` wraps the `cryptography` library for every
signing operation — no external `openssl` process dependency.

## Renewal

`app/cert/renewal.py` runs every 10 minutes and reissues any certificate
opted into auto-renewal that has entered its window. Manual renewal is the
same code path, so an auto-renewed certificate is indistinguishable from a
hand-issued one.

**It installs nothing.** The new certificate and its freshly generated key are
stored here; putting them on the server that serves them is still a human step
or a job for whatever configuration management runs that host. Auto-renewal
removes the "nobody noticed it was expiring" failure, not the deployment step
— which is why it's opt-in per certificate rather than a global default.

Renewal marks the previous certificate `superseded` rather than revoking it,
so the running service survives until the replacement is installed. Revoke the
old one yourself once it is.

The loop skips certificates whose CA is disabled, offline, or still awaiting
its signed certificate, and anything whose template has since been deleted —
those need a human decision rather than a silent guess.

## Offline root CA

The root's private key can stay entirely outside pktCert. Register the root by
certificate alone (Certificate Authorities → + Add CA → **Offline Root**),
generate an intermediate CSR here, sign it on the machine holding the root
key, and import the result. Full procedure in
[PKI-and-Discovery.md](PKI-and-Discovery.md#offline-root).

Two operational consequences worth knowing before you commit to it:

- An offline CA **cannot sign its own CRL**. Revocations under it are published
  by signing the CRL on the machine that holds the key and uploading it
  (**Publish CRL**). Until one is uploaded, that CA's distribution point
  returns 404 — which to a relying party reads as "no CRL published here".
- An intermediate sits in `pending_signature` and can issue nothing until its
  signed certificate comes back. Its CSR can be re-downloaded for as long as
  it's pending, because the round trip to an air-gapped machine is rarely done
  in one sitting and regenerating would produce a different key.

## Approvals (separation of duties)

Off by default, and off means genuinely unchanged — issuing and revoking stay
immediate. Turn either on under Settings → Cert Settings and the operation
records a request on the Approvals page instead, for a **different** admin to
approve.

Nobody can approve their own request. That has a practical consequence worth
knowing before you switch it on: **an install with one admin account cannot
approve anything**. The Approvals page detects that and says so.

## Device enrolment (EST and SCEP)

Settings → Enrolment manages the profiles devices authenticate with. A profile
is a shared secret bound to one CA and one template, optionally limited to a
name suffix and a certificate count.

The secret is a bearer credential — anything holding it gets a certificate —
so keep profiles narrow and rotate on suspicion. Rotation is instant and
one-click; every device on the old secret stops enrolling.

**EST requires TLS.** The request carries a secret that yields a trusted
certificate, so over plain HTTP that secret belongs to anyone on the path.
pktCert refuses enrolment over non-TLS connections. `X-Forwarded-Proto` is
honoured when TLS terminates at a reverse proxy. For an isolated lab network
where you accept the risk, set `est_allow_insecure_http`.

**SCEP** (RFC 8894) is at `/scep`, for equipment that doesn't speak EST — most
network hardware, and every MDM. Set the profile's protocol to `scep`; the
device uses the profile secret as its *challenge password* and there is no
username. SCEP does **not** require TLS: its request body is already encrypted
to the CA's public key, so the challenge password isn't exposed the way an EST
secret over plain HTTP would be.

SCEP needs an RSA CA — its envelope uses RSA key transport, so a profile
pointing at an EC CA cannot complete an enrolment.

SCEP support adds one dependency, `asn1crypto` (pure Python, no compiled
extensions). It's in `requirements.txt`; an existing install needs
`pip install -r requirements.txt` inside its venv before SCEP will start.

## Alerting

Fifteen condition types, each with its own settings — expiry windows,
minimum key sizes, which signature algorithms count as broken, how long a
validity period is too long. The full table is in
[PKI-and-Discovery.md](PKI-and-Discovery.md#alerting-conditions-parameters-and-scope);
they're declared in `app/cert/alert_conditions.py`, and the Alerts page
renders its parameter inputs from that declaration, so adding a condition
there needs no frontend change.

Rules also take a **scope** — one CA, one source, a name or host pattern.
Empty means everything. Narrow rules are the ones that get acted on.

Create rules under Alerts → Rules (an inline form, no modal). The engine
evaluates every 60 seconds. Each rule has per-rule notification channels:
`inapp`, `email`, `slack`, `pagerduty`, `webhook`, `tracecat`. Channels other
than in-app must be configured and enabled under Settings → Notifications
first; a rule targeting an unconfigured channel is recorded as *skipped*
rather than failed. Every delivery attempt is recorded in `notification_log`.

### When an alert repeats

An alert stays quiet for as long as it is **open and untouched**, so a
persisting problem doesn't re-notify every minute.

**Acknowledging or resolving dismisses it** — and a dismissed alert whose cause
is still present raises again on the next evaluation. Clearing the board must
not silence a live problem. "Still present" is decided by the condition itself,
so fixing the underlying issue stops it and auto-resolves the open event
instead; nothing re-fires.

A re-raise retires the dismissed event it replaces, so the active list doesn't
accumulate one row per acknowledgement.

**Revocation is the exception.** It records something that already happened and
cannot un-happen, so acknowledging one is final rather than a snooze —
otherwise it would nag forever about something nobody can act on.

There is no cooldown setting. It existed to stop a flapping condition
reopening every tick, and re-alert-on-dismissal makes it self-contradictory:
the two rules disagree about what should happen after a dismissal. It was
removed rather than left as a control that half-worked.

Resolved alert events, and their delivery records, are purged automatically
after their retention window (default 90 days, Settings → Data → Storage).

Rules written before conditions had parameters keep working: the old
`threshold` value is still read as the days figure when a rule carries no
parameter for it.

## Backup & Restore

Configure schedule and rotation at Settings → Data → Backups, or trigger
immediately with **Run backup now**. Each snapshot is a timestamped
directory under the configured backup path containing `pktcert.db` and a
`RESTORE-NOTES.txt`.

**`config.yaml` is deliberately NOT included.** The database holds every CA
private key, encrypted with `credential_key` — and `credential_key` lives in
`config.yaml`. Putting both in one snapshot stores the safe next to its key:
a single stolen or mis-synced backup would yield every CA private key in
plaintext, and backups are exactly the thing that ends up rsynced to a NAS or
copied to a laptop.

**This means you must back up `config.yaml` yourself, and store it somewhere
other than the snapshots.** Without it, the CA private keys in a restored
database cannot be decrypted and are permanently unusable. Back it up once
and after any change — it is small and changes rarely.

Set `backup_include_config` if you would rather have single-directory
restore and accept that the snapshot then contains everything needed to
impersonate your CAs.

The downloadable full bundle (Settings → Data → Backups → export) *does*
include `config.yaml`, because it exists to move a whole installation to a
new host in one step. Its `RESTORE.md` says so prominently: treat that file
as key material, move it to encrypted storage immediately, and delete it once
the restore is done.

**Restoring:**
- Every listed snapshot has a **Restore…** link — restores directly from
  that on-server snapshot, no download/upload needed. Expanding it shows a
  checkbox per file present, so you can restore just `pktcert.db` or just
  `config.yaml` instead of both together.
- A full bundle can also be downloaded/uploaded as a `.tar.gz`, with the
  same per-file selection on upload.
- Restoring a backup requires a manual service restart afterward to pick
  up any restored config.

## Suite Integration

Both directions live on Settings → Security → Suite Integration: the
inbound Suite Token pktHub uses to proxy in, and the multi-instance list
of named sibling-app connections (e.g. pktIPAM, for internal-IP context
on a scanned certificate's host).

Each outbound connection has its own **verify TLS** flag, on by default.
A suite token grants full access to the target app, so pktCert validates
the target's certificate before sending it. Turn verification off only
for a specific internal app that serves a self-signed certificate — and
prefer issuing that app a certificate from one of your CAs here instead,
so you can leave verification on. Existing connections upgraded from
before this flag existed default to verifying; if one of them starts
failing its health check with a TLS error, that's the reason, and the
right fix is a valid certificate on the target rather than switching the
flag off.

## Lost admin password

There's no password-recovery flow in the UI. If the only admin account is
locked out, reset it directly against the database — safe to run against
a live service (SQLite's WAL mode handles the concurrent write fine):

```bash
NEWPASS=$(openssl rand -base64 12 | tr -d '/+=' | head -c 16)
HASH=$(<install_dir>/venv/bin/python3 -c "
import sys; sys.path.insert(0, '<install_dir>')
from app.auth.local import hash_password
print(hash_password('$NEWPASS'))
")
sqlite3 <install_dir>/pktcert.db \
  "UPDATE users SET hashed_password = '$HASH' WHERE username = 'admin';"
```

Takes effect immediately, no restart needed. Log in and change it again
through the normal change-password flow once you're in.

## Resonance (embedded assistant)

Settings → Resonance (admin only). Adds an assistant launcher to the bottom corner of every page. The assistant itself runs on the resonance server; pktCert only decides who may open it.

**Setting it up.** Paste the **interface server** address — not resonance's admin portal, which answers on a different address and serves `embed.js` too, so it looks right until the session call returns "not found" — then the key you were issued. Choose which roles may use it, press **Test Connection**, and only then switch **Enabled** on. Test Connection works whether or not the feature is enabled; always prove a key before putting the widget in front of users. Every field ships blank, so a fresh install shows nothing until it is pointed at a resonance server of its own.

Two things have to line up on the resonance side, and both fail silently when they don't:

- **This install's origin** must be on the key's allow-list. The exact string is shown ready to copy on the same page. Behind a reverse proxy, fill in **pktCert's own address** yourself — what the app detects is the internal address, not the one users type.
- **Speakers Name** must be on for the key. Without it resonance records nothing, so there is no trace of who asked what.

**Reachability, twice over.**

- Resonance must be reachable **from the browser**, over HTTPS, with a certificate those browsers already trust. An untrusted certificate produces an empty widget and nothing in the console to explain it.
- pktCert also calls resonance **server to server**, so this host must resolve resonance's name and trust its certificate — the browser doing both is not enough. Python verifies against its own bundled roots rather than the system store, so a certificate signed by an internal CA is trusted by every browser on the network and still rejected here. Point **CA bundle** at the system store instead (`/etc/ssl/certs/ca-certificates.crt` on Debian and Ubuntu).

**What it can reach.** The certificate inventory, one certificate in full, the internal CAs, the estate summary, the issue and revoke approval queue, alert rules and the alerts they have fired, and pktCert's own diagnostic log. Every call is made by pktCert's own page on the session of whoever is signed in, so it reaches only what that person could already open in the interface. Which operations exist is fixed in the code, not configurable per install — `/.well-known/resonance.json` lists exactly what is on offer, and needs no login to read because it contains names, not data.

**What it can never reach**, at any role level: a private key, a passcode, or the PEM of any certificate. Possession of a key is reported as a yes or no and nothing more. Nothing the assistant can call issues a certificate, revokes one, signs a CSR, or creates or edits a CA. **The approval queue is read-only on purpose** — approving a request in pktCert *is* the issuance or the revocation, performed the moment it is granted, so that decision stays with a person in the interface.

Documentation is published separately at `GET /api/resonance/docs`, to a suite token or an admin session — the guides shipped with the running version, so pointing resonance at it keeps the assistant's knowledge in step with the installed release instead of describing last year's UI.

**What each role can do.** Set per role. *No access* hides the launcher entirely. *Read only* lets the assistant look at the operations above. *Read and write* also lets it act — and adds exactly three things, no more: acknowledge one alert, acknowledge all of them, and switch an existing alert rule on or off. There is no delete of anything and no creating or editing of configuration. Resonance stops and reads the actual values back to the person before it runs any of them.

**A level never exceeds the role.** Two checks have to agree: the level set here, and pktCert's own rule for the thing being done. An analyst on *Read and write* can acknowledge an alert, because analysts may; the same analyst cannot switch a rule, because that is an administrator's to do in the interface too. Setting a level grants nobody a right they did not already have — it decides whether the assistant may use the rights they do.

Where no role is set to *Read and write*, the write operations are withheld from the published grant altogether, so there is nothing at the resonance end that could be turned on. Every write the assistant performs is recorded in the application log with who asked for it.

**Credentials.** pktCert never sends a login to resonance. It vouches for whoever is signed in and gets back a short-lived, single-use code the browser spends on opening the panel. The key is encrypted at rest and never reaches the browser.

**If it never appears.** Diagnostics reports how many users could not load the widget in the last week; the usual causes are an ad blocker, a wrong server address, or resonance being unreachable. Repeated failures pause the integration for a few minutes rather than hammering resonance — the panel says so while it is paused, and a successful Test Connection clears it.

## Troubleshooting

| Symptom | Check |
|---|---|
| Service won't start | `journalctl -u pktcert -n 50`; check `config.yaml` and secret keys |
| A scan target shows `error` | Check `last_error` on the Scan Targets page, or **Scan Now** for the current error |
| Frontend shows `{"detail":"Not Found"}` | Frontend wasn't built — `cd frontend && npm install && npm run build`, then restart |
| A restored `config.yaml` didn't take effect | Restart the service — restoring never does this automatically |
| `reveal-secret` always returns 401 | Caller is suite-proxied (no local password) — log in as a real local admin |
| Login returns 429 "Too many failed login attempts" | Five failed attempts for that IP+username in 5 minutes. Wait for the window to clear, or restart the service to reset the counters |
| Password rejected as too short | Minimum is 8 characters, on every path that sets a password |
| A sibling-app connection's health check fails with a TLS error | That connection now verifies the target's certificate (default on). Fix the target's certificate, or clear **verify TLS** for just that connection |
| Uploading an SSL PFX fails with "Could not parse PKCS#12 bundle" | Wrong passphrase or a corrupt/unsupported bundle. The bundle is now parsed in-process rather than shelled out to `openssl`, so the error is the parser's, not a missing binary |

## Upgrading

Pull the latest code, rebuild the frontend if you build manually, then
restart the service. Migrations run automatically on startup.

Migration `005` adds two columns, both additive with safe defaults, so
no action is needed on upgrade:

- `certificates.key_encrypted` — records whether an issued certificate's
  exported private key is passphrase-protected. Existing rows default to
  `0` (not protected), which is accurate: they were issued before the
  option existed.
- `integrations.verify_tls` — whether outbound suite calls to that
  sibling app verify the target's TLS certificate. Existing rows default
  to `1` (verify). If a sibling app serves a self-signed certificate, its
  health check will start failing after this upgrade — see
  [Suite Integration](#suite-integration) above.
