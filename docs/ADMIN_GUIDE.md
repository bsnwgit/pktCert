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
6. **Set up alert rules** (Alerts → Rules) and notification channels.
7. **Set up backups** (Settings → Data → Backups) and confirm a manual run
   succeeds.
8. **Create accounts** for your team.

## Users & roles

`admin` (full access, including CA/PKI issuance, revocation, secret
reveal, and Settings), `analyst` (manage Scan Targets, ack/resolve
alerts), `viewer` (read-only). Local auth is always available; layer SAML
SSO on top via Settings if needed. When pktHub proxies a request with a
valid suite token, its `X-Suite-Role` header maps directly onto these same
three roles.

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

## Alerting

Five built-in condition types: `cert_expiring`, `cert_expired`,
`cert_revoked`, `ca_expiring`, `scan_target_unreachable`. Create rules
under Alerts → Rules — an inline form, no separate modal. The engine
evaluates every 60 seconds; `cert_expiring`/`ca_expiring` use a
days-before-expiry threshold, the others are boolean conditions. Each rule
has a **cooldown** (minutes, default 15) so a flapping condition doesn't
spam a new event every tick, and per-rule notification channels (`inapp`,
`email`, `webhook`, `slack`). Revocation alerts never auto-resolve.
Resolved alert events are purged automatically after their retention
window (default 90 days, Settings → Data → Storage).

## Backup & Restore

Configure schedule and rotation at Settings → Data → Backups, or trigger
immediately with **Run backup now**. Each snapshot is a timestamped
directory under the configured backup path containing `pktcert.db` +
`config.yaml` — which means CA private keys and every other secret travel
with the backup, encrypted under the same `credential_key` recorded in
that snapshot's `config.yaml`. Treat backup storage with the same care as
the live server.

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

## Troubleshooting

| Symptom | Check |
|---|---|
| Service won't start | `journalctl -u pktcert -n 50`; check `config.yaml` and secret keys |
| A scan target shows `error` | Check `last_error` on the Scan Targets page, or **Scan Now** for the current error |
| Frontend shows `{"detail":"Not Found"}` | Frontend wasn't built — `cd frontend && npm install && npm run build`, then restart |
| A restored `config.yaml` didn't take effect | Restart the service — restoring never does this automatically |
| `reveal-secret` always returns 401 | Caller is suite-proxied (no local password) — log in as a real local admin |

## Upgrading

Pull the latest code, rebuild the frontend if you build manually, then
restart the service. Migrations run automatically on startup.
