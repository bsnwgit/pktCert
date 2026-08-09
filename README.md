# pktCert

<p align="center">
  <img src="lockup-256h.png" alt="pktCert" height="64">
</p>

Enterprise certificate management — part of the pkt suite. Discovers and
inventories TLS certificates across your network (active port scans and
Certificate Transparency log search), tracks expiration, and doubles as an
internal CA/PKI: generate or import root/intermediate CAs, define issuance
templates, issue and revoke certificates, and serve CRLs. Surfaces it
through a React UI with alerting and an in-app AI assistant. Every
page/section has a "?" help button (same pattern across the whole pkt*
suite) with a short in-context explainer — no separate user manual.

**Default port:** `8763` (HTTP)

---

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
- [Issuance Templates](#issuance-templates)
- [Issuing & Revoking Certificates](#issuing--revoking-certificates)
- [Configuration Reference](#configuration-reference)
- [Running & Managing the Service](#running--managing-the-service)
- [Roles & Auth](#roles--auth)
- [AI Assistant](#ai-assistant)
- [Alerting](#alerting)
- [Suite Integration](#suite-integration)
- [Backup & Restore](#backup--restore)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Contributing](#contributing)
- [Known Gaps / Fast-Follow Work](#known-gaps--fast-follow-work)

---

## Quick Start

```bash
git clone git@github.com:bsnwgit/pktcert.git
cd pktcert
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
  `scanner.py` runs the active TLS discovery loop; `ct_search.py` queries
  crt.sh/Censys; `alert_engine.py` evaluates expiry/revocation conditions.
- **Auth:** local JWT (bcrypt-hashed passwords) or SAML 2.0 SSO, plus an
  inbound Suite Token path so pktHub can proxy in with users pre-authenticated.

## Requirements

- Python 3.10+
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
about — scanned, CT-discovered, or internally issued. Status
(valid/expiring/expired/revoked) updates automatically as certificates
approach or pass their expiration date.

## Certificate Authorities

Generate a new root (self-signed) or intermediate (signed by a root you
control) CA, or import an existing cert+key pair. CA private keys are
Fernet-encrypted at rest and are **never** returned by any API response —
they're decrypted only in-process, for signing. Each CA exposes a CRL
endpoint covering its own revoked, internally-issued certificates.

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

## Configuration Reference

See `config.example.yaml` for every startup/infrastructure setting
(host/port, JWT secret, `credential_key` for encryption at rest, CORS,
logging, SSL directory). Everything else (scan defaults, CA/template/alert
data) lives in the app itself, editable from the UI.

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

## AI Assistant

A floating chat panel answers questions about your certificate inventory,
scan results, and CA status. Configure a provider (local/Ollama,
OpenAI-compatible endpoint, Anthropic, or OpenAI) under Settings → Security
→ AI Assistant. Scope-locked to pktCert's own domain — see
`app/api/ai.py` for the guard implementation.

## Alerting

Rules watch certificate/CA expiration windows, revocations, and scan
targets stuck in an error state. See Alerts → Rules to configure
thresholds, severity, and notification channels (in-app, email, webhook,
Slack, PagerDuty, TraceCat).

## Suite Integration

Settings → Security → Suite Integration shows this app's inbound Suite
Token — copy it into pktHub's App Manager when registering pktCert so
pktHub can proxy into it with users already signed in.

## Backup & Restore

Settings → Data → Backups covers scheduled/manual snapshots and full
export/import bundles (SQLite database + `config.yaml`).

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Known Gaps / Fast-Follow Work

- No ACME protocol server (RFC 8555) — issuance is UI/API-driven only.
- No OCSP responder — revocation status is only available via CRL.
- Censys is the only optional CT-search provider beyond crt.sh.
