# Publicly-trusted certificates with Let's Encrypt and Cloudflare

End-to-end setup for pktCert's ACME client: what to collect, where each piece
comes from, and how to prove it works before anything depends on it.

Replace `example.com` with your own domain throughout.

---

## What this gives you

A certificate issued by Let's Encrypt, which every browser and operating system
already trusts. Nothing to install on the machines that connect to it.

This is separate from pktCert's own CA. An internal root cannot be publicly
trusted — that takes a CA/Browser Forum audit programme, not a setting — so
anything the outside world must trust has to be issued from outside.

**The host being certified never needs to be reachable from the internet.**
Validation is `dns-01`: it proves you control the *zone*, not the host. A server
on `10.x` can hold a publicly-trusted certificate perfectly well. That is also
the only way to get a **wildcard**.

---

## Before you start — what to collect

| Piece | Where it comes from | Notes |
|---|---|---|
| A registered domain | Your registrar | Must be real. `.lan`, `.local`, `.internal`, `.home`, `.corp` are refused. |
| The domain's DNS on Cloudflare | Cloudflare dashboard | Nameservers must actually be delegated to Cloudflare. |
| A Cloudflare API token | Cloudflare → My Profile → API Tokens | Scoped `Zone:DNS:Edit`. Created in Part 1. |
| A contact email | You | Where Let's Encrypt warns you if renewal stops. |
| pktCert admin login | You | Everything here is admin-only. |

You do **not** need: a public IP, an open port 80, a reverse proxy, or
`certbot` installed anywhere.

---

## Part 1 — Cloudflare

### 1.1 Confirm the zone is really on Cloudflare

In the Cloudflare dashboard the zone should show **Active**, not "Pending
nameserver update". If it is pending, Cloudflare is not authoritative yet and
no challenge record you write there will be visible to Let's Encrypt.

Check from a terminal:

```bash
dig +short NS example.com
```

The answer must be Cloudflare nameservers.

### 1.2 Create the API token

Cloudflare has two kinds of token and either works:

* **Manage account → Account API tokens** — owned by the account. Preferred for
  a service integration: it keeps working if the person who made it later
  leaves the account.
* **My Profile → API Tokens** — owned by your user, and dies with your access.

Then **Create Token**, and use the **Edit zone DNS** template — it is exactly
the `Zone:DNS:Edit` permission needed, so there is no reason to build a custom
token. If you do go custom, the permission is `Zone` · `DNS` · `Edit`.

Do not use "Global API Key". It authorises everything on the account, it cannot
be scoped, and pktCert deliberately refuses it. A certificate robot has no
business holding account-wide credentials.

Then set:

* **Zone Resources** — `Include` · `Specific zone` · pick your zone.
  Add a row per zone if one certificate will cover names in more than one.
* **TTL** — leave open, or set an expiry and diarise the rotation.
* **Client IP Address Filtering** — optional. If you set it, use the address
  pktCert egresses from, not the address it listens on.

Continue to the summary, create it, then **copy the token now**. Cloudflare
shows it exactly once.

### 1.3 Scope it to every zone the certificate touches

A certificate covering `example.com` and `app.example.net` needs a token with
both zones included. pktCert looks the zone up per name, so a missing zone
fails at lookup with "no Cloudflare zone found", which reads like a
permissions problem and is really a scope problem.

### 1.4 Check CAA, if you have any

CAA records restrict which CAs may issue for your domain. If you have none, any
CA may issue and there is nothing to do.

```bash
dig +short CAA example.com
```

If anything comes back, `letsencrypt.org` must be permitted:

```
0 issue "letsencrypt.org"
```

For wildcards, `issuewild` applies if present. Getting this wrong produces a
CAA failure at validation time, which counts against the failure rate limit.

---

## Part 2 — pktCert: DNS provider

**Settings → Public Certs → DNS provider.**

| Field | Value |
|---|---|
| Label | Anything meaningful — `Cloudflare` |
| Provider | Cloudflare |
| Credential | The token from 1.2 |

**Add provider**, then press **Test**.

Test lists the zones the token can actually reach. Do this before anything
depends on it — a failed button costs nothing, a failed validation costs a
rate-limited attempt at Let's Encrypt.

If Test fails:

| Message | Cause |
|---|---|
| rejected the API token | Wrong token, or it lacks `Zone:DNS:Edit` |
| can reach no zones | Token created with no zone in Zone Resources |
| was unreachable | pktCert has no outbound HTTPS to `api.cloudflare.com` |

The token is encrypted at rest and never returned by the API. It can repoint
your domain, so treat it accordingly.

---

## Part 3 — pktCert: the Let's Encrypt account

**Settings → Public Certs → Certificate authority account.**

| Field | Value |
|---|---|
| Label | `Let's Encrypt staging` |
| Directory | `letsencrypt-staging` |
| Contact email | Yours — this is where expiry warnings go |
| External account binding | Leave blank. Let's Encrypt does not use it. |

**Register account.** pktCert generates an account key, registers it with
Let's Encrypt, and stores the key encrypted. Registering agrees to the CA's
subscriber terms on your behalf.

**Use staging first, and stay there until Part 5 succeeds.** Staging
certificates are *not* trusted — that is the point. Production rate limits
count failures as well as successes, and a lockout is measured in hours to
days.

---

## Part 4 — pktCert: the certificate

**Settings → Public Certs → Managed certificates.**

| Field | Value |
|---|---|
| Label | `Public web` |
| Names | `example.com, www.example.com` |
| Account | The staging account |
| DNS provider | Cloudflare |
| Renew before | `30` days |

Names are comma separated. Some patterns:

* `example.com, www.example.com` — the usual pair.
* `*.internal.example.com` — one wildcard covering every internal service.
  Only possible over DNS, which is what this uses.
* `*.example.com, example.com` — a wildcard does **not** cover the bare
  domain. If you want both, list both.

Thirty days suits a 90-day certificate. If you later move to a short-lived
profile, tighten this — the window has to be wider than your worst-case
outage.

---

## Part 5 — Issue it

Press **Issue now**.

What happens, in order:

1. pktCert asks Let's Encrypt for an order covering your names.
2. For each name it writes `_acme-challenge.<name>` as a TXT record in
   Cloudflare, clearing any stale record already there.
3. It polls public DNS until that record actually resolves — asking the CA to
   look too early spends a rate-limited attempt.
4. It tells Let's Encrypt to validate. Let's Encrypt queries your authoritative
   nameservers directly.
5. On success it generates a key, sends a CSR, collects the certificate, and
   removes the TXT record. The record is removed even if the order fails.

This takes seconds to a couple of minutes, mostly waiting on step 3.

Watch it if you like — the record is short-lived:

```bash
dig +short TXT _acme-challenge.example.com
```

---

## Part 6 — Verify

The certificate appears in **Certificates**, source **Public CA**.

Open it and check the issuer. Staging says something like *(STAGING) Let's
Encrypt* — that is correct, and it is why staging certificates are untrusted.

The inventory row carries the expiry, so the normal expiry alerting applies
from here on with no extra configuration.

---

## Part 7 — Production

Once Part 5 has worked on staging:

1. Register a **second** account, Directory `letsencrypt`, label it clearly.
2. Create a **new** managed certificate against that account, same names.
3. **Issue now.**

Keep the staging account. It is where you test changes to names or providers
without spending production quota.

Production rate limits worth knowing:

| Limit | Value |
|---|---|
| Certificates per registered domain | 50 per week |
| Duplicate certificate (identical name set) | 5 per week |
| Failed validations | 5 per account, per hostname, per hour |
| New orders | 300 per account per 3 hours |

The duplicate limit is the one people hit: pressing **Issue now** repeatedly
with the same names exhausts it in five attempts.

---

## Part 8 — Getting the certificate onto the server

pktCert obtains and stores the certificate. Installing it is still yours — the
same as for internally-issued certificates.

**Certificates → open the certificate.**

* **Download** gives the certificate PEM, or the chain.
* **Reveal secret** gives the private key.

Both require re-entering your current password, both are admin-only, and both
are written to the certificate's event log. Nothing is cached — each download
prompts again.

Install the leaf plus chain and the key wherever they are served, and reload
that service.

---

## Renewal

Automatic, if **auto-renew** is on. pktCert holds the private key for these
certificates — which it does not for ACME enrolment — so it can genuinely
renew them with nobody present.

Renewal runs on the same loop as internal renewal and takes the identical code
path as **Replace now**, so an automatic renewal is not a separate mechanism
with its own failure modes. A failed order backs off for an hour before
retrying, because the failure rate limit is the one that bites.

Each renewal is a new inventory row linked to the one it replaces; the previous
certificate is marked superseded so it stops raising expiry alerts.

**You still have to install the renewed certificate.** Renewal removes the
"nobody noticed it was expiring" failure, not the deployment step.

---

## Revoking

**Revoke** on the managed certificate revokes it at Let's Encrypt and switches
auto-renew off — a revoked certificate that quietly returns an hour later is
not what anyone means by revoking it.

**Delete** only stops managing the name. What was already issued stays valid
and stays in the inventory, because it is deployed somewhere and forgetting
about it here does not untrust it.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `no Cloudflare zone found for '<name>'` | The token's Zone Resources don't include that zone, or the zone isn't on this Cloudflare account |
| `the TXT record did not become visible within 120s` | Nameservers not actually delegated to Cloudflare, or the zone is still Pending |
| `Cloudflare rejected the API token` | Global API key used, or the token lacks `Zone:DNS:Edit` |
| CAA failure from the CA | A CAA record exists and doesn't permit `letsencrypt.org` |
| `not a publicly resolvable domain` | An internal-only suffix — a public CA cannot issue for it |
| Too many certificates already issued | Duplicate-certificate limit; wait, or change the name set |
| Certificate issued but browsers distrust it | You are still on the staging account |
