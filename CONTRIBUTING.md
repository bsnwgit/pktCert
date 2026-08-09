# Contributing to pktCert

## Branch strategy

| Branch | Purpose |
|---|---|
| `main` | Production-ready code — reflects what is deployed |
| `feature/<name>` / `fix/<name>` | Individual features or bug fixes, branched from `main` |

## Workflow

### Starting new work

```bash
cd pktcert

# Make sure you're up to date
git checkout main
git pull

# Create a feature branch
git checkout -b feature/your-feature-name
```

### Committing changes

```bash
git add -A
git commit -m "short description of what changed"
git push -u origin feature/your-feature-name
```

### Opening a PR

```bash
# PR from feature branch directly into main
gh pr create --base main --head feature/your-feature-name --title "Your feature title"
```

### Deploying after merge

```bash
# On the server:
cd pktcert && git pull && cd frontend && npm ci && npm run build && cd .. && bash install.sh
```

Always cut a brand-new branch off `main` for each round of work — don't reuse a
branch name across unrelated changes, since a previously merged branch name
can be silently re-merged as a no-op.

## Deployment rules

- **Never deploy directly from a feature branch** — merge to `main` first
- **Deployment/diagnostic helper scripts are environment-specific** — keep
  them in a local, untracked `scripts/` directory (already excluded via
  `.gitignore`); they are not part of this repository
- **No source file hardcodes an absolute install path** — `install_dir` is
  resolved at runtime and every other path derives from it (see
  `app/config.py`); don't reintroduce a literal path in a template or
  shipped config
- **`install.sh` always runs as the normal user, never `sudo ./install.sh`**
  — it calls `sudo` internally wherever it actually needs root

## Adding a new CT search provider

Certificate Transparency search providers live in `app/cert/ct_search.py`
(`search_crtsh`, `search_censys`). To add another provider:

1. Write a `search_<provider>(...)` async function that queries the
   provider's API and returns raw results (normalization into pktCert's
   `certificates` schema happens in the caller, not here).
2. If the provider needs a credential, add it to `SUPPORTED_PROVIDERS` in
   `app/api/user_api_keys.py` and wire a `test_api_key` branch for it.
3. Surface it in the frontend's User Keys tab (`Settings.tsx`) the same way
   Censys is — one masked text field, Test + Save buttons.

## Commit message style

```
type: short description (imperative, lowercase)

Examples:
  feat: add Censys CT search provider
  fix: correct CRL serial-number formatting
  chore: update requirements.txt
  docs: expand CA issuance guide
```
