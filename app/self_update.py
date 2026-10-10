"""
Self-update: checks bsnw's pktCert GitHub releases against the local VERSION
and, in 'auto' mode inside the configured window, downloads and applies a
newer release, then exits so systemd brings the new code back up.

'manual' mode (the default) never applies anything by itself — it records
what's available so Settings → System can show it, and an admin's "Update
now" applies it on demand.

There is no code signing upstream: this trusts GitHub's TLS and nothing
else, same as any other HTTPS download. Applying is refused outright on an
install that looks like a git checkout (a `.git` directory in install_dir)
— that's a dev/working tree, not the kind of hands-off install this is
for, and overwriting it would silently clobber uncommitted work.

A private repo needs a GitHub token (read access to contents). It is held
Fernet-encrypted in the settings table and never returned by the API.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Optional

import aiosqlite
import httpx

from app.config import get_settings
from app.database import DB_PATH

log = logging.getLogger("pktcert.self_update")

REPO = "bsnwgit/pktcert"
_ASSET_PREFIX = "pktcert-"
_RELEASES_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
_CHECK_EVERY_SECONDS = 3600
_REQUEST_TIMEOUT = 15.0
_DOWNLOAD_TIMEOUT = 120.0
_MAX_ASSET_BYTES = 200 * 1024 * 1024  # a built frontend + app source, generously bounded

# Paths replaced by an applied update — an allow-list, not a deny-list, so
# nothing outside it (config.yaml, the db + -wal/-shm, venv, logs, backups)
# is ever touched no matter what a release tarball happens to contain.
_UPDATED_PATHS = ("app", "migrations", "docs", "VERSION", "requirements.txt")

# Settings keys. Mode / window / token are configuration; the rest is state.
_MODES = ("manual", "auto")


class UpdateRefused(Exception):
    """An update that can't or shouldn't be applied right now — already up
    to date, GitHub unreachable, or an install that must not self-mutate
    (a git checkout). Not a failure: nothing was touched."""


def _version_file() -> Path:
    return Path(__file__).resolve().parent.parent / "VERSION"


def current_version() -> tuple[int, int, int]:
    try:
        parts = _version_file().read_text().strip().split(".")
        if len(parts) >= 3:
            return int(parts[0]), int(parts[1]), int(parts[2])
    except (OSError, ValueError):
        pass
    return (0, 0, 0)


def _parse_tag(tag: str) -> Optional[tuple[int, int, int]]:
    core = tag.lstrip("vV").split(".")
    if len(core) < 3:
        return None
    try:
        return int(core[0]), int(core[1]), int(core[2])
    except ValueError:
        return None


# -- settings table helpers ---------------------------------------------------

async def _get_setting(db: aiosqlite.Connection, key: str, default=None):
    async with db.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cur:
        row = await cur.fetchone()
    if not row:
        return default
    try:
        return json.loads(row[0])
    except (json.JSONDecodeError, TypeError):
        return default


async def _set_setting(db: aiosqlite.Connection, key: str, value: Any) -> None:
    await db.execute(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime('now')) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, json.dumps(value)),
    )


async def _github_token(db: aiosqlite.Connection) -> str:
    stored = await _get_setting(db, "self_update_github_token", "")
    if not stored or not isinstance(stored, str):
        return ""
    from app.cert.crypto import decrypt_str
    try:
        return decrypt_str(stored)
    except Exception:
        # A rotated credential key reads as "not configured", not a 500.
        return ""


def _headers(token: str, accept: str = "application/vnd.github+json") -> dict[str, str]:
    headers = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


# -- status / configuration ---------------------------------------------------

async def status(db: aiosqlite.Connection) -> dict:
    version_file = _version_file()
    major, minor, patch = current_version()
    return {
        "current_version": version_file.read_text().strip() if version_file.exists() else f"{major}.{minor}.{patch}",
        "latest_tag": await _get_setting(db, "self_update_latest_tag"),
        "latest_url": await _get_setting(db, "self_update_latest_url"),
        "update_available": await _get_setting(db, "self_update_available", False),
        "checked_at": await _get_setting(db, "self_update_checked_at"),
        "last_error": await _get_setting(db, "self_update_last_error", ""),
        "last_applied_tag": await _get_setting(db, "self_update_applied_tag"),
        "last_applied_at": await _get_setting(db, "self_update_applied_at"),
        "mode": await _get_setting(db, "self_update_mode", "manual"),
        "window_start": await _get_setting(db, "self_update_window_start", "02:00"),
        "window_end": await _get_setting(db, "self_update_window_end", "04:00"),
        "token_set": bool(await _get_setting(db, "self_update_github_token", "")),
        "repo": REPO,
        "can_apply": not _refuses_to_apply(Path(get_settings().install_dir)),
    }


def _valid_hhmm(value: str) -> bool:
    try:
        h, m = (int(x) for x in value.split(":"))
    except (ValueError, AttributeError):
        return False
    return 0 <= h <= 23 and 0 <= m <= 59 and len(value) == 5


async def save_config(
    db: aiosqlite.Connection,
    *,
    mode: Optional[str] = None,
    window_start: Optional[str] = None,
    window_end: Optional[str] = None,
    github_token: Optional[str] = None,
) -> dict:
    """Persist update configuration. `github_token`: None leaves the stored
    token alone, "" clears it, anything else replaces it."""
    if mode is not None:
        if mode not in _MODES:
            raise ValueError("mode must be 'manual' or 'auto'")
        await _set_setting(db, "self_update_mode", mode)
    for key, value in (("self_update_window_start", window_start), ("self_update_window_end", window_end)):
        if value is not None:
            if not _valid_hhmm(value):
                raise ValueError("Window times must be HH:MM")
            await _set_setting(db, key, value)
    if github_token is not None:
        token = github_token.strip()
        if token:
            from app.cert.crypto import encrypt_str
            await _set_setting(db, "self_update_github_token", encrypt_str(token))
        else:
            await _set_setting(db, "self_update_github_token", "")
    await db.commit()
    return await status(db)


# -- check --------------------------------------------------------------------

async def check_latest(db: aiosqlite.Connection) -> dict:
    """Read-only against GitHub: ask for the latest release, record what's
    found. Safe to call from any mode, any number of times."""
    error = ""
    release: Optional[dict] = None
    token = await _github_token(db)
    try:
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
            resp = await client.get(_RELEASES_URL, headers=_headers(token))
        if resp.status_code == 404:
            error = (
                "No releases published yet" if token
                else "No releases published yet, or the repository is private — set a GitHub token"
            )
        elif resp.status_code in (401, 403):
            error = "GitHub refused the request — check the GitHub token (or the API rate limit)"
        else:
            resp.raise_for_status()
            release = resp.json()
    except httpx.HTTPError as exc:
        error = f"Couldn't reach GitHub: {exc}"

    available = False
    if release:
        tag = release.get("tag_name", "")
        parsed = _parse_tag(tag)
        if parsed and parsed > current_version():
            available = True
        await _set_setting(db, "self_update_latest_tag", tag)
        await _set_setting(db, "self_update_latest_url", release.get("html_url", ""))
        await _set_setting(db, "self_update_latest_assets", release.get("assets", []))

    await _set_setting(db, "self_update_available", available)
    await _set_setting(db, "self_update_checked_at", dt.datetime.now(dt.timezone.utc).isoformat())
    await _set_setting(db, "self_update_last_error", error)
    await db.commit()
    return await status(db)


# -- apply --------------------------------------------------------------------

def _in_window(now: dt.time, start: str, end: str) -> bool:
    try:
        h1, m1 = (int(x) for x in start.split(":"))
        h2, m2 = (int(x) for x in end.split(":"))
    except ValueError:
        return False
    lo, hi = dt.time(h1, m1), dt.time(h2, m2)
    if lo <= hi:
        return lo <= now <= hi
    return now >= lo or now <= hi  # window wraps past midnight


def _refuses_to_apply(install_dir: Path) -> str:
    """Reasons an install can never safely self-mutate — checked before
    every apply, not just once at startup, since the setting can change
    without a restart."""
    if (install_dir / ".git").exists():
        return f"{install_dir} looks like a git checkout — refusing to overwrite it"
    return ""


def _find_asset(assets: list[dict]) -> Optional[dict]:
    for asset in assets:
        name = asset.get("name", "")
        if name.startswith(_ASSET_PREFIX) and name.endswith(".tar.gz"):
            return asset
    return None


def _safe_extract(tf: tarfile.TarFile, dest: Path) -> None:
    dest_resolved = dest.resolve()
    for member in tf.getmembers():
        # Links could point outside dest after extraction, whatever their own
        # path looks like — a release has no use for them.
        if not (member.isfile() or member.isdir()):
            raise RuntimeError(f"Release archive has an unexpected entry type: {member.name}")
        target = (dest / member.name).resolve()
        if target != dest_resolved and dest_resolved not in target.parents:
            raise RuntimeError(f"Release archive has an unsafe path: {member.name}")
    tf.extractall(dest)


def _find_staged_root(extract_dir: Path) -> Path:
    entries = list(extract_dir.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return extract_dir


def _verify_staged(staged: Path) -> None:
    required = ["app/main.py", "VERSION", "requirements.txt", "frontend/dist/index.html"]
    missing = [p for p in required if not (staged / p).exists()]
    if missing:
        raise RuntimeError(f"Release package is missing expected files: {missing}")


def _install_requirements(install_dir: Path, requirements: Path) -> None:
    """Install the release's Python packages into the app's venv *before* any
    file is swapped, so a failed install leaves the running code untouched."""
    pip = install_dir / "venv" / "bin" / "pip"
    if pip.exists():
        subprocess.run(
            [str(pip), "install", "--quiet", "-r", str(requirements)],
            check=True, timeout=300,
        )


def _swap_in(staged: Path, install_dir: Path) -> None:
    for name in _UPDATED_PATHS:
        src = staged / name
        if not src.exists():
            continue
        dest = install_dir / name
        if dest.exists():
            if dest.is_dir():
                shutil.rmtree(dest)
            else:
                dest.unlink()
        if src.is_dir():
            shutil.copytree(src, dest)
        else:
            shutil.copy2(src, dest)

    dist_src = staged / "frontend" / "dist"
    if dist_src.exists():
        dist_dest = install_dir / "frontend" / "dist"
        if dist_dest.exists():
            shutil.rmtree(dist_dest)
        dist_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(dist_src, dist_dest)


async def apply_update(db: aiosqlite.Connection) -> dict:
    """Download the latest release's packaged asset and apply it in place.
    Raises on anything that isn't a clean, verified apply; never partially
    overwrites install_dir (packages first, then one swap of the allow-list)."""
    install_dir = Path(get_settings().install_dir)
    refusal = _refuses_to_apply(install_dir)
    if refusal:
        raise UpdateRefused(refusal[0].upper() + refusal[1:])

    assets = await _get_setting(db, "self_update_latest_assets", [])
    tag = await _get_setting(db, "self_update_latest_tag", "")
    asset = _find_asset(assets)
    if not asset:
        raise RuntimeError(f"Release {tag or '(unknown)'} has no {_ASSET_PREFIX}*.tar.gz asset")

    token = await _github_token(db)
    if token:
        # A private repo's asset is only reachable through the API endpoint.
        url, accept = asset.get("url"), "application/octet-stream"
    else:
        url, accept = asset.get("browser_download_url"), "application/octet-stream"
    if not url:
        raise RuntimeError("Release asset has no download URL")

    with tempfile.TemporaryDirectory(prefix="pktcert-update-") as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / "release.tar.gz"
        downloaded = 0
        async with httpx.AsyncClient(timeout=_DOWNLOAD_TIMEOUT, follow_redirects=True) as client:
            async with client.stream("GET", url, headers=_headers(token, accept)) as resp:
                resp.raise_for_status()
                with archive.open("wb") as f:
                    async for chunk in resp.aiter_bytes():
                        downloaded += len(chunk)
                        if downloaded > _MAX_ASSET_BYTES:
                            raise RuntimeError("Release asset exceeded the size limit — aborting download")
                        f.write(chunk)

        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()

        def _unpack() -> Path:
            with tarfile.open(archive) as tf:
                _safe_extract(tf, extract_dir)
            staged = _find_staged_root(extract_dir)
            _verify_staged(staged)
            return staged

        staged = await asyncio.to_thread(_unpack)
        await asyncio.to_thread(_install_requirements, install_dir, staged / "requirements.txt")
        await asyncio.to_thread(_swap_in, staged, install_dir)

    await _set_setting(db, "self_update_applied_tag", tag)
    await _set_setting(db, "self_update_applied_at", dt.datetime.now(dt.timezone.utc).isoformat())
    await _set_setting(db, "self_update_available", False)
    await db.commit()
    log.info("Self-update applied: %s", tag)
    return {"applied": tag}


async def apply_now(db: aiosqlite.Connection) -> dict:
    """The admin's "Update now" click: the same download-and-swap auto mode
    does, but on demand and outside the daily window — the person pressing
    the button is the window. Re-checks GitHub first so a stale "available"
    flag can't apply an old release. The caller exits afterwards so systemd
    brings the new code up."""
    found = await check_latest(db)
    if not found["update_available"]:
        raise UpdateRefused(found["last_error"] or "Already up to date")
    return await apply_update(db)


def restart_soon(delay: float = 2.0) -> None:
    """Exit shortly, after the HTTP response has been sent. Exit code 1, not
    0: a unit with Restart=on-failure ignores a clean exit, and 1 restarts
    under Restart=always too.
    os._exit, not sys.exit — a Task would swallow that and the process would
    keep serving from a half-replaced app/ tree."""
    asyncio.get_running_loop().call_later(delay, os._exit, 1)


async def maybe_apply(db: aiosqlite.Connection) -> None:
    if await _get_setting(db, "self_update_mode", "manual") != "auto":
        return
    if not await _get_setting(db, "self_update_available", False):
        return
    start = await _get_setting(db, "self_update_window_start", "02:00")
    end = await _get_setting(db, "self_update_window_end", "04:00")
    if not _in_window(dt.datetime.now().time(), start, end):
        return
    try:
        await apply_update(db)
    except UpdateRefused as exc:
        await _set_setting(db, "self_update_last_error", str(exc))
        await db.commit()
        return
    except Exception as exc:
        log.exception("Self-update apply failed")
        await _set_setting(db, "self_update_last_error", f"Apply failed: {exc}")
        await db.commit()
        return
    log.info("Self-update applied — exiting for systemd to restart")
    os._exit(1)


async def run_forever() -> None:
    log.info("Self-update checker started (every %ss)", _CHECK_EVERY_SECONDS)
    while True:
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                db.row_factory = aiosqlite.Row
                await check_latest(db)
                await maybe_apply(db)
        except Exception:
            log.exception("Self-update check failed")
        await asyncio.sleep(_CHECK_EVERY_SECONDS)
