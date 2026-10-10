#!/usr/bin/env python3
"""
Self-update tests (app/self_update.py).

Standalone script — run from the repo root:
    python3 tests/test_self_update.py

GitHub is replaced with an httpx MockTransport, so nothing here touches the
network. Everything else is real: the settings table, the tarball extraction,
the allow-listed swap into a throwaway install dir, and the GitHub token going
through Fernet. What the swap must never touch (config.yaml, the database,
venv/, logs/) is planted in the install dir and checked afterwards, because
that is the property that matters when this runs on a live install.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import io
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

REPO_ROOT = Path(__file__).resolve().parents[1]

TMP = Path(tempfile.mkdtemp(prefix="pktcert-selfupdate-"))
INSTALL = TMP / "install"
INSTALL.mkdir()
(TMP / "config.yaml").write_text(
    f"install_dir: {INSTALL}\n"
    f"secret_key: {'a' * 64}\n"
    f"credential_key: {Fernet.generate_key().decode()}\n"
    f"suite_token: ''\n"
)
os.environ["PKTCERT_CONFIG"] = str(TMP / "config.yaml")
os.environ["PKTCERT_INSTALL_DIR"] = str(INSTALL)
sys.path.insert(0, str(REPO_ROOT))

import aiosqlite                                                    # noqa: E402
import httpx                                                        # noqa: E402

from app import self_update                                         # noqa: E402

# Generated per run: a literal here would be a hardcoded credential on paper.
TEST_TOKEN = "t-" + os.urandom(12).hex()

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{(' — ' + detail) if detail and not ok else ''}")
    if not ok:
        failures.append(name)


def tarball(files: dict[str, str], extra=None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        if extra:
            extra(tf)
    return buf.getvalue()


RELEASE_FILES = {
    "pktcert-v9.9.9/app/main.py": "NEW MAIN\n",
    "pktcert-v9.9.9/VERSION": "9.9.9.testing\n",
    "pktcert-v9.9.9/requirements.txt": "# none\n",
    "pktcert-v9.9.9/migrations/001_initial.sql": "-- new\n",
    "pktcert-v9.9.9/frontend/dist/index.html": "<html>new</html>\n",
    # Not on the allow-list: must never land in the install dir.
    "pktcert-v9.9.9/config.yaml": "evil: true\n",
    "pktcert-v9.9.9/pktcert.db": "evil\n",
    "pktcert-v9.9.9/venv/marker": "evil\n",
}


def fake_github(asset_bytes: bytes, tag: str = "v9.9.9", private_only: bool = False):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("/releases/latest"):
            if private_only and "authorization" not in request.headers:
                return httpx.Response(404)
            return httpx.Response(200, json={
                "tag_name": tag, "html_url": "https://example.com/release",
                "assets": [{
                    "name": f"pktcert-{tag}.tar.gz",
                    "url": "https://api.example.com/asset/1",
                    "browser_download_url": "https://example.com/asset.tar.gz",
                }],
            })
        return httpx.Response(200, content=asset_bytes)

    return httpx.MockTransport(handler), seen


_REAL_CLIENT = httpx.AsyncClient


def patch_client(transport: httpx.MockTransport) -> None:
    def factory(*args, **kwargs):
        kwargs["transport"] = transport
        return _REAL_CLIENT(*args, **kwargs)

    self_update.httpx.AsyncClient = factory  # type: ignore[assignment]


async def new_db() -> aiosqlite.Connection:
    db = await aiosqlite.connect(":memory:")
    db.row_factory = aiosqlite.Row
    await db.execute(
        "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, "
        "updated_at TEXT NOT NULL DEFAULT (datetime('now')))"
    )
    await db.commit()
    return db


def plant_install() -> None:
    for p in INSTALL.iterdir():
        if p.is_dir():
            import shutil
            shutil.rmtree(p)
        else:
            p.unlink()
    (INSTALL / "app").mkdir()
    (INSTALL / "app" / "main.py").write_text("OLD MAIN\n")
    (INSTALL / "app" / "stale.py").write_text("removed by update\n")
    (INSTALL / "VERSION").write_text("0.0.1.old\n")
    (INSTALL / "config.yaml").write_text("keep: me\n")
    (INSTALL / "pktcert.db").write_text("live data\n")
    (INSTALL / "venv").mkdir()
    (INSTALL / "venv" / "marker").write_text("keep\n")
    (INSTALL / "logs").mkdir()
    (INSTALL / "logs" / "pktcert.log").write_text("keep\n")


async def main() -> None:
    print("version + window logic")
    check("tag parses", self_update._parse_tag("v1.2.3") == (1, 2, 3))
    check("tag with codename rejected only when short", self_update._parse_tag("v1.2") is None)
    check("garbage tag", self_update._parse_tag("vX.Y.Z") is None)
    check("overnight window wraps (inside)", self_update._in_window(dt.time(23, 30), "22:00", "04:00"))
    check("overnight window wraps (after midnight)", self_update._in_window(dt.time(1, 0), "22:00", "04:00"))
    check("overnight window (outside)", not self_update._in_window(dt.time(12, 0), "22:00", "04:00"))
    check("same-day window (inside)", self_update._in_window(dt.time(3, 0), "02:00", "04:00"))
    check("same-day window (outside)", not self_update._in_window(dt.time(5, 0), "02:00", "04:00"))

    print("archive safety")
    def traversal(tf: tarfile.TarFile) -> None:
        data = b"x"
        info = tarfile.TarInfo("../escape.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    def symlink(tf: tarfile.TarFile) -> None:
        info = tarfile.TarInfo("rel/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)
    for label, extra in (("path traversal", traversal), ("symlink", symlink)):
        dest = TMP / f"extract-{label.replace(' ', '-')}"
        dest.mkdir()
        raised = False
        try:
            with tarfile.open(fileobj=io.BytesIO(tarball({"ok.txt": "x"}, extra)), mode="r:gz") as tf:
                self_update._safe_extract(tf, dest)
        except RuntimeError:
            raised = True
        check(f"{label} refused", raised)
        check(f"{label}: nothing written outside", not (TMP / "escape.txt").exists())

    print("status + config")
    db = await new_db()
    st = await self_update.status(db)
    check("defaults: manual mode", st["mode"] == "manual")
    check("defaults: no token", st["token_set"] is False)
    st = await self_update.save_config(db, mode="auto", window_start="01:00", window_end="03:30", github_token=TEST_TOKEN)
    check("mode saved", st["mode"] == "auto" and st["window_start"] == "01:00" and st["window_end"] == "03:30")
    check("token flagged set", st["token_set"] is True)
    check("token never returned by status", TEST_TOKEN not in json.dumps(st))
    async with db.execute("SELECT value FROM settings WHERE key='self_update_github_token'") as cur:
        raw = (await cur.fetchone())[0]
    check("token encrypted at rest", TEST_TOKEN not in raw)
    check("token round-trips", await self_update._github_token(db) == TEST_TOKEN)
    st = await self_update.save_config(db, mode="manual")
    check("omitted token left alone", st["token_set"] is True)
    st = await self_update.save_config(db, github_token="")
    check("empty token clears", st["token_set"] is False and await self_update._github_token(db) == "")
    for bad in ({"mode": "sometimes"}, {"window_start": "25:00"}, {"window_end": "noon"}):
        try:
            await self_update.save_config(db, **bad)
            check(f"rejects {bad}", False)
        except ValueError:
            check(f"rejects {bad}", True)
    await db.close()

    print("check against GitHub")
    (INSTALL / "VERSION").write_text("0.0.1.old\n")
    db = await new_db()
    transport, _ = fake_github(b"", tag="v9.9.9")
    patch_client(transport)
    st = await self_update.check_latest(db)
    check("newer release flagged", st["update_available"] is True and st["latest_tag"] == "v9.9.9", str(st))
    transport, _ = fake_github(b"", tag="v0.0.1")
    patch_client(transport)
    st = await self_update.check_latest(db)
    check("same version is not an update", st["update_available"] is False)
    transport, _ = fake_github(b"", private_only=True)
    patch_client(transport)
    db2 = await new_db()
    st = await self_update.check_latest(db2)
    check("private repo without a token says so", "private" in st["last_error"], st["last_error"])
    await self_update.save_config(db2, github_token=TEST_TOKEN)
    st = await self_update.check_latest(db2)
    check("private repo with a token works", st["update_available"] is True, str(st))
    await db2.close()

    print("apply")
    plant_install()
    db = await new_db()
    asset = tarball(RELEASE_FILES)
    transport, seen = fake_github(asset)
    patch_client(transport)
    result = await self_update.apply_now(db)
    check("apply reports the tag", result == {"applied": "v9.9.9"}, str(result))
    check("app replaced", (INSTALL / "app" / "main.py").read_text() == "NEW MAIN\n")
    check("stale file in app/ removed", not (INSTALL / "app" / "stale.py").exists())
    check("VERSION replaced", (INSTALL / "VERSION").read_text().startswith("9.9.9"))
    check("migrations installed", (INSTALL / "migrations" / "001_initial.sql").exists())
    check("frontend dist installed", (INSTALL / "frontend" / "dist" / "index.html").read_text().startswith("<html>new"))
    check("config.yaml untouched", (INSTALL / "config.yaml").read_text() == "keep: me\n")
    check("database untouched", (INSTALL / "pktcert.db").read_text() == "live data\n")
    check("venv untouched", (INSTALL / "venv" / "marker").read_text() == "keep\n")
    check("logs untouched", (INSTALL / "logs" / "pktcert.log").read_text() == "keep\n")
    st = await self_update.status(db)
    check("state recorded", st["last_applied_tag"] == "v9.9.9" and st["update_available"] is False)
    check("public repo: no Authorization header sent",
          all("authorization" not in r.headers for r in seen))

    print("apply: refusals")
    plant_install()
    db = await new_db()
    transport, _ = fake_github(tarball({k: v for k, v in RELEASE_FILES.items() if "main.py" not in k}))
    patch_client(transport)
    raised = False
    try:
        await self_update.apply_now(db)
    except RuntimeError:
        raised = True
    check("incomplete package refused", raised)
    check("incomplete package: install untouched", (INSTALL / "app" / "main.py").read_text() == "OLD MAIN\n")

    plant_install()
    (INSTALL / ".git").mkdir()
    db = await new_db()
    transport, _ = fake_github(asset)
    patch_client(transport)
    raised = False
    try:
        await self_update.apply_now(db)
    except self_update.UpdateRefused:
        raised = True
    check("git checkout refused", raised)
    check("git checkout: install untouched", (INSTALL / "app" / "main.py").read_text() == "OLD MAIN\n")
    check("git checkout reported as not applicable", (await self_update.status(db))["can_apply"] is False)

    plant_install()
    db = await new_db()
    patch_client(fake_github(asset, tag="v0.0.1")[0])
    raised = False
    try:
        await self_update.apply_now(db)
    except self_update.UpdateRefused:
        raised = True
    check("already up to date is a refusal, not a failure", raised)

    print()
    if failures:
        print(f"{len(failures)} FAILED: {', '.join(failures)}")
        sys.exit(1)
    print("All self-update tests passed.")


asyncio.run(main())
