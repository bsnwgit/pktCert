"""
Scheduled on-server backup job.

Runs at a configurable interval (default every 24 hours).
Each run creates a timestamped snapshot directory under backup_path:
  <backup_path>/backup_2026-07-16_22-00/
    pktcert.db
    config.yaml

Rotates snapshots — keeps the newest `backup_rotation_count` directories
and deletes older ones.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from app.config import get_settings

log = logging.getLogger("pktcert.backup")
_cfg = get_settings()


def _read_backup_settings_sync(db_path: str) -> dict:
    """Read backup settings synchronously (called from thread)."""
    import sqlite3
    defaults = {
        "backup_enabled": False,
        "backup_interval_hours": 24,
        "backup_rotation_count": 5,
        "backup_path": str(Path(_cfg.install_dir) / "backups"),
        # Off by default — see run_backup_sync() for why the CA keys and the
        # key that decrypts them should not share a directory.
        "backup_include_config": False,
    }
    try:
        conn = sqlite3.connect(db_path)
        for key in defaults:
            row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            if row:
                try:
                    defaults[key] = json.loads(row[0])
                except (ValueError, TypeError):
                    pass
        conn.close()
    except Exception as e:
        log.warning(f"Could not read backup settings: {e}")
    return defaults


def run_backup_sync(db_path: str) -> dict:
    """
    Perform one backup run synchronously (called via asyncio.to_thread).
    Returns a dict describing what was done.
    """
    s = _read_backup_settings_sync(db_path)
    result: dict = {"status": "ok", "path": "", "files": []}

    backup_root = Path(s["backup_path"])
    backup_root.mkdir(parents=True, exist_ok=True)

    ts = datetime.utcnow().strftime("%Y-%m-%d_%H-%M")
    snap_dir = backup_root / f"backup_{ts}"
    snap_dir.mkdir(parents=True, exist_ok=True)
    result["path"] = str(snap_dir)

    # Must go through SQLite's own online-backup API, never a file copy.
    #
    # The database runs in WAL mode, so at any instant the committed state is
    # split between the .db file and its -wal sidecar. A plain copy of the .db
    # alone captures neither a consistent snapshot nor the most recent commits
    # — it can silently produce a torn or stale backup, the worst possible
    # failure mode for the one artifact you reach for in an emergency. The
    # backup API takes a read lock and copies real pages, yielding a
    # standalone, internally consistent database.
    #
    # The result is verified before being accepted: a backup that cannot pass
    # integrity_check is worse than no backup, because it looks like one.
    db_src = Path(db_path)
    if db_src.exists():
        dest = snap_dir / "pktcert.db"
        src_conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            dst_conn = sqlite3.connect(str(dest))
            try:
                src_conn.backup(dst_conn)
            finally:
                dst_conn.close()
        finally:
            src_conn.close()

        check = "unknown"
        try:
            verify = sqlite3.connect(f"file:{dest}?mode=ro", uri=True)
            try:
                row = verify.execute("PRAGMA integrity_check").fetchone()
                check = row[0] if row else "no result"
            finally:
                verify.close()
        except Exception as e:
            check = f"verification failed: {e}"

        if check == "ok":
            result["files"].append("pktcert.db")
        else:
            log.error(
                f"Backup verification FAILED for {dest} — integrity_check said: {check}. "
                f"Keeping the file for inspection but not counting it as a usable backup."
            )
            result["status"] = "sqlite_backup_unverified"
            result["sqlite_integrity"] = check

    # config.yaml is EXCLUDED by default, and that default matters.
    #
    # The database holds every CA private key, Fernet-encrypted with
    # credential_key — and credential_key lives in config.yaml. Copying both
    # into one snapshot directory stores the safe next to its key: a single
    # stolen or mis-synced backup yields every CA private key in plaintext,
    # and backups are exactly the thing that gets rsynced to a NAS, copied to
    # a laptop, or left on a share.
    #
    # So snapshots carry the data, and config.yaml is backed up separately by
    # the operator and stored somewhere else. Set backup_include_config if you
    # accept the risk and want single-directory restore.
    if s.get("backup_include_config"):
        for candidate in [Path("config.yaml"), Path(_cfg.install_dir) / "config.yaml"]:
            if candidate.exists():
                shutil.copy2(str(candidate), str(snap_dir / "config.yaml"))
                result["files"].append("config.yaml")
                break

    (snap_dir / "RESTORE-NOTES.txt").write_text(
        "pktCert backup snapshot\n"
        "=======================\n\n"
        f"Contains: {', '.join(result['files']) or 'nothing'}\n\n"
        + (
            "config.yaml IS included in this snapshot. It holds credential_key,\n"
            "which decrypts every CA private key in pktcert.db. Treat this\n"
            "directory as key material: restrict access to it and do not copy\n"
            "it anywhere you would not store the CA keys themselves.\n"
            if "config.yaml" in result["files"]
            else
            "config.yaml is NOT included, deliberately. It holds credential_key,\n"
            "which decrypts every CA private key stored in pktcert.db — keeping\n"
            "the two apart means one stolen backup is not enough to obtain your\n"
            "CA keys.\n\n"
            "You must back up config.yaml yourself and store it somewhere other\n"
            "than these snapshots. WITHOUT IT, THE CA PRIVATE KEYS IN THIS\n"
            "BACKUP CANNOT BE DECRYPTED AND ARE PERMANENTLY UNUSABLE.\n\n"
            "To include it here anyway, enable 'backup_include_config' in\n"
            "Settings and accept that this directory then contains everything\n"
            "needed to impersonate your CAs.\n"
        )
    )
    result["files"].append("RESTORE-NOTES.txt")

    keep = int(s["backup_rotation_count"])
    snapshots = sorted(
        [d for d in backup_root.iterdir() if d.is_dir() and d.name.startswith("backup_")],
        key=lambda d: d.stat().st_mtime,
    )
    removed = []
    while len(snapshots) > keep:
        old = snapshots.pop(0)
        shutil.rmtree(str(old), ignore_errors=True)
        removed.append(old.name)
    if removed:
        log.info(f"Backup rotation: removed {removed}")

    result["kept"] = len(snapshots)
    log.info(f"Backup complete: {snap_dir} — files: {result['files']}")
    return result


def list_backups_sync(db_path: str) -> list[dict]:
    """List existing backup snapshots, newest first."""
    s = _read_backup_settings_sync(db_path)
    backup_root = Path(s["backup_path"])
    if not backup_root.exists():
        return []
    snapshots = sorted(
        [d for d in backup_root.iterdir() if d.is_dir() and d.name.startswith("backup_")],
        key=lambda d: d.stat().st_mtime,
        reverse=True,
    )
    result = []
    for snap in snapshots:
        try:
            size = sum(f.stat().st_size for f in snap.rglob("*") if f.is_file())
            files = [f.name for f in snap.iterdir() if f.is_file()]
            result.append({
                "name": snap.name,
                "path": str(snap),
                "size_bytes": size,
                "files": files,
            })
        except Exception:
            pass
    return result


class BackupScheduler:
    _instance: "Optional[BackupScheduler]" = None

    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        BackupScheduler._instance = self
        self._task = asyncio.create_task(self._run_loop())
        log.info("Backup scheduler started")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _run_loop(self) -> None:
        while True:
            try:
                s = await asyncio.to_thread(_read_backup_settings_sync, _cfg.db_path)
                if s["backup_enabled"]:
                    await asyncio.to_thread(run_backup_sync, _cfg.db_path)
                else:
                    log.debug("Backup disabled — skipping run")
            except Exception as e:
                log.error(f"Backup scheduler error: {e}")
            try:
                s = await asyncio.to_thread(_read_backup_settings_sync, _cfg.db_path)
                interval_secs = max(1, int(s["backup_interval_hours"])) * 3600
            except Exception:
                interval_secs = 86400
            await asyncio.sleep(interval_secs)
