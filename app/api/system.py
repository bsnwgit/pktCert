"""
/api/system/* — version info, backups, and admin diagnostics.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.config import get_settings
from app.dependencies import AdminUser, CurrentUser
from app.backup import run_backup_sync, list_backups_sync, _read_backup_settings_sync
from app.cert import x509_utils
from app.version import get_version

router = APIRouter()


async def _delayed_restart(delay: float = 1.5) -> None:
    """Wait briefly, then exit so systemd restarts the service (Restart=on-failure)."""
    await asyncio.sleep(delay)
    os._exit(1)


def _config_file_path() -> Path:
    """Locate the on-disk config.yaml — same candidates app/config.py checks."""
    cfg = get_settings()
    for candidate in [Path("config.yaml"), Path(cfg.install_dir) / "config.yaml"]:
        if candidate.exists():
            return candidate
    raise HTTPException(500, "config.yaml not found")


@router.get("/info")
async def system_info(user: CurrentUser) -> dict:
    """Version/about info shown on the Settings → System tab."""
    cfg = get_settings()
    return {
        "app_name": "pktCert",
        "version": get_version(),
        "install_dir": cfg.install_dir,
        "github": "https://github.com/bsnwgit/pktcert",
        "license": "PolyForm Noncommercial 1.0.0",
        "developer": "Robert Barnett",
        "contact": "inquiry@barsoftnetware.com",
    }


@router.post("/restart")
async def restart_service(user: AdminUser):
    asyncio.create_task(_delayed_restart())
    return {"status": "restarting", "message": "Service will restart in ~2 seconds"}


class PortUpdate(BaseModel):
    port: int


@router.get("/port")
async def get_port(user: AdminUser):
    """
    The port pktCert listens on. Lives in config.yaml (startup config, read
    before the DB connects) rather than the SQLite-backed settings table —
    see app/config.py.
    """
    return {"port": get_settings().port}


@router.post("/port")
async def set_port(user: AdminUser, body: PortUpdate):
    """
    Update the listen port in config.yaml. Takes effect on the next service
    restart — this only writes the file, it doesn't restart anything itself.
    """
    if not (1 <= body.port <= 65535):
        raise HTTPException(400, "Port must be between 1 and 65535")

    path = _config_file_path()
    text = path.read_text()
    new_line = f"port: {body.port}"
    if re.search(r"(?m)^port:\s*\d+", text):
        text = re.sub(r"(?m)^port:\s*\d+", new_line, text, count=1)
    else:
        text = text.rstrip("\n") + f"\n{new_line}\n"
    path.write_text(text)

    return {"port": body.port, "message": "Saved — restart the service to apply"}


def _ssl_dir() -> Path:
    return Path(get_settings().ssl_dir)


def _cert_file() -> Path:
    return _ssl_dir() / "server.crt"


def _key_file() -> Path:
    return _ssl_dir() / "server.key"


def _cert_info() -> dict:
    """Read cert metadata via openssl CLI. Returns {} on failure."""
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-in", str(_cert_file()), "-noout",
             "-enddate", "-subject", "-issuer"],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode != 0:
            return {"error": proc.stderr.strip()}
        info: dict = {}
        for line in proc.stdout.strip().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                k = k.strip().lower()
                if "notafter" in k or "enddate" in k:
                    info["expires"] = v.strip()
                elif k == "subject":
                    info["subject"] = v.strip()
                elif k == "issuer":
                    info["issuer"] = v.strip()
        try:
            from datetime import datetime, timezone
            exp = datetime.strptime(info["expires"], "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            info["days_until_expiry"] = (exp - datetime.now(timezone.utc)).days
            info["expires_iso"] = exp.isoformat()
        except Exception:
            pass
        return info
    except Exception as e:
        return {"error": str(e)}


@router.get("/ssl/status")
async def ssl_status(user: AdminUser) -> dict:
    """Return current SSL certificate status."""
    if not _cert_file().exists() or not _key_file().exists():
        return {"installed": False}
    info = await asyncio.to_thread(_cert_info)
    return {"installed": True, **info}


@router.post("/ssl/upload")
async def upload_ssl_cert(
    user: AdminUser,
    cert: UploadFile = File(...),
    key: UploadFile = File(...),
) -> dict:
    """Upload and install a PEM certificate + private key."""
    cert_data = await cert.read()
    key_data  = await key.read()

    if b"-----BEGIN CERTIFICATE-----" not in cert_data:
        raise HTTPException(400, "Invalid certificate — must be PEM format (-----BEGIN CERTIFICATE-----)")
    if b"PRIVATE KEY-----" not in key_data:
        raise HTTPException(400, "Invalid private key — must be PEM format (-----BEGIN ... PRIVATE KEY-----)")

    def _save():
        _ssl_dir().mkdir(parents=True, exist_ok=True)
        _cert_file().write_bytes(cert_data)
        _cert_file().chmod(0o644)
        _key_file().write_bytes(key_data)
        _key_file().chmod(0o600)

    await asyncio.to_thread(_save)
    info = await asyncio.to_thread(_cert_info)
    return {"installed": True, "status": "saved", **info}


@router.delete("/ssl/cert")
async def delete_ssl_cert(user: AdminUser) -> dict:
    """Remove the installed SSL certificate and key."""
    _cert_file().unlink(missing_ok=True)
    _key_file().unlink(missing_ok=True)
    return {"installed": False, "status": "removed"}


@router.post("/ssl/upload-pfx")
async def upload_ssl_pfx(
    user: AdminUser,
    pfx: UploadFile = File(...),
    passphrase: str = Form(...),
) -> dict:
    """
    Accept a PKCS#12 (.pfx/.p12) bundle + passphrase.
    Extracts the cert and private key as unencrypted PEM files
    (server.crt / server.key) so uvicorn can load them without interaction.
    """
    pfx_data = await pfx.read()

    def _extract() -> tuple[bool, str]:
        # Parse in-process with the cryptography library instead of shelling
        # out to `openssl pkcs12 -passin pass:...` — that exposed the private
        # key passphrase in the process argument list (visible via ps /
        # /proc/<pid>/cmdline to any local user) and needed an insecure
        # temp file. The extracted key is written unencrypted so uvicorn can
        # load it without an interactive prompt.
        _ssl_dir().mkdir(parents=True, exist_ok=True)
        try:
            cert_pem, key_pem, chain_pem = x509_utils.load_pkcs12_bundle(pfx_data, passphrase or None)
        except Exception as e:
            return False, f"Could not parse PKCS#12 bundle (wrong passphrase or corrupt file): {e}"
        if not key_pem:
            return False, "PKCS#12 bundle has no private key"
        _cert_file().write_text(chain_pem or cert_pem)
        _cert_file().chmod(0o644)
        _key_file().write_text(key_pem)
        _key_file().chmod(0o600)
        return True, "ok"

    ok, msg = await asyncio.to_thread(_extract)
    if not ok:
        raise HTTPException(400, msg)

    info = await asyncio.to_thread(_cert_info)
    return {"installed": True, "status": "saved", **info}


@router.get("/backups")
async def list_backups(user: AdminUser):
    settings = get_settings()
    return await asyncio.to_thread(list_backups_sync, settings.db_path)


@router.post("/backups/run")
async def run_backup_now(user: AdminUser):
    settings = get_settings()
    result = await asyncio.to_thread(run_backup_sync, settings.db_path)
    if result.get("status") != "ok":
        raise HTTPException(status_code=500, detail="Backup failed")
    return result


_STATS_TABLES = [
    "certificates", "certificate_authorities", "cert_templates",
    "scan_targets", "cert_events", "alert_events",
]


def _storage_stats_sync(db_path: str) -> dict:
    import sqlite3
    size_bytes = Path(db_path).stat().st_size if Path(db_path).exists() else 0
    counts = {}
    conn = sqlite3.connect(db_path)
    try:
        for table in _STATS_TABLES:
            counts[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()
    return {"db_size_bytes": size_bytes, "row_counts": counts}


@router.get("/storage-stats")
async def storage_stats(user: AdminUser):
    """SQLite database file size + row counts per table — pktCert is
    SQLite-only (no backend picker like pktsnmp/pktflow's ClickHouse/DuckDB
    option), so this is what the Data -> Storage tab shows instead."""
    settings = get_settings()
    return await asyncio.to_thread(_storage_stats_sync, settings.db_path)


@router.post("/cleanup")
async def run_cleanup_now(user: AdminUser):
    """Run the retention cleanup (resolved/old alert_events rows)
    immediately instead of waiting for the daily scheduled pass."""
    from app.cert.alert_engine import run_cleanup_once
    result = await run_cleanup_once()
    return result


def _build_export_archive(out_path: Path) -> None:
    cfg = get_settings()
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        db = Path(cfg.db_path)
        if db.exists():
            shutil.copy2(str(db), str(tmp_path / "pktcert.db"))

        for candidate in [Path("config.yaml"), Path(cfg.install_dir) / "config.yaml"]:
            if candidate.exists():
                shutil.copy2(str(candidate), str(tmp_path / "config.yaml"))
                break

        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        instructions = f"""# pktCert Full Restore Bundle
Generated: {ts}

## Contents
- pktcert.db   — SQLite: certificates, CAs, templates, scan targets, users, settings, alert rules
- config.yaml  — Server startup config (port, secret keys)

## Restore procedure (fresh install)
1. Deploy pktCert to the new server per the README.
2. Stop the service:     sudo systemctl stop pktcert
3. Copy pktcert.db    →  {cfg.db_path}
4. Copy config.yaml   →  {cfg.install_dir}/config.yaml
5. Start the service:    sudo systemctl start pktcert

## ⚠ THIS ARCHIVE IS KEY MATERIAL — HANDLE ACCORDINGLY

pktcert.db holds every CA private key, encrypted with `credential_key`.
config.yaml holds `credential_key`. This bundle deliberately contains both,
because a restore is useless without them — but that means **anyone who
obtains this file can decrypt and use your CA private keys**, and therefore
issue certificates that every machine trusting your CAs will accept.

Treat it exactly as you would the CA keys themselves:

- Do not leave it in a Downloads folder, mail it, or put it in chat or a
  ticket.
- Move it to encrypted storage immediately, or split it: keep config.yaml
  somewhere other than pktcert.db.
- Delete it once the restore is done.

The scheduled on-server backups under Settings → Data → Backups deliberately
exclude config.yaml for this reason. This bundle does not, because it is
meant to move a whole installation to a new host in one step.

## Notes
- The JWT secret in config.yaml will invalidate existing browser sessions —
  users on the old server will need to log in again after restore.
- If you use the UI restore endpoint, the service will need a manual restart
  after restore for config.yaml changes to take effect.
"""
        (tmp_path / "RESTORE.md").write_text(instructions)

        with tarfile.open(str(out_path), "w:gz") as tar:
            for f in tmp_path.iterdir():
                tar.add(str(f), arcname=f.name)


@router.get("/export")
async def export_bundle(user: AdminUser):
    """Download a full backup bundle as a .tar.gz archive — pktcert.db +
    config.yaml + restore instructions. Streams directly to avoid holding
    the archive in memory."""
    date_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    filename = f"pktcert-export-{date_str}.tar.gz"

    _fd, _tmp_name = tempfile.mkstemp(suffix=".tar.gz")
    os.close(_fd)
    tmp_out = Path(_tmp_name)
    try:
        await asyncio.to_thread(_build_export_archive, tmp_out)

        def _iterfile():
            try:
                with open(tmp_out, "rb") as f:
                    while chunk := f.read(65536):
                        yield chunk
            finally:
                tmp_out.unlink(missing_ok=True)

        return StreamingResponse(
            _iterfile(),
            media_type="application/gzip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception:
        tmp_out.unlink(missing_ok=True)
        raise


def _restore_from_dir(src_dir: Path, cfg, files: Optional[set[str]]) -> dict:
    """
    Restore whatever of {pktcert.db, config.yaml} is present in src_dir and
    selected by `files` (None means restore everything present).
    """
    result: dict = {}

    def wanted(name: str) -> bool:
        return files is None or name in files

    db_src = src_dir / "pktcert.db"
    if wanted("pktcert.db"):
        if db_src.exists():
            shutil.copy2(str(db_src), cfg.db_path)
            result["pktcert.db"] = "restored"
        else:
            result["pktcert.db"] = "not found in backup"

    cfg_src = src_dir / "config.yaml"
    if wanted("config.yaml"):
        if cfg_src.exists():
            shutil.copy2(str(cfg_src), str(Path(cfg.install_dir) / "config.yaml"))
            result["config.yaml"] = "restored (restart required)"
        else:
            result["config.yaml"] = "not found in backup"

    return result


def _parse_files_param(files: Optional[str]) -> Optional[set[str]]:
    if not files:
        return None
    return {f.strip() for f in files.split(",") if f.strip()}


def _safe_tar_members(tar: tarfile.TarFile, dest: Path):
    """
    Yield only tar members whose extracted path resolves inside `dest`.
    Blocks path traversal (../, absolute paths) and symlink/hardlink
    escapes ("tarslip") from an uploaded/untrusted backup archive.
    """
    dest_root = dest.resolve()
    for member in tar.getmembers():
        member_path = (dest / member.name).resolve()
        if member_path != dest_root and dest_root not in member_path.parents:
            raise ValueError(f"Unsafe path in archive: {member.name}")
        if member.issym() or member.islnk():
            link_target = (dest / member.name).parent / member.linkname
            link_target = link_target.resolve()
            if link_target != dest_root and dest_root not in link_target.parents:
                raise ValueError(f"Unsafe link target in archive: {member.name} -> {member.linkname}")
        yield member


def _do_restore(raw: bytes, cfg, files: Optional[set[str]]) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        archive_path = tmp_path / "upload.tar.gz"
        archive_path.write_bytes(raw)

        try:
            with tarfile.open(str(archive_path), "r:gz") as tar:
                safe_members = list(_safe_tar_members(tar, tmp_path))
                tar.extractall(tmp_path, members=safe_members)
        except Exception as e:
            return {"error": f"Failed to extract archive: {e}"}

        return _restore_from_dir(tmp_path, cfg, files)


@router.post("/import")
async def import_bundle(user: AdminUser, file: UploadFile = File(...), files: Optional[str] = Form(None)):
    """Restore from a pktCert export bundle (.tar.gz): pktcert.db +
    config.yaml. `files` is an optional comma-separated subset of
    {pktcert.db, config.yaml} — omit to restore everything present in the
    bundle. Requires a service restart after restore for config changes to
    take effect."""
    cfg = get_settings()
    data = await file.read()
    wanted = _parse_files_param(files)
    result = await asyncio.to_thread(_do_restore, data, cfg, wanted)
    return result


@router.post("/backups/restore/{snapshot_name}")
async def restore_from_snapshot(user: AdminUser, snapshot_name: str, files: Optional[str] = None) -> dict:
    """
    Restore directly from an on-server backup snapshot — no download/upload round trip.
    `files` is an optional comma-separated subset of {pktcert.db, config.yaml} —
    omit to restore everything present in the snapshot.
    """
    if not re.fullmatch(r"backup_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}", snapshot_name):
        raise HTTPException(status_code=400, detail="Invalid snapshot name")

    cfg = get_settings()
    s = await asyncio.to_thread(_read_backup_settings_sync, cfg.db_path)
    backup_root = Path(s["backup_path"]).resolve()
    snap_dir = (backup_root / snapshot_name).resolve()
    if snap_dir.parent != backup_root or not snap_dir.is_dir():
        raise HTTPException(status_code=404, detail="Snapshot not found")

    wanted = _parse_files_param(files)
    result = await asyncio.to_thread(_restore_from_dir, snap_dir, cfg, wanted)
    return result
