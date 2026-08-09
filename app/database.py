"""
SQLite async database engine for the pktCert app database
(users, settings, scan targets, certificates, certificate authorities,
templates, alerts).
"""
from __future__ import annotations

import sys
import aiosqlite
from pathlib import Path
from typing import AsyncGenerator

from app.config import get_settings

_settings = get_settings()
DB_PATH = _settings.db_path


async def get_db() -> AsyncGenerator[aiosqlite.Connection, None]:
    """FastAPI dependency — yields an open aiosqlite connection per request."""
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA foreign_keys=ON")
        await conn.execute("PRAGMA busy_timeout=5000")
        yield conn


async def init_db() -> None:
    """Run migrations on startup. Safe to call multiple times (idempotent SQL)."""
    migration_dir = Path(__file__).parent.parent / "migrations"
    migration_files = sorted(migration_dir.glob("*.sql"))

    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA foreign_keys=ON")

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS _migrations (
                filename TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        await conn.commit()

        for mfile in migration_files:
            async with conn.execute(
                "SELECT 1 FROM _migrations WHERE filename = ?", (mfile.name,)
            ) as cur:
                already_applied = await cur.fetchone()

            if not already_applied:
                sql = mfile.read_text()
                try:
                    await conn.executescript(sql)
                except Exception as exc:
                    if "duplicate column name" not in str(exc).lower():
                        raise
                await conn.execute(
                    "INSERT INTO _migrations (filename) VALUES (?)", (mfile.name,)
                )
                await conn.commit()

        await _encrypt_legacy_api_keys(conn)


async def _encrypt_legacy_api_keys(conn: aiosqlite.Connection) -> None:
    """One-time data migration: user_api_keys.api_key used to be stored in
    plaintext. Encrypt any row that isn't already a valid Fernet token.
    Tracked via _migrations (same table the .sql migrations use) so this
    only does real work once."""
    marker = "999_encrypt_legacy_user_api_keys.py"
    async with conn.execute(
        "SELECT 1 FROM _migrations WHERE filename = ?", (marker,)
    ) as cur:
        if await cur.fetchone():
            return

    from app.cert.crypto import decrypt_str, encrypt_str

    async with conn.execute(
        "SELECT id, api_key FROM user_api_keys WHERE api_key != ''"
    ) as cur:
        rows = await cur.fetchall()

    for row_id, api_key in rows:
        try:
            already_encrypted = bool(decrypt_str(api_key))
        except Exception:
            already_encrypted = False
        if already_encrypted:
            continue
        await conn.execute(
            "UPDATE user_api_keys SET api_key = ? WHERE id = ?",
            (encrypt_str(api_key), row_id),
        )

    await conn.execute("INSERT INTO _migrations (filename) VALUES (?)", (marker,))
    await conn.commit()


async def seed_admin() -> None:
    """
    Create the default admin user on first boot.

    Reads the plain-text password from PKTCERT_ADMIN_PASSWORD (set by
    install.sh to a randomly generated value). If the users table is empty
    and the password is blank, the process exits with a clear error message
    rather than silently starting with no admin account.
    """
    _settings = get_settings()
    admin_password = _settings.admin_password

    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute("PRAGMA journal_mode=WAL")
        cur = await conn.execute("SELECT COUNT(*) FROM users")
        row = await cur.fetchone()
        user_count = row[0] if row else 0

        if user_count > 0:
            return  # DB already has users — skip seeding

        if not admin_password:
            print(
                "\nFATAL: No users exist and PKTCERT_ADMIN_PASSWORD is not set.\n"
                "       Set PKTCERT_ADMIN_PASSWORD to create the initial admin account.\n"
                "       Example: PKTCERT_ADMIN_PASSWORD=changeme python3 -m app.main\n",
                file=sys.stderr,
            )
            sys.exit(1)

        from app.auth.local import hash_password
        hashed = hash_password(admin_password)
        await conn.execute(
            "INSERT INTO users (username, email, hashed_password, role, is_default_admin) VALUES (?, ?, ?, ?, 1)",
            ("admin", "admin@pktcert.local", hashed, "admin"),
        )
        await conn.commit()
