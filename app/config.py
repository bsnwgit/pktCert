"""
pktCert configuration.

Priority order (highest -> lowest):
  1. Environment variables  (PKTCERT_*)
  2. config.yaml — found via $PKTCERT_CONFIG, $PKTCERT_INSTALL_DIR/config.yaml,
     ./config.yaml, or ~/.pktcert/config.yaml
  3. Defaults defined here

No path in this file is hardcoded to a specific install location. Every
on-disk path (db_path, log_file, ssl_dir, ...) defaults to somewhere under
`install_dir` — the directory install.sh (or $PKTCERT_INSTALL_DIR) was
pointed at — so the app works the same whether it's installed at
/opt/pktcert, in-place in a repo checkout, or anywhere else. Override any
individual path in config.yaml if you need it to live somewhere else.

Runtime settings (scan targets, alert thresholds, discovery defaults, etc.)
are stored in SQLite and loaded via the settings table; those are NOT in
this file. This file only covers startup/infrastructure settings that must
be known before the database is connected.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _find_config_path() -> Optional[Path]:
    """Try known config file locations, in priority order."""
    candidates = [Path("config.yaml")]
    install_dir = os.environ.get("PKTCERT_INSTALL_DIR")
    if install_dir:
        candidates.insert(0, Path(install_dir) / "config.yaml")
    candidates.append(Path.home() / ".pktcert" / "config.yaml")

    env_path = os.environ.get("PKTCERT_CONFIG")
    if env_path:
        candidates.insert(0, Path(env_path))

    for path in candidates:
        if path.exists():
            return path
    return None


def _load_yaml(path: Optional[Path]) -> dict:
    if path is None:
        return {}
    with path.open() as f:
        return yaml.safe_load(f) or {}


def _default_install_dir(config_path: Optional[Path]) -> Path:
    """The app root: everything else defaults to a path under this."""
    env_dir = os.environ.get("PKTCERT_INSTALL_DIR")
    if env_dir:
        return Path(env_dir)
    if config_path is not None:
        return config_path.resolve().parent
    return Path.cwd()


_CONFIG_PATH = _find_config_path()
_yaml_cfg = _load_yaml(_CONFIG_PATH)
_INSTALL_DIR = _default_install_dir(_CONFIG_PATH)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PKTCERT_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -- Server --------------------------------------------------------------
    host: str = Field(default=_yaml_cfg.get("host", "0.0.0.0"))
    port: int = Field(default=_yaml_cfg.get("port", 8763))
    https_port: int = Field(default=_yaml_cfg.get("https_port", 443))
    workers: int = Field(default=_yaml_cfg.get("workers", 2))
    debug: bool = Field(default=_yaml_cfg.get("debug", False))

    # -- App root — every other path below defaults to somewhere under this --
    install_dir: str = Field(default=_yaml_cfg.get("install_dir", str(_INSTALL_DIR)))

    # -- First-boot admin seed -------------------------------------------------
    # Set by install.sh from PKTCERT_ADMIN_PASSWORD; ignored if DB already has users.
    admin_password: str = Field(default="")

    # -- App database (SQLite) ------------------------------------------------
    db_path: str = Field(
        default=_yaml_cfg.get("db_path", str(_INSTALL_DIR / "pktcert.db"))
    )

    # -- JWT -------------------------------------------------------------------
    secret_key: str = Field(
        default=_yaml_cfg.get("secret_key", "CHANGE_ME_IN_PRODUCTION_secret_key_32chars")
    )
    algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # -- CORS --------------------------------------------------------------------
    cors_origins: list[str] = Field(
        default=_yaml_cfg.get("cors_origins", ["*"])
    )

    # -- pktSuite integration (inbound — pktHub calling into this app) -----------
    suite_token: str = Field(default=_yaml_cfg.get("suite_token", ""))

    # -- Fernet key for encrypting CA private keys and other secrets at rest -----
    credential_key: str = Field(default=_yaml_cfg.get("credential_key", ""))

    # -- Logging -------------------------------------------------------------------
    log_level: str = Field(default=_yaml_cfg.get("log_level", "info"))
    log_file: str = Field(
        default=_yaml_cfg.get("log_file", str(_INSTALL_DIR / "logs" / "pktcert.log"))
    )

    # -- SSL certificate storage -------------------------------------------------
    ssl_dir: str = Field(default=_yaml_cfg.get("ssl_dir", str(_INSTALL_DIR / "ssl")))


@lru_cache
def get_settings() -> Settings:
    return Settings()


# suite_token_from_sqlite_patch — reads token from SQLite so /api/suite/register
# takes effect immediately without service restart.
_patched_get_settings = get_settings  # noqa: save original if it exists

def get_settings() -> Settings:  # type: ignore[misc]
    s = Settings()
    try:
        import sqlite3 as _sq, json as _j
        _db_path = s.db_path
        _conn = _sq.connect(_db_path)
        _row = _conn.execute("SELECT value FROM settings WHERE key='suite_token'").fetchone()
        _conn.close()
        if _row and _row[0]:
            _val = _row[0]
            _tok = _j.loads(_val) if _val.startswith('"') else _val
            if _tok:
                s = s.model_copy(update={'suite_token': _tok})
    except Exception:
        pass
    return s
