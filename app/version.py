"""
Reads this app's VERSION file — see scripts/bump_version.py for the
vMajor.Minor.Patch.CodeName[.Hotfix] format and bump rule.
"""
from __future__ import annotations

from pathlib import Path

from app.config import get_settings


def get_version() -> str:
    cfg = get_settings()
    for candidate in [Path("VERSION"), Path(cfg.install_dir) / "VERSION"]:
        if candidate.exists():
            return candidate.read_text().strip()
    return "0.0.0.unknown"
