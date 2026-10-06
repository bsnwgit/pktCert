#!/usr/bin/env python3
"""
Unlock a user locked out by repeated failed logins, from the host.

The Users tab does this too, but it needs an admin who can still sign in. If
the locked account is the only admin, this is the way back in.

Run from the repo root (or install directory), with the app's own Python:
    python3 scripts/unlock_user.py <username-or-email>
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip().split("\n\n")[-1], file=sys.stderr)
        return 2
    who = sys.argv[1]
    conn = sqlite3.connect(get_settings().db_path)
    try:
        cur = conn.execute(
            "UPDATE users SET failed_login_count = 0, lockout_count = 0, locked_until = NULL, is_locked = 0 "
            "WHERE username = ? OR email = ?",
            (who, who),
        )
        conn.commit()
    finally:
        conn.close()
    if cur.rowcount == 0:
        print(f"No user '{who}'.", file=sys.stderr)
        return 1
    print(f"Unlocked '{who}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
