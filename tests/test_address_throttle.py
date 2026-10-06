#!/usr/bin/env python3
"""
Per-address throttle on failed sign-ins.

Standalone script — run from the repo root:
    python3 tests/test_address_throttle.py

The account lockout stops one account being guessed at; this stops one address
guessing at many. The properties worth proving:

  * enough failures from one address block it — whatever usernames were tried,
    known or not — and while blocked even correct credentials are refused,
  * another address is unaffected,
  * failures stop counting once the window passes, and the count starts again
    after a block ends,
  * a successful sign-in does not reset the count,
  * a wrong current password at the change-password form counts too,
  * a request for a locked account is not counted,
  * the limit, the window and the block length are settings, and an unusable
    value falls back to the default.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

REPO_ROOT = Path(__file__).resolve().parents[1]

TMP = Path(tempfile.mkdtemp(prefix="pktcert-throttle-"))
(TMP / "config.yaml").write_text(
    f"install_dir: {TMP}\n"
    f"db_path: {TMP}/pktcert.db\n"
    f"log_file: {TMP}/app.log\n"
    f"ssl_dir: {TMP}/ssl\n"
    f"secret_key: {'a' * 64}\n"
    f"credential_key: {Fernet.generate_key().decode()}\n"
    f"suite_token: ''\n"
)
os.environ["PKTCERT_CONFIG"] = str(TMP / "config.yaml")
os.environ["PKTCERT_INSTALL_DIR"] = str(TMP)
os.environ["PKTCERT_ADMIN_PASSWORD"] = "admin-test-password"
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient           # noqa: E402

from app.auth.local import hash_password            # noqa: E402
from app.main import app                            # noqa: E402

DB = TMP / "pktcert.db"
GOOD, BAD = "right-password", "wrong-password"
FAILURES: list[str] = []


def check(label: str, passed: bool, detail: str = "") -> None:
    print(f"{'PASS' if passed else 'FAIL'}  {label}" + (f"  — {detail}" if detail and not passed else ""))
    if not passed:
        FAILURES.append(label)


def sql(query: str, *params):
    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(query, params).fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


def make_user(name: str) -> None:
    sql("INSERT INTO users (username, email, hashed_password, role) VALUES (?, ?, ?, 'viewer')",
        name, f"{name}@example.com", hash_password(GOOD))


def set_setting(key: str, value) -> None:
    import json
    sql("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        key, json.dumps(value))


def reset_settings() -> None:
    sql("DELETE FROM settings WHERE key LIKE 'address_%' OR key = 'login_max_failed_attempts'")


def count(address: str) -> int:
    return sql("SELECT COUNT(*) AS n FROM address_failures WHERE address = ?", address)[0]["n"]


def main() -> int:
    with TestClient(app):          # starts the app once: schema, seeded admin
        pass

    def at(ip: str) -> TestClient:
        """A client whose requests come from `ip`."""
        return TestClient(app, client=(ip, 50000))

    def login(c: TestClient, user: str, pw: str):
        return c.post("/api/auth/login", json={"username": user, "password": pw})

    def fail_unknown(c: TestClient, n: int, start: int = 0) -> list[int]:
        return [login(c, f"nobody{start + i}", BAD).status_code for i in range(n)]

    print("── an address that keeps failing is blocked ──")
    make_user("alice")
    a, b = at("203.0.113.1"), at("203.0.113.2")
    codes = fail_unknown(a, 10)
    check("nine failures are plain refusals", codes[:9] == [401] * 9, str(codes))
    check("the tenth, with a different username each time, blocks the address", codes[9] == 429, str(codes))
    r = login(a, "alice", GOOD)
    check("then even correct credentials are refused", r.status_code == 429, f"{r.status_code} {r.text}")
    ra = int(r.headers.get("retry-after", "0"))
    check("with a Retry-After of about the default 15 minutes", 800 <= ra <= 900, str(ra))
    check("and a message that says how long", "about 15 minutes" in r.json()["detail"], r.text)
    check("another address is unaffected", login(b, "alice", GOOD).status_code == 200)

    print("\n── a block ends, and the count starts again ──")
    sql("UPDATE address_blocks SET blocked_until = datetime('now', '-1 minutes') WHERE address = '203.0.113.1'")
    check("once it has run out the address can sign in", login(a, "alice", GOOD).status_code == 200)
    check("the failures that caused the block were cleared", count("203.0.113.1") == 0, str(count("203.0.113.1")))
    codes = fail_unknown(a, 9, start=100)
    check("so nine more failures do not block it again", codes == [401] * 9, str(codes))

    print("\n── failures stop counting after the window ──")
    c = at("203.0.113.3")
    fail_unknown(c, 9)
    sql("UPDATE address_failures SET ts = datetime('now', '-20 minutes') WHERE address = '203.0.113.3'")
    codes = fail_unknown(c, 9, start=200)
    check("nine old failures plus nine new ones do not block", codes == [401] * 9, str(codes))
    check("the tenth new one does", fail_unknown(c, 1, start=300) == [429])

    print("\n── signing in does not reset the count ──")
    d = at("203.0.113.4")
    fail_unknown(d, 5)
    check("a successful sign-in from the address works", login(d, "alice", GOOD).status_code == 200)
    codes = fail_unknown(d, 5, start=400)
    check("and the next five failures still reach the limit", codes == [401, 401, 401, 401, 429], str(codes))

    print("\n── what counts ──")
    e = at("203.0.113.5")
    make_user("bob")
    login(e, "bob", BAD)
    login(e, "nobody-at-all", BAD)
    check("a wrong password and an unknown username both count", count("203.0.113.5") == 2, str(count("203.0.113.5")))
    check("and the account's own failure count is kept too",
          sql("SELECT failed_login_count AS n FROM users WHERE username = 'bob'")[0]["n"] == 1)
    make_user("lockee")
    f = at("203.0.113.6")
    for _ in range(3):
        login(f, "lockee", BAD)
    before = count("203.0.113.6")
    for _ in range(4):
        login(f, "lockee", BAD)
    check("requests for a locked account are not counted", count("203.0.113.6") == before, f"{before} -> {count('203.0.113.6')}")

    print("\n── changing a password counts too ──")
    set_setting("address_max_failed_attempts", 4)
    set_setting("login_max_failed_attempts", 100)     # keep the account lock out of the way
    make_user("carol")
    g = at("203.0.113.7")
    token = login(g, "carol", GOOD).json()["access_token"]
    gh = {"Authorization": f"Bearer {token}"}

    def change(current: str):
        return g.post("/api/users/me/change-password", json={"current_password": current, "new_password": "a-new-password"}, headers=gh)

    codes = [change(BAD).status_code for _ in range(4)]
    check("wrong current passwords count toward the address, and the fourth blocks it", codes == [401, 401, 401, 429], str(codes))
    check("the blocked address cannot change it even with the right one", change(GOOD).status_code == 429)
    check("nor sign in", login(g, "carol", GOOD).status_code == 429)
    reset_settings()

    print("\n── the settings ──")
    set_setting("address_max_failed_attempts", 3)
    h = at("203.0.113.8")
    check("a limit of 3 blocks on the third", fail_unknown(h, 3) == [401, 401, 429])
    reset_settings()

    set_setting("address_block_minutes", 1)
    set_setting("address_max_failed_attempts", 2)
    i = at("203.0.113.9")
    fail_unknown(i, 1)
    r = i.post("/api/auth/login", json={"username": "nobody-x", "password": BAD})
    check("the block length is a setting", r.status_code == 429 and 1 <= int(r.headers["retry-after"]) <= 60,
          f"{r.status_code} {r.headers.get('retry-after')}")
    reset_settings()

    set_setting("address_failure_window_minutes", 1)
    set_setting("address_max_failed_attempts", 3)
    j = at("203.0.113.10")
    fail_unknown(j, 2)
    sql("UPDATE address_failures SET ts = datetime('now', '-2 minutes') WHERE address = '203.0.113.10'")
    check("the window is a setting: failures older than it do not count", fail_unknown(j, 2, start=500) == [401, 401])
    reset_settings()

    set_setting("address_max_failed_attempts", "junk")
    set_setting("address_failure_window_minutes", 0)
    set_setting("address_block_minutes", -5)
    k = at("203.0.113.11")
    codes = fail_unknown(k, 10)
    check("unusable values fall back to the defaults (10 failures)", codes[:9] == [401] * 9 and codes[9] == 429, str(codes))
    r = login(k, "alice", GOOD)
    check("and the default block length", 800 <= int(r.headers.get("retry-after", "0")) <= 900)
    reset_settings()

    print("\n── a request with no client address ──")
    nobody = TestClient(app, client=None)
    login(nobody, "nobody", BAD)
    login(nobody, "nobody", BAD)
    check("is counted under one shared name rather than skipped", count("unknown") == 2, str(count("unknown")))

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
