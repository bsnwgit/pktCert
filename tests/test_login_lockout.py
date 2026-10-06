#!/usr/bin/env python3
"""
Failed-login lockout.

Standalone script — run from the repo root:
    python3 tests/test_login_lockout.py

The properties worth proving:

  * the configured number of failures locks an account for 30 minutes, and
    while it is locked even the right password is refused,
  * once that lock lapses, the same number of failures again locks it for good,
    and a lapsed time no longer matters,
  * a successful login wipes the record of an earlier lockout, so an old lock
    never turns the next one permanent,
  * an admin can unlock a user, and so can the host-side script,
  * the limit is a setting, with 3 as the default when it is missing or junk,
  * a wrong current password when changing a password counts as a failed
    login and locks the account the same way, so a signed-in session cannot be
    used to guess it,
  * an unknown username is refused without anything being counted,
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

REPO_ROOT = Path(__file__).resolve().parents[1]

TMP = Path(tempfile.mkdtemp(prefix="pktcert-lockout-"))
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


def row(name: str):
    return sql("SELECT * FROM users WHERE username = ?", name)[0]


def lapse(name: str) -> None:
    """Let a temporary lock run out without waiting 30 minutes."""
    sql("UPDATE users SET locked_until = datetime('now', '-1 minutes') WHERE username = ?", name)


def main() -> int:
    with TestClient(app) as client:
        def login(user: str, pw: str):
            return client.post("/api/auth/login", json={"username": user, "password": pw})

        def fail(user: str, n: int) -> list[int]:
            return [login(user, BAD).status_code for _ in range(n)]

        # Every attempt below comes from one address; this test is about the account
        # lockout, so keep the per-address limit (tests/test_address_throttle.py) out of its way.
        sql("INSERT INTO settings (key, value) VALUES ('address_max_failed_attempts', '10000')")

        print("── first lockout ──")
        make_user("bob")
        codes = fail("bob", 3)
        check("failures below the limit are plain refusals", codes[:2] == [401, 401], str(codes))
        check("the failure that reaches it locks the account", codes[2] == 423, str(codes))
        r = login("bob", GOOD)
        check("the right password is refused while locked", r.status_code == 423, str(r.status_code))
        check("and the message says when to try again", "Try again after" in r.json()["detail"], r.text)
        check("the lock is temporary, not permanent", row("bob")["is_locked"] == 0 and row("bob")["locked_until"])

        print("\n── a lapsed lock, then a second round ──")
        lapse("bob")
        check("once it lapses nothing stops the next attempt", login("bob", BAD).status_code == 401)
        codes = fail("bob", 2)
        check("the same number of failures again locks it permanently",
              codes[-1] == 423 and row("bob")["is_locked"] == 1, str(codes))
        lapse("bob")
        r = login("bob", GOOD)
        check("a permanent lock ignores the clock", r.status_code == 423, str(r.status_code))
        check("and says an admin must unlock it", "administrator" in r.json()["detail"], r.text)

        print("\n── an admin unlocks ──")
        admin = login("admin", "admin-test-password")
        check("the seeded admin can sign in", admin.status_code == 200, admin.text)
        h = {"Authorization": f"Bearer {admin.json()['access_token']}"}
        listed = {u["username"]: u for u in client.get("/api/users", headers=h).json()}
        check("the user list shows the lock", listed["bob"]["is_locked"] and listed["bob"]["lock_permanent"],
              str(listed["bob"]))
        check("and an unlocked user as not locked", not listed["admin"]["is_locked"])
        r = client.post(f"/api/users/{row('bob')['id']}/unlock", headers=h)
        check("unlock succeeds", r.status_code == 204, str(r.status_code))
        check("the user can sign in again", login("bob", GOOD).status_code == 200)
        check("unlocking an unknown user is a 404", client.post("/api/users/99999/unlock", headers=h).status_code == 404)
        make_user("viewer1")
        vh = {"Authorization": f"Bearer {login('viewer1', GOOD).json()['access_token']}"}
        check("a non-admin cannot unlock", client.post(f"/api/users/{row('bob')['id']}/unlock", headers=vh).status_code == 403)

        print("\n── a successful login clears earlier lockouts ──")
        make_user("carol")
        fail("carol", 3)
        lapse("carol")
        check("one lockout on record", row("carol")["lockout_count"] == 1)
        check("signing in succeeds after it lapses", login("carol", GOOD).status_code == 200)
        check("which wipes the record", row("carol")["lockout_count"] == 0 and row("carol")["failed_login_count"] == 0)
        codes = fail("carol", 3)
        check("so the next lockout is temporary again, not permanent",
              codes[-1] == 423 and row("carol")["is_locked"] == 0, str(codes))

        print("\n── failures that fall short ──")
        make_user("dave")
        fail("dave", 2)
        login("dave", GOOD)
        check("a success resets the failure count", row("dave")["failed_login_count"] == 0)
        codes = fail("dave", 2)
        check("so two more failures do not lock", codes == [401, 401], str(codes))

        print("\n── the limit is a setting ──")
        make_user("erin")
        sql("INSERT INTO settings (key, value) VALUES ('login_max_failed_attempts', '5')")
        codes = fail("erin", 5)
        check("with 5, four failures do not lock", codes[:4] == [401] * 4, str(codes))
        check("and the fifth does", codes[4] == 423, str(codes))
        make_user("frank")
        sql("UPDATE settings SET value = '\"junk\"' WHERE key = 'login_max_failed_attempts'")
        check("an unusable value falls back to 3", fail("frank", 3)[-1] == 423)
        make_user("gina")
        sql("DELETE FROM settings WHERE key = 'login_max_failed_attempts'")
        check("so does no value at all", fail("gina", 3)[-1] == 423)

        print("\n── changing a password counts too ──")
        def headers_for(name: str, pw: str = GOOD) -> dict:
            return {"Authorization": f"Bearer {login(name, pw).json()['access_token']}"}

        def change(h: dict, current: str, new: str = "a-new-password"):
            return client.post("/api/users/me/change-password",
                               json={"current_password": current, "new_password": new}, headers=h)

        make_user("nina")
        nh = headers_for("nina")
        codes = [change(nh, BAD).status_code for _ in range(3)]
        check("wrong current passwords are refused, and the third locks", codes == [401, 401, 423], str(codes))
        check("the right current password is then refused too", change(nh, GOOD).status_code == 423)
        check("the same lock applies to signing in", login("nina", GOOD).status_code == 423)
        check("a session already open keeps working", client.get("/api/users/me", headers=nh).status_code == 200)
        lapse("nina")
        codes = [change(nh, BAD).status_code for _ in range(3)]
        check("a second round locks it permanently", codes[-1] == 423 and row("nina")["is_locked"] == 1, str(codes))
        check("an admin unlock lifts it", client.post(f"/api/users/{row('nina')['id']}/unlock", headers=h).status_code == 204)
        check("and the password can then be changed", change(nh, GOOD, "brand-new-password").status_code == 200)
        check("the new password signs in", login("nina", "brand-new-password").status_code == 200)
        check("counters are clear", row("nina")["failed_login_count"] == 0 and row("nina")["lockout_count"] == 0)

        make_user("omar")
        oh = headers_for("omar")
        change(oh, BAD)
        check("a failure is counted", row("omar")["failed_login_count"] == 1)
        check("a successful change clears it", change(oh, GOOD).status_code == 200 and row("omar")["failed_login_count"] == 0)
        check("sign-in is required", client.post("/api/users/me/change-password",
                                                 json={"current_password": GOOD, "new_password": "x" * 8}).status_code == 401)

        print("\n── accounts that do not exist ──")
        before = sql("SELECT COUNT(*) AS n FROM users")[0]["n"]
        check("an unknown username is refused plainly", fail("nobody", 5) == [401] * 5)
        check("and nothing is created or counted", sql("SELECT COUNT(*) AS n FROM users")[0]["n"] == before)

        print("\n── the host-side unlock ──")
        make_user("hank")
        fail("hank", 3)
        lapse("hank")
        fail("hank", 3)
        check("locked permanently", row("hank")["is_locked"] == 1)
        env = dict(os.environ)
        done = subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "unlock_user.py"), "hank"],
                              env=env, capture_output=True, text=True, cwd=str(REPO_ROOT))
        check("the script reports success", done.returncode == 0, done.stderr + done.stdout)
        check("and the account signs in", login("hank", GOOD).status_code == 200)
        done = subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "unlock_user.py"), "nobody"],
                              env=env, capture_output=True, text=True, cwd=str(REPO_ROOT))
        check("an unknown user is reported, not ignored", done.returncode == 1)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
