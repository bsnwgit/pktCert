#!/usr/bin/env python3
"""
Backup-bundle step-up re-auth test.

Standalone script — run from the repo root:
    python3 tests/test_export_stepup.py

The full backup bundle contains pktcert.db AND config.yaml: every encrypted
secret, plus the credential_key that decrypts them, in one file that lands in
a Downloads folder. It used to be a plain authenticated GET, so any live admin
session — a borrowed laptop, an unlocked screen, a stolen token — could pull
every CA private key in one request. It now requires the caller's current
password, the same bar as revealing any other stored secret.

This same change was applied across all nine pkt apps that ship an export
bundle; pktCert is where it's regression-tested, since it's the app whose
bundle carries CA private keys.
"""
import os, sys, tempfile, asyncio
from pathlib import Path
from cryptography.fernet import Fernet

TMP = Path(tempfile.mkdtemp(prefix="pktcert-export-"))
(TMP/"config.yaml").write_text(
    f"install_dir: {TMP}\nsecret_key: {'a'*64}\ncredential_key: {Fernet.generate_key().decode()}\nsuite_token: ''\n")
os.environ["PKTCERT_CONFIG"] = str(TMP/"config.yaml")
os.environ["PKTCERT_INSTALL_DIR"] = str(TMP)
os.environ["PKTCERT_ADMIN_PASSWORD"] = "correct-horse-battery"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from app.database import init_db, seed_admin
from app.dependencies import get_current_user
from app.main import app

asyncio.run(init_db()); asyncio.run(seed_admin())
app.dependency_overrides[get_current_user] = lambda: {
    "id": 1, "username": "admin", "role": "admin", "is_active": True}
c = TestClient(app)
fails = []
def check(label, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f"  — {detail}" if detail and not ok else ""))
    if not ok: fails.append(label)

# 404 rather than 405: with the GET route gone, the SPA catch-all handles it
# and refuses anything under /api/. Either way the old GET no longer works.
_get = c.get("/api/system/export").status_code
check("the old unauthenticated GET no longer works", _get in (404, 405), f"got {_get}")
r = c.post("/api/system/export", json={"password": "wrong"})
check("wrong password is rejected", r.status_code == 401, f"HTTP {r.status_code}")
r = c.post("/api/system/export", json={})
check("missing password is rejected", r.status_code == 422, f"HTTP {r.status_code}")
r = c.post("/api/system/export", json={"password": "correct-horse-battery"})
check("correct password returns the bundle", r.status_code == 200, f"HTTP {r.status_code}: {r.text[:120]}")
check("and it is a gzip archive", r.content[:2] == b"\x1f\x8b", repr(r.content[:8]))
check("served as an attachment", "attachment" in r.headers.get("content-disposition", ""),
      r.headers.get("content-disposition", ""))
import io, tarfile
names = tarfile.open(fileobj=io.BytesIO(r.content)).getnames()
check("bundle still contains db + config + restore notes",
      {"pktcert.db","config.yaml","RESTORE.md"} <= set(names), str(names))
print()
print("ALL PASS" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
