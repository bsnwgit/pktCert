#!/usr/bin/env python3
"""
NOC widget tests.

Standalone script — run from the repo root:
    python3 tests/test_widgets.py

The Dashboard's "Inventory by Status" panel draws four bars, each a share of the
whole inventory. Certificate Summary carried the same counts only as tiles, so a
wallboard could not show the bars; Certificates by Status is the widget that
does. What is worth proving about it:

  * it is in the manifest the NOC Builder reads,
  * each bar is a share of the TOTAL inventory (not of the largest status — a
    scale that would make a 1-of-100 revoked count look as big as the valid
    ones), and the labels carry the real counts,
  * an empty inventory says so rather than drawing four empty bars,
  * and the route is not open to anyone who can reach the port.
"""
from __future__ import annotations

import asyncio
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

REPO_ROOT = Path(__file__).resolve().parents[1]

TMP = Path(tempfile.mkdtemp(prefix="pktcert-widgets-"))
SUITE_TOKEN = secrets.token_hex(16)     # generated per run, never a literal
(TMP / "config.yaml").write_text(
    f"install_dir: {TMP}\n"
    f"secret_key: {'a' * 64}\n"
    f"credential_key: {Fernet.generate_key().decode()}\n"
    f"suite_token: {SUITE_TOKEN!r}\n"
)
os.environ["PKTCERT_CONFIG"] = str(TMP / "config.yaml")
os.environ["PKTCERT_INSTALL_DIR"] = str(TMP)
sys.path.insert(0, str(REPO_ROOT))

import aiosqlite                                   # noqa: E402
from fastapi.testclient import TestClient          # noqa: E402

from app.api import widgets                        # noqa: E402
from app.database import init_db                   # noqa: E402
from app.main import app                           # noqa: E402

DB = TMP / "pktcert.db"
FAILURES: list[str] = []


def check(label: str, passed: bool, detail: str = "") -> None:
    print(f"{'PASS' if passed else 'FAIL'}  {label}" + (f"  — {detail}" if detail and not passed else ""))
    if not passed:
        FAILURES.append(label)


async def seed(status: str, n: int) -> None:
    async with aiosqlite.connect(str(DB)) as db:
        for _ in range(n):
            await db.execute(
                """INSERT INTO certificates
                   (common_name, san_json, issuer, subject, serial_number, fingerprint_sha256,
                    not_before, not_after, key_algorithm, key_size, signature_algorithm,
                    status, source)
                   VALUES ('h.example.com', '[]', 'CN=CA', 'CN=h.example.com', ?, ?,
                           datetime('now','-10 days'), datetime('now','+400 days'),
                           'rsa', 2048, 'sha256', ?, 'scan')""",
                (os.urandom(6).hex(), os.urandom(16).hex(), status),
            )
        await db.commit()


def widths_and_values(page: str) -> dict[str, tuple[float, int]]:
    """{label: (bar width %, count shown)} from the rendered bar rows."""
    rows = re.findall(
        r'class="bar-lbl">([^<]+)</div><div class="bar-trk"><div class="bar-fill" style="width:([0-9.]+)%[^"]*"></div></div>'
        r'<div class="bar-val">(\d+)</div>', page)
    return {lbl: (float(w), int(v)) for lbl, w, v in rows}


async def main() -> int:
    await init_db()
    widgets._DB = str(DB)

    print("── manifest ──")
    entry = next((m for m in widgets.MANIFEST if m["id"] == "certs_by_status"), None)
    check("Certificates by Status is in the manifest", entry is not None)
    check("its view_path is the route that serves it",
          bool(entry) and entry["view_path"] == "/api/widgets/certs_by_status")

    print("\n── empty inventory ──")
    page = (await widgets.widget_certs_by_status()).body.decode()
    check("an empty inventory says so", "No certificates in the inventory" in page)
    check("and draws no bars", "bar-row" not in page.replace(".bar-row", ""))

    print("\n── shares of the total ──")
    for status, n in (("valid", 8), ("expiring", 1), ("expired", 0), ("revoked", 1)):
        await seed(status, n)
    page = (await widgets.widget_certs_by_status()).body.decode()
    bars = widths_and_values(page)
    check("all four statuses are drawn", set(bars) == {"Valid", "Expiring", "Expired", "Revoked"}, str(bars))
    check("the labels carry the real counts",
          {k: v[1] for k, v in bars.items()} == {"Valid": 8, "Expiring": 1, "Expired": 0, "Revoked": 1}, str(bars))
    check("each bar is its share of the whole inventory (8 of 10 = 80%)",
          abs(bars.get("Valid", (0, 0))[0] - 80.0) < 0.1, str(bars))
    check("a small status stays small (1 of 10 = 10%), not scaled to the largest",
          abs(bars.get("Revoked", (0, 0))[0] - 10.0) < 0.1, str(bars))
    check("a zero count draws a zero-width bar", bars.get("Expired", (None, 0))[0] == 0.0, str(bars))

    print("\n── access ──")
    client = TestClient(app)
    r = client.get("/api/widgets/certs_by_status")
    check("the route refuses a request with no suite token", r.status_code in (401, 403), str(r.status_code))
    r = client.get("/api/widgets/certs_by_status", headers={"X-Suite-Token": "wrong-token"})
    check("and one with the wrong token", r.status_code in (401, 403), str(r.status_code))
    r = client.get("/api/widgets/certs_by_status", headers={"X-Suite-Token": SUITE_TOKEN})
    check("the right token is served", r.status_code == 200 and "Certificates by Status" in r.text, str(r.status_code))

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: {', '.join(FAILURES)}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
