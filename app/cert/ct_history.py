"""
History of Certificate Transparency checks (crt.sh validations).

Every validation — of an inventory certificate or of one pasted or fetched on
the CT Checks page — leaves a row, so everyone with a login can see what has
been checked and what the answer was, rather than each person repeating a
lookup against a free shared service.

What is kept is what identifies the certificate and the verdict, plus the full
result so a row can be expanded later. A PEM is never stored.
"""
from __future__ import annotations

import json
from typing import Any

import aiosqlite


async def record_check(
    db: aiosqlite.Connection,
    *,
    username: str,
    source: str,
    certificate_id: int | None,
    cert: dict[str, Any],
    result: dict[str, Any],
    fetched_from: str | None = None,
) -> int:
    cur = await db.execute(
        """INSERT INTO ct_checks
           (checked_by, source, certificate_id, common_name, issuer, serial_number,
            fingerprint_sha256, not_after, fetched_from, verdict, unexpected_count, result_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            username, source, certificate_id,
            cert.get("common_name") or "", cert.get("issuer") or "",
            cert.get("serial_number") or "", cert.get("fingerprint_sha256") or "",
            cert.get("not_after"), fetched_from, result["verdict"],
            len(result.get("unexpected") or []), json.dumps(result),
        ),
    )
    await db.commit()
    return cur.lastrowid
