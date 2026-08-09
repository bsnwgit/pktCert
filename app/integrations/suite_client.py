"""
app/integrations/suite_client.py
----------------------------------
Base HTTP client for pktWiFi acting as a suite-token CLIENT of a sibling
pkt* app (pktsnmp, pktflow, pktlog, pktpcap). This is the mirror image of
app/api/suite.py (which is the INBOUND side — pktHub calling into pktWiFi).

Every pkt* app's get_current_user() dependency trusts three headers when
they're present and X-Suite-Token matches that app's own configured
suite_token:
  X-Suite-Token — the token copied from that app's Settings -> Integrations page
  X-Suite-User  — an identity string (shows up as the "user" in that app's audit trail)
  X-Suite-Role  — admin | analyst | viewer — mapped to that app's local roles

No login/JWT dance is needed — the token itself is the credential, same as
how pktHub proxies requests to every app it manages.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

log = logging.getLogger("pktcert.integrations")


class SuiteClient:
    def __init__(self, base_url: str, suite_token: str, suite_user: str = "pktcert", suite_role: str = "admin"):
        self.base_url = base_url.rstrip("/")
        self.suite_token = suite_token
        self.suite_user = suite_user
        self.suite_role = suite_role

    def _headers(self) -> dict:
        return {
            "X-Suite-Token": self.suite_token,
            "X-Suite-User": self.suite_user,
            "X-Suite-Role": self.suite_role,
        }

    async def get(self, path: str, params: Optional[dict] = None) -> Any:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            resp = await client.get(f"{self.base_url}{path}", headers=self._headers(), params=params)
            resp.raise_for_status()
            return resp.json()

    async def health_check(self) -> tuple[bool, str]:
        """
        Full round trip: reach the host on the configured port AND prove the
        stored suite_token is actually accepted there. Hits /api/suite/whoami
        (authenticated), not the public /api/health — a wrong or revoked
        token must fail this test, not just an unreachable host.
        """
        try:
            data = await self.get("/api/suite/whoami")
            ok = bool(data.get("authenticated"))
            return ok, f"connected and authenticated as {data.get('role', 'unknown')}" if ok else f"unexpected response: {data}"
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (401, 403):
                return False, "reachable, but suite token was rejected — check the token"
            return False, f"HTTP {exc.response.status_code}"
        except httpx.ConnectError as exc:
            return False, f"could not connect to host/port: {exc}"
        except httpx.TimeoutException:
            return False, "connection timed out"
        except Exception as exc:
            return False, str(exc)
