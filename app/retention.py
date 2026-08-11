"""
Retention scheduler.

`run_cleanup_once()` in app.cert.alert_engine has existed since v1, but its own
docstring said the schedule "isn't wired here" — it was reachable only from the
Data → Storage "Run Cleanup" button. In practice that means retention was never
enforced on any deployment where nobody clicked it, and resolved alert_events
accumulated indefinitely.

This is the missing schedule. It is deliberately the same shape as pktSNMP's
storage retention, where the identical gap let a table reach 129 million rows
before anyone noticed.

Every run is logged, including runs that delete nothing — "ran and removed 0
rows" has to stay distinguishable from "never ran", because the second one is
what hid the original bug.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

log = logging.getLogger("pktcert.retention")

# Retention is expressed in days, so once a day is enough.
_INTERVAL_SECONDS = 86_400

# Startup already runs migrations and the first certificate sweep; a prune
# racing that would only make a slow boot slower.
_FIRST_RUN_DELAY_SECONDS = 300


class RetentionScheduler:
    def __init__(self, interval_seconds: int = _INTERVAL_SECONDS):
        self._interval = interval_seconds
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run_loop())
        log.info(f"Retention scheduler started (interval={self._interval}s)")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def run_once(self) -> dict:
        from app.cert.alert_engine import run_cleanup_once

        result = await run_cleanup_once()
        log.info(f"Retention run complete: {result}")
        return result

    async def _run_loop(self) -> None:
        await asyncio.sleep(_FIRST_RUN_DELAY_SECONDS)
        while True:
            try:
                await self.run_once()
            except Exception as e:
                log.error(f"Retention error: {e}")
            await asyncio.sleep(self._interval)
