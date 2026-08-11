"""
app/logging_handler.py
----------------------
Background-threaded SQLite log handler for pktCert.

Features
~~~~~~~~
* Batches writes every 2 seconds (non-blocking for the caller).
* Ring-buffers to 10,000 rows — oldest rows deleted automatically.
* Default capture level: WARNING (WARNING, ERROR, CRITICAL).
* Level can be changed at runtime via set_level() — picked up by the
  next flush cycle without restarting the process.
* Attach to any named logger (or the root logger) via attach_to_root_logger().
* Call stop() at shutdown to flush the final batch.
"""
from __future__ import annotations

import logging
import queue
import sqlite3
import threading
import traceback
from pathlib import Path
from typing import Optional

# Maximum rows kept in app_logs; older rows are trimmed after every insert batch.
_MAX_ROWS = 10_000
# How long to wait (seconds) between flush cycles.
_FLUSH_INTERVAL = 2.0

logger = logging.getLogger(__name__)


class SQLiteLogHandler(logging.Handler):
    """
    A logging.Handler that queues records and writes them to SQLite
    asynchronously from a background daemon thread.
    """

    # Capture INFO by default, matching the rest of the suite.
    #
    # A WARNING default makes an app effectively unobservable: lifecycle events
    # (storage selected, collectors started, retention runs) are all INFO, so
    # app_logs stays near-empty and the in-app Logs page shows nothing. A silent
    # app looks identical to a healthy one right up until it isn't.
    def __init__(self, db_path: str | Path, level: int = logging.INFO) -> None:
        super().__init__(level=level)
        self._db_path = str(db_path)
        self._queue: queue.Queue = queue.Queue()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._flush_loop,
            name="pktcert-log-flusher",
            daemon=True,
        )
        self._thread.start()

    # -- Public API ------------------------------------------------------------

    def attach_to_root_logger(self, logger_name: str = "") -> None:
        """Attach this handler to the named logger (or root if empty string)."""
        target = logging.getLogger(logger_name) if logger_name else logging.root
        target.addHandler(self)
        if target.level == logging.NOTSET or target.level > self.level:
            target.setLevel(self.level)

    def set_level(self, level: int) -> None:
        """Change capture level at runtime (thread-safe)."""
        self.setLevel(level)
        for h in logging.root.handlers:
            if h is self:
                logging.root.setLevel(min(logging.root.level or level, level))

    def stop(self) -> None:
        """Signal the background thread to stop and wait for it to flush."""
        self._stop_event.set()
        self._thread.join(timeout=10)

    # -- Internal ----------------------------------------------------------------

    def emit(self, record: logging.LogRecord) -> None:
        """Called by the logging framework; enqueue the record immediately."""
        try:
            exc_text: Optional[str] = None
            if record.exc_info:
                exc_text = "".join(traceback.format_exception(*record.exc_info))
            self._queue.put_nowait(
                (
                    record.levelname,
                    record.levelno,
                    record.name,
                    self.format(record),
                    exc_text,
                )
            )
        except Exception:
            self.handleError(record)

    def _flush_loop(self) -> None:
        """Background thread: drain the queue every _FLUSH_INTERVAL seconds."""
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=_FLUSH_INTERVAL)
            self._drain()
        self._drain()

    def _drain(self) -> None:
        """Pull everything from the queue and write to SQLite in one transaction."""
        rows: list[tuple] = []
        try:
            while True:
                rows.append(self._queue.get_nowait())
        except queue.Empty:
            pass

        if not rows:
            return

        try:
            con = sqlite3.connect(self._db_path, timeout=5)
            with con:
                con.executemany(
                    """
                    INSERT INTO app_logs (level, level_no, logger, message, exc_info)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    rows,
                )
                con.execute(
                    """
                    DELETE FROM app_logs
                    WHERE id <= (
                        SELECT id FROM app_logs
                        ORDER BY id DESC
                        LIMIT 1 OFFSET ?
                    )
                    """,
                    (_MAX_ROWS - 1,),
                )
            con.close()
        except Exception as exc:
            import sys
            print(f"[SQLiteLogHandler] Failed to write logs: {exc}", file=sys.stderr)
