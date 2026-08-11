"""
Application log forwarding to pktLog (or any syslog collector).

pktcert's own log records are written to the local app_logs table for the
in-app Logs page, which is fine until you want them alongside everything else
in the estate. This ships the same records out as syslog so pktLog can hold
them centrally.

Format is RFC 5424, deliberately. pktLog parses both 3164 and 5424, but 3164
timestamps carry no timezone marker — the parser has to guess an offset, and
guessing wrong has bitten this suite before. 5424 carries a full ISO-8601
timestamp with offset, so there is nothing to guess.

Delivery is fire-and-forget on a background thread. Log forwarding must never
block or crash the thing it is observing: a dropped log line is a nuisance, a
stalled poll loop is an outage. Failures are counted and surfaced via
get_forward_stats() rather than raised.
"""
from __future__ import annotations

import logging
import queue
import socket
import threading
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("pktcert.log_forward")

# RFC 5424 facility 16 (local0) — the conventional choice for app logs.
_FACILITY = 16

# Python level -> syslog severity
_SEVERITY = {
    logging.CRITICAL: 2,   # crit
    logging.ERROR:    3,   # err
    logging.WARNING:  4,   # warning
    logging.INFO:     6,   # info
    logging.DEBUG:    7,   # debug
}

_MAX_QUEUE = 5_000


def _severity_for(levelno: int) -> int:
    for level in (logging.CRITICAL, logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG):
        if levelno >= level:
            return _SEVERITY[level]
    return 7


class SyslogForwardHandler(logging.Handler):
    """Ships log records to a syslog collector over UDP or TCP."""

    def __init__(
        self,
        host: str,
        port: int = 5514,
        protocol: str = "udp",
        app_name: str = "pktcert",
        hostname: Optional[str] = None,
        level: int = logging.INFO,
    ) -> None:
        super().__init__(level=level)
        self.host = host
        self.port = int(port)
        self.protocol = (protocol or "udp").lower()
        self.app_name = app_name
        self.hostname = hostname or socket.gethostname()

        self._queue: queue.Queue = queue.Queue(maxsize=_MAX_QUEUE)
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None
        self._sent = 0
        self._dropped = 0
        self._errors = 0
        self._last_error: str = ""

        self._thread = threading.Thread(
            target=self._run, name="pktcert-log-forward", daemon=True
        )
        self._thread.start()

    # ── formatting ───────────────────────────────────────────────────────────

    def _format_5424(self, record: logging.LogRecord) -> str:
        pri = _FACILITY * 8 + _severity_for(record.levelno)
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).astimezone()
        timestamp = ts.isoformat(timespec="milliseconds")
        msg = record.getMessage()
        if record.exc_info:
            msg = f"{msg} | {logging.Formatter().formatException(record.exc_info)}"
        # Newlines would be read as separate syslog messages by the collector.
        msg = msg.replace("\n", " ").replace("\r", " ")
        procid = record.process or "-"
        msgid = (record.name or "-")[:32]
        return f"<{pri}>1 {timestamp} {self.hostname} {self.app_name} {procid} {msgid} - {msg}"

    # ── logging.Handler ──────────────────────────────────────────────────────

    def emit(self, record: logging.LogRecord) -> None:
        # Never let the forwarder's own logging recurse back into itself.
        if record.name.startswith("pktcert.log_forward"):
            return
        try:
            self._queue.put_nowait(self._format_5424(record))
        except queue.Full:
            self._dropped += 1
        except Exception:
            self._dropped += 1

    # ── worker ───────────────────────────────────────────────────────────────

    def _connect(self) -> None:
        if self.protocol == "tcp":
            s = socket.create_connection((self.host, self.port), timeout=5)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock = s

    def _send(self, line: str) -> None:
        data = line.encode("utf-8", errors="replace")
        if self.protocol == "tcp":
            if self._sock is None:
                self._connect()
            # Octet-counting framing keeps multi-line safety on a stream.
            assert self._sock is not None
            self._sock.sendall(f"{len(data)} ".encode() + data)
        else:
            if self._sock is None:
                self._connect()
            assert self._sock is not None
            self._sock.sendto(data, (self.host, self.port))

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                line = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._send(line)
                self._sent += 1
            except Exception as e:
                self._errors += 1
                self._last_error = str(e)
                # Drop the socket so the next line reconnects.
                try:
                    if self._sock:
                        self._sock.close()
                except Exception:
                    pass
                self._sock = None

    def close(self) -> None:
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        super().close()

    def stats(self) -> dict:
        return {
            "sent": self._sent,
            "dropped": self._dropped,
            "errors": self._errors,
            "last_error": self._last_error,
            "queued": self._queue.qsize(),
            "target": f"{self.host}:{self.port}/{self.protocol}",
        }


# ── module-level wiring ──────────────────────────────────────────────────────

_handler: Optional[SyslogForwardHandler] = None


def configure_forwarding(
    enabled: bool,
    host: str,
    port: int,
    protocol: str,
    level: int = logging.INFO,
    app_name: str = "pktcert",
    logger_name: str = "pktcert",
) -> Optional[SyslogForwardHandler]:
    """(Re)configure forwarding. Safe to call repeatedly — replaces any existing handler."""
    global _handler

    target = logging.getLogger(logger_name)
    if _handler is not None:
        try:
            target.removeHandler(_handler)
            _handler.close()
        except Exception:
            pass
        _handler = None

    if not enabled or not host:
        log.info("Log forwarding disabled")
        return None

    _handler = SyslogForwardHandler(
        host=host, port=port, protocol=protocol, app_name=app_name, level=level
    )
    target.addHandler(_handler)
    if target.level == logging.NOTSET or target.level > level:
        target.setLevel(level)
    log.info(f"Log forwarding enabled -> {host}:{port}/{protocol} (level={logging.getLevelName(level)})")
    return _handler


def get_forward_stats() -> dict:
    if _handler is None:
        return {"enabled": False}
    return {"enabled": True, **_handler.stats()}


def send_test_message(host: str, port: int, protocol: str, app_name: str = "pktcert") -> dict:
    """Send a single test line without touching the live handler."""
    h = SyslogForwardHandler(host=host, port=port, protocol=protocol, app_name=app_name)
    try:
        rec = logging.LogRecord(
            name="pktcert.test", level=logging.INFO, pathname=__file__, lineno=0,
            msg="pktcert log forwarding test message", args=(), exc_info=None,
        )
        h.emit(rec)
        # Give the worker a moment to drain before reporting.
        import time
        for _ in range(20):
            if h._queue.empty():
                break
            time.sleep(0.1)
        s = h.stats()
        ok = s["sent"] > 0 and s["errors"] == 0
        return {"ok": ok, **s}
    finally:
        h.close()
