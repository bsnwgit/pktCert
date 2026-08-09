"""
Production entrypoint — reads host/port from Settings (config.yaml) at
process start, instead of a fixed --port flag in the systemd unit. This is
what lets Settings → General "Port" actually take effect on restart: saving
just rewrites config.yaml, and the next process start picks it up here.

Also auto-detects an uploaded SSL cert (Settings → Security → SSL/TLS
writes to <ssl_dir>/server.crt + server.key) and switches to HTTPS
automatically — no systemd unit edit needed.
"""
from __future__ import annotations

from pathlib import Path

import uvicorn

from app.config import get_settings


def main() -> None:
    settings = get_settings()
    kwargs = dict(
        host=settings.host,
        port=settings.port,
        workers=1,
        log_level="info",
        access_log=False,
    )

    cert = Path(settings.ssl_dir) / "server.crt"
    key = Path(settings.ssl_dir) / "server.key"
    if cert.exists() and key.exists():
        kwargs["ssl_certfile"] = str(cert)
        kwargs["ssl_keyfile"] = str(key)

    uvicorn.run("app.main:app", **kwargs)


if __name__ == "__main__":
    main()
