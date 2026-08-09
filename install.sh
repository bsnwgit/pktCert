#!/bin/bash
# pktCert install script — Ubuntu Server 22.04/24.04 LTS
# Usage: bash install.sh
# Prompts for the install directory (default /opt/pktcert) and port (default
# 8763) when run interactively.
# Override defaults with env vars to skip the prompts, e.g.:
#   PKTCERT_INSTALL_DIR=/opt/pktcert PKTCERT_SERVICE_USER=pktcert PKTCERT_PORT=8763 bash install.sh

set -euo pipefail

if [ -z "${PKTCERT_INSTALL_DIR:-}" ] && [ -t 0 ]; then
    read -rp "Install directory [/opt/pktcert]: " INSTALL_DIR_INPUT
    INSTALL_DIR="${INSTALL_DIR_INPUT:-/opt/pktcert}"
else
    INSTALL_DIR="${PKTCERT_INSTALL_DIR:-/opt/pktcert}"
fi
# Normalize: expand a leading ~ (read/env vars don't do this automatically —
# a literal "~" ends up baked into config.yaml and the systemd unit, and
# systemd rejects a WorkingDirectory that isn't an absolute path), and
# strip any trailing slash so the REPO_DIR/INSTALL_DIR string-equality
# check below (in-place install guard) isn't fooled by "/path/" vs "/path".
case "$INSTALL_DIR" in
    "~") INSTALL_DIR="$HOME" ;;
    "~/"*) INSTALL_DIR="$HOME/${INSTALL_DIR#\~/}" ;;
esac
INSTALL_DIR="${INSTALL_DIR%/}"
if [ -z "${PKTCERT_PORT:-}" ] && [ -t 0 ]; then
    read -rp "Port [8763]: " PORT_INPUT
    PORT="${PORT_INPUT:-8763}"
else
    PORT="${PKTCERT_PORT:-8763}"
fi
LOG_DIR="${PKTCERT_LOG_DIR:-$INSTALL_DIR/logs}"
SERVICE_USER="${PKTCERT_SERVICE_USER:-$(whoami)}"
SERVICE_GROUP="${PKTCERT_SERVICE_GROUP:-$SERVICE_USER}"
VENV="$INSTALL_DIR/venv"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$SCRIPT_DIR"
LOCAL_IP="$(hostname -I | awk '{print $1}')"

echo "=== pktCert Installer ==="
echo "Install dir: $INSTALL_DIR"
echo "Service user: $SERVICE_USER"
echo "Port: $PORT"
echo ""

# -- 1. System packages --------------------------------------------------------
echo "[1/8] Installing system packages..."
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    libssl-dev libffi-dev \
    libxmlsec1-dev libxmlsec1-openssl libxml2-dev pkg-config gcc \
    curl ca-certificates

# -- 2. Create install + log directories ---------------------------------------
echo "[2/8] Creating directories..."
sudo mkdir -p "$INSTALL_DIR"
sudo mkdir -p "$LOG_DIR"
sudo mkdir -p "$INSTALL_DIR/ssl"
# Owned by the invoking user for now so the steps below don't need sudo;
# re-owned to $SERVICE_USER:$SERVICE_GROUP at the end (step 8).
sudo chown "$(whoami):$(whoami)" "$INSTALL_DIR" "$LOG_DIR"

# -- 3. Python virtualenv -------------------------------------------------------
echo "[3/8] Setting up Python virtualenv..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$REPO_DIR/requirements.txt"
echo "  Python dependencies installed."

# -- 4. Copy application files --------------------------------------------------
echo "[4/8] Copying application files..."
if [ "$REPO_DIR" = "$INSTALL_DIR" ]; then
    echo "  Install dir is the repo checkout itself — nothing to copy."
else
    cp -r "$REPO_DIR/app"        "$INSTALL_DIR/"
    cp -r "$REPO_DIR/migrations" "$INSTALL_DIR/"
    cp -r "$REPO_DIR/docs"       "$INSTALL_DIR/"
    cp -r "$REPO_DIR/icon.svg" "$REPO_DIR/lockup.svg" "$INSTALL_DIR/" 2>/dev/null || true
fi

# -- 5. Configure ----------------------------------------------------------------
echo "[5/8] Setting up config..."
if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
    cp "$REPO_DIR/config.example.yaml" "$INSTALL_DIR/config.yaml"
    # Generate a random JWT secret key
    SECRET=$(openssl rand -hex 32)
    sed -i "s/CHANGE_ME_generate_with_openssl_rand_hex_32/$SECRET/" "$INSTALL_DIR/config.yaml"
    # Generate a Fernet key for encrypting CA private keys and other secrets at rest
    CRED_KEY=$("$VENV/bin/python3" -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    sed -i "s#CHANGE_ME_generate_with_fernet_generate_key#$CRED_KEY#" "$INSTALL_DIR/config.yaml"
    sed -i "s#http://SERVER-IP:8763#http://$LOCAL_IP:$PORT#g" "$INSTALL_DIR/config.yaml"
    sed -i "s/^port: 8763/port: $PORT/" "$INSTALL_DIR/config.yaml"
    # Pin install_dir explicitly (app/config.py derives every other path —
    # db, logs, ssl, backups — from this by default).
    echo "install_dir: \"$INSTALL_DIR\"" >> "$INSTALL_DIR/config.yaml"
    echo "  Config created at $INSTALL_DIR/config.yaml"
    echo "  !! Review and update cors_origins before production use !!"
else
    echo "  Config already exists — skipping."
fi

# -- 6. Apply migrations + create admin user -----------------------------------
echo "[6/8] Initializing database and admin user..."
ADMIN_PASS=$(openssl rand -base64 12 | tr -d '/+=' | head -c 16)

PKTCERT_CONFIG="$INSTALL_DIR/config.yaml" \
PKTCERT_INSTALL_DIR="$INSTALL_DIR" \
PKTCERT_ADMIN_PASSWORD="$ADMIN_PASS" \
"$VENV/bin/python3" - << PYEOF
import asyncio, sys
sys.path.insert(0, '$INSTALL_DIR')

from app.database import init_db, seed_admin

async def setup():
    await init_db()
    await seed_admin()
    print("  Database initialized.")

asyncio.run(setup())
PYEOF

# -- 7. Build frontend -----------------------------------------------------------
# Not installing Node.js itself here (see README Requirements — version
# management is left to the operator), but if it's already present, just
# build it — there's no reason to leave this as a manual step when we can.
echo "[7/8] Building frontend..."
FRONTEND_BUILT=0
if command -v npm &>/dev/null; then
    ( cd "$REPO_DIR/frontend" && npm install --no-audit --no-fund && npm run build )
    mkdir -p "$INSTALL_DIR/frontend"
    if [ "$REPO_DIR/frontend/dist" != "$INSTALL_DIR/frontend/dist" ]; then
        rm -rf "$INSTALL_DIR/frontend/dist"
        cp -r "$REPO_DIR/frontend/dist" "$INSTALL_DIR/frontend/dist"
    fi
    FRONTEND_BUILT=1
    echo "  Frontend built and deployed."
else
    echo "  npm not found — skipping (Node.js is required; see README Requirements)."
    echo "  The web UI will return \"Not Found\" until you build it manually — see the"
    echo "  banner at the end of this script for the exact commands."
fi

# -- 8. Install systemd service ----------------------------------------------------
echo "[8/8] Installing systemd service..."
# Re-own the install/log dirs to the service user before starting the service.
sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR" "$LOG_DIR"
sed \
    -e "s#__INSTALL_DIR__#$INSTALL_DIR#g" \
    -e "s#__LOG_DIR__#$LOG_DIR#g" \
    -e "s#__SERVICE_USER__#$SERVICE_USER#g" \
    -e "s#__SERVICE_GROUP__#$SERVICE_GROUP#g" \
    "$REPO_DIR/pktcert.service" | sudo tee /etc/systemd/system/pktcert.service > /dev/null
sudo systemctl daemon-reload
sudo systemctl enable pktcert
sudo systemctl start pktcert

echo ""
echo "+----------------------------------------------------------+"
echo "|             pktCert installed successfully!               |"
echo "+----------------------------------------------------------+"
printf "|  URL:           http://%-35s|\n" "$LOCAL_IP:$PORT"
echo "|  Username:      admin                                    |"
printf "|  Password:      %-43s|\n" "$ADMIN_PASS"
echo "|                                                          |"
echo "|  SAVE THESE CREDENTIALS — they won't be shown again!     |"
echo "+----------------------------------------------------------+"
echo ""
if [ "$FRONTEND_BUILT" -eq 0 ]; then
    echo "!! Frontend was NOT built (npm not found) — the web UI will show"
    echo "!! {\"detail\":\"Not Found\"} until you run:"
    echo "!!   cd $REPO_DIR/frontend && npm install && npm run build"
    if [ "$REPO_DIR/frontend/dist" != "$INSTALL_DIR/frontend/dist" ]; then
        echo "!!   mkdir -p $INSTALL_DIR/frontend && cp -r $REPO_DIR/frontend/dist $INSTALL_DIR/frontend/dist"
    fi
    echo "!!   sudo systemctl restart pktcert"
    echo ""
fi
echo "Next steps:"
echo "  1. Open the firewall for TCP $PORT"
echo "  2. Log in and change the admin password (top-left user menu)"
echo "  3. Add a Scan Target to discover TLS certs on your network, and/or generate a Certificate Authority under Certificate Authorities to start issuing your own"
echo "  4. Copy the Suite Token (Settings -> Security -> Suite Integration) into pktHub's App Manager"
