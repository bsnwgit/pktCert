#!/bin/bash
# pktCert uninstall script — Ubuntu Server 22.04/24.04 LTS
# Usage: bash uninstall.sh [--purge] [--yes] [--dry-run] [--dir <path>]
#
# Removes the systemd unit, the application code and the virtualenv.
#
# Data is KEPT by default — config.yaml (which holds the JWT secret and the
# credential encryption key), pktcert.db and its -wal/-shm, logs, backups and
# any TLS material uploaded through Settings. Re-running install.sh over the
# top therefore resumes with the same database and the same admin password.
# Pass --purge to remove that too; it is not recoverable.
#
#   --purge      also delete config.yaml, the database, logs, backups, ssl
#   --keep-data  the default; stated explicitly for scripted runs
#   --yes        don't prompt (required for --purge non-interactively)
#   --dry-run    print what would be removed, change nothing
#   --dir PATH   install directory, if it can't be read from the unit file
#
# The install directory is discovered from the installed systemd unit's
# WorkingDirectory, then $PKTCERT_INSTALL_DIR, then /opt/pktcert.

set -euo pipefail

APP="pktcert"
DISPLAY="pktCert"
UNIT_PATH="/etc/systemd/system/pktcert.service"
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
SELF_IN_INSTALL_DIR=0

# The installer runs as an ordinary user and calls sudo for the few steps that
# need it; running the whole thing as root would leave the install dir
# root-owned. Mirror that here so this works either way.
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

PURGE=0
ASSUME_YES=0
DRY_RUN=0
DIR_OVERRIDE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --purge)       PURGE=1 ;;
        --keep-data)   PURGE=0 ;;
        --yes|-y)      ASSUME_YES=1 ;;
        --dry-run|-n)  DRY_RUN=1 ;;
        --dir)         DIR_OVERRIDE="${2:-}"; shift ;;
        --dir=*)       DIR_OVERRIDE="${1#--dir=}" ;;
        -h|--help)     sed -n '2,21p' "$0"; exit 0 ;;
        *)             echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

# Every mutating command goes through this, so --dry-run is a single decision
# rather than a flag threaded through each call site.
RUN() {
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "  [dry-run] $*"
    elif [ -n "$SUDO" ]; then
        sudo "$@"
    else
        "$@"
    fi
}

# ── 1. Locate the installation ────────────────────────────────────────────────
# The unit file is the source of truth: it is what systemd is actually running,
# so its WorkingDirectory is the directory that matters even if the operator
# has since forgotten where they put it.
INSTALL_DIR=""
if [ -n "$DIR_OVERRIDE" ]; then
    INSTALL_DIR="$DIR_OVERRIDE"
elif [ -f "$UNIT_PATH" ]; then
    INSTALL_DIR="$(sed -n 's/^WorkingDirectory=//p' "$UNIT_PATH" | head -1)"
fi
if [ -z "$INSTALL_DIR" ]; then
    INSTALL_DIR="${PKTCERT_INSTALL_DIR:-/opt/pktcert}"
fi
case "$INSTALL_DIR" in
    "~") INSTALL_DIR="$HOME" ;;
    "~/"*) INSTALL_DIR="$HOME/${INSTALL_DIR#\~/}" ;;
esac
INSTALL_DIR="${INSTALL_DIR%/}"

# Never operate on a system directory or a bare home. An install dir read from
# a hand-edited unit file, or typed at --dir, is exactly where a wrong answer
# turns "uninstall the app" into "delete /usr".
case "$INSTALL_DIR" in
    ""|/|/usr|/usr/*|/etc|/etc/*|/var|/var/*|/bin|/bin/*|/sbin|/sbin/*|/lib|/lib/*|/boot|/boot/*|/opt|/home|/root|/srv|/mnt|/tmp)
        echo "ERROR: refusing to uninstall from '$INSTALL_DIR' — that is a system path." >&2
        exit 1 ;;
    /*) ;;
    *)  echo "ERROR: install directory must be an absolute path (got '$INSTALL_DIR')." >&2
        exit 1 ;;
esac
if [ "$INSTALL_DIR" = "$HOME" ]; then
    echo "ERROR: refusing to uninstall from '$INSTALL_DIR' — that is your home directory." >&2
    echo "       Pass --dir with the actual install directory." >&2
    exit 1
fi

if [ ! -f "$UNIT_PATH" ] && [ ! -d "$INSTALL_DIR/app" ] && [ ! -d "$INSTALL_DIR/venv" ]; then
    echo "No $DISPLAY installation found (no $UNIT_PATH, nothing at $INSTALL_DIR)."
    exit 0
fi

# An install directory that is itself a git checkout is an in-place install —
# the repo and the deployment are the same tree. Deleting the code there would
# destroy the operator's working copy, so the code is left alone and only the
# unit (and, with --purge, the data) is removed.
IN_PLACE=0
if [ -e "$INSTALL_DIR/.git" ]; then
    IN_PLACE=1
fi

# The unit is only this installation's if it actually runs from this directory.
# With --dir naming a second install — or after another install took the
# service name over — stopping and deleting the unit would take down a
# different, live installation that has nothing to do with the files being
# removed here.
UNIT_MATCHES=1
UNIT_DIR=""
if [ -f "$UNIT_PATH" ]; then
    UNIT_DIR="$(sed -n 's/^WorkingDirectory=//p' "$UNIT_PATH" | head -1)"
    if [ -n "$UNIT_DIR" ] && [ "$UNIT_DIR" != "$INSTALL_DIR" ]; then
        UNIT_MATCHES=0
    fi
fi

VERSION="(unknown)"
if [ -f "$INSTALL_DIR/VERSION" ]; then
    VERSION="$(head -1 "$INSTALL_DIR/VERSION" 2>/dev/null || echo '(unknown)')"
fi

echo "=== $DISPLAY Uninstaller ==="
echo "Install dir: $INSTALL_DIR"
echo "Version:     $VERSION"
echo "Unit file:   $([ -f "$UNIT_PATH" ] && echo "$UNIT_PATH" || echo '(not installed)')"
if [ "$UNIT_MATCHES" -eq 0 ]; then
    echo "             ^ runs from $UNIT_DIR — another install owns the"
    echo "               service name, so the unit is left alone"
fi
if [ "$IN_PLACE" -eq 1 ]; then
    echo "Mode:        in-place (git checkout) — source tree will NOT be deleted"
fi
echo "Data:        $([ "$PURGE" -eq 1 ] && echo 'WILL BE DELETED (--purge)' || echo 'kept')"
if [ "$DRY_RUN" -eq 1 ]; then
    echo "Dry run:     nothing will actually be changed"
fi
echo ""

if [ "$ASSUME_YES" -ne 1 ] && [ "$DRY_RUN" -ne 1 ]; then
    if [ ! -t 0 ]; then
        echo "ERROR: not running interactively and --yes was not given." >&2
        exit 1
    fi
    read -rp "Proceed? [y/N]: " CONFIRM
    case "$CONFIRM" in [yY]|[yY][eE][sS]) ;; *) echo "Aborted."; exit 0 ;; esac

    # Asked separately, and defaulting to no, so that an operator who came here
    # to clear out an old release cannot lose the database by holding Enter.
    if [ "$PURGE" -eq 0 ]; then
        echo ""
        echo "Also remove $DISPLAY data? This deletes, permanently:"
        echo "    config.yaml   (JWT secret + credential encryption key)"
        echo "    $APP.db      and its -wal/-shm"
        echo "    logs/  backups/  ssl/"
        read -rp "Remove data too? [y/N]: " CONFIRM_DATA
        case "$CONFIRM_DATA" in [yY]|[yY][eE][sS]) PURGE=1 ;; *) PURGE=0 ;; esac
    fi
    echo ""
fi

# ── 2. Stop and remove the service ────────────────────────────────────────────
echo "[1/3] Stopping service..."
if [ "$UNIT_MATCHES" -eq 0 ]; then
    echo "  Skipped — $UNIT_PATH runs from $UNIT_DIR, not $INSTALL_DIR."
    echo "  Stopping it would take down that installation instead of this one."
    echo "  Only the files under $INSTALL_DIR are removed below."
elif command -v systemctl &>/dev/null; then
    RUN systemctl stop "$APP" 2>/dev/null || true
    RUN systemctl disable "$APP" 2>/dev/null || true
    if [ -f "$UNIT_PATH" ]; then
        RUN rm -f "$UNIT_PATH"
        if [ "$DRY_RUN" -eq 0 ]; then
            echo "  Removed $UNIT_PATH"
        fi
    fi
    RUN systemctl daemon-reload || true
    # Clear a lingering failed state, otherwise `systemctl status` keeps
    # reporting the unit long after the file is gone.
    RUN systemctl reset-failed "$APP" 2>/dev/null || true
else
    echo "  systemctl not found — skipping."
fi

# ── 3. Remove application code ────────────────────────────────────────────────
echo "[2/3] Removing application files..."
if [ "$IN_PLACE" -eq 1 ]; then
    echo "  In-place install — leaving the checkout at $INSTALL_DIR alone."
    echo "  (venv/ is removed; it is generated, not source.)"
    if [ -e "$INSTALL_DIR/venv" ]; then
        RUN rm -rf "${INSTALL_DIR:?}/venv"
    fi
else
    for entry in app migrations clickhouse scripts agent homeassistant-addon frontend venv docs tests start.sh install.sh uninstall.sh requirements.txt config.example.yaml VERSION README.md LICENSE SECURITY.md icon.svg lockup.svg favicon.ico; do
        [ -e "$INSTALL_DIR/$entry" ] || continue
        # bash reads a script lazily, so deleting the one currently executing
        # can leave it running off a truncated file. Skip it and say so.
        if [ "$INSTALL_DIR/$entry" = "$SELF" ]; then
            SELF_IN_INSTALL_DIR=1
            continue
        fi
        RUN rm -rf "${INSTALL_DIR:?}/$entry"
    done
    if [ "$DRY_RUN" -eq 0 ]; then
        echo "  Application code and virtualenv removed."
    fi
fi

# ── 4. Data ───────────────────────────────────────────────────────────────────
# Databases, their write-ahead logs, and the kept-aside copies taken before a
# migration — plain *.db does not match "pktcert.db.pre-upgrade".
DATA_FILES=( -name 'config.yaml' -o -name 'config.yaml.*'
             -o -name '*.db' -o -name '*.db-wal' -o -name '*.db-shm' -o -name '*.db.*'
             -o -name '*.sqlite' -o -name '*.sqlite3'
             -o -name '*.duckdb' -o -name '*.duckdb-wal' -o -name '*.duckdb.*' )

echo "[3/3] Handling data..."
if [ "$PURGE" -eq 1 ]; then
    for entry in logs backups ssl data; do
        if [ -e "$INSTALL_DIR/$entry" ]; then
            RUN rm -rf "${INSTALL_DIR:?}/$entry"
        fi
    done
    if [ "$DRY_RUN" -eq 1 ]; then
        find "$INSTALL_DIR" -maxdepth 1 \( "${DATA_FILES[@]}" \) -print 2>/dev/null \
            | sed 's|^|  [dry-run] rm |' || true
    else
        $SUDO find "$INSTALL_DIR" -maxdepth 1 \( "${DATA_FILES[@]}" \) -delete 2>/dev/null || true
        echo "  Data removed."
    fi
    # Only ever rmdir — an empty directory goes, anything left is reported
    # rather than force-deleted.
    if [ "$IN_PLACE" -eq 0 ] && [ "$DRY_RUN" -eq 0 ] && [ -d "$INSTALL_DIR" ]; then
        if $SUDO rmdir "$INSTALL_DIR" 2>/dev/null; then
            echo "  Removed empty $INSTALL_DIR"
        else
            echo "  $INSTALL_DIR still holds files not created by the installer:"
            ls -A "$INSTALL_DIR" 2>/dev/null | sed 's/^/    /' || true
            echo "  Left in place — remove them by hand if you want the directory gone."
        fi
    fi
else
    echo "  Data kept in $INSTALL_DIR:"
    for entry in config.yaml pktcert.db logs backups ssl; do
        if [ -e "$INSTALL_DIR/$entry" ]; then
            echo "    $entry"
        fi
    done
    echo "  Re-run install.sh with the same install directory to reuse it."
fi

echo ""
if [ "$DRY_RUN" -eq 1 ]; then
    echo "Dry run complete — nothing was changed."
    if [ "$PURGE" -eq 0 ]; then
        echo "Add --purge to see what removing the data would take with it."
    fi
    echo "Re-run without --dry-run to apply."
else
    echo "$DISPLAY uninstalled."
    if [ "$SELF_IN_INSTALL_DIR" -eq 1 ]; then
        echo "This script is still at $SELF (it was running). Remove it by hand."
    fi
    if [ "$PURGE" -eq 0 ]; then
        echo "Data was kept. To remove it as well: bash uninstall.sh --purge --dir $INSTALL_DIR"
    fi
fi
