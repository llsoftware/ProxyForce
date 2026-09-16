#!/bin/sh
# ProxyForce — Linux installer.
#
# The zip is already a working, portable build: `sudo ./ProxyForce` runs it from
# wherever you extracted it. This script is for the case where you want it to
# behave like an installed application — a launcher in the applications menu, a
# polkit rule so the GUI can raise its own privileges instead of needing sudo on
# the command line, and optionally a systemd service that starts the engine at
# boot with nothing to click.
#
# Everything it installs is listed in uninstall.sh, which removes exactly that set
# and nothing else.
#
# Usage:  sudo ./packaging/install.sh [--prefix /opt/proxyforce] [--service]

set -eu

PREFIX="/opt/proxyforce"
ENABLE_SERVICE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --service) ENABLE_SERVICE=1; shift ;;
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "This installer must run as root: sudo $0" >&2
    exit 1
fi

# Find the application root by walking UP from this script until we see the two
# things that define it. Not a fixed "../.." — the script is reachable as
# packaging/linux/install.sh and as the packaging/install.sh symlink beside it, and
# a hardcoded depth silently resolves to the wrong directory through one of them.
SELF="$0"
# Resolve the symlink chain by hand: `readlink -f` is GNU-only and this runs under
# whatever /bin/sh the distribution provides.
while [ -L "$SELF" ]; do
    LINK="$(readlink "$SELF")"
    case "$LINK" in
        /*) SELF="$LINK" ;;
        *)  SELF="$(dirname "$SELF")/$LINK" ;;
    esac
done
SRC="$(cd "$(dirname "$SELF")" && pwd)"
while [ "$SRC" != "/" ]; do
    if [ -f "$SRC/ProxyForce" ] && [ -d "$SRC/_internal" ]; then
        break
    fi
    SRC="$(dirname "$SRC")"
done
if [ ! -f "$SRC/ProxyForce" ] || [ ! -d "$SRC/_internal" ]; then
    echo "Could not find the ProxyForce build above this script." >&2
    echo "Run it from inside the extracted release folder." >&2
    exit 1
fi

echo "Installing ProxyForce to $PREFIX"
mkdir -p "$PREFIX"
# -T so a second run replaces the tree rather than nesting a copy inside it.
cp -a "$SRC/." "$PREFIX/"
chown -R root:root "$PREFIX"
# The execute bit does not survive a zip round-trip; set it rather than trusting
# the archive. Everything else stays read-only to non-root: the engine runs as
# root, so a user-writable install directory would be a privilege-escalation path.
chmod 755 "$PREFIX/ProxyForce"
[ -f "$PREFIX/_internal/singbox/sing-box" ] && chmod 755 "$PREFIX/_internal/singbox/sing-box"
find "$PREFIX" -type d -exec chmod 755 {} +

# ── polkit: let the GUI raise its own privileges ─────────────────────────────
# Without this, launching from the applications menu can only tell the user to
# re-run with sudo — a desktop launcher has no way to prompt. With it,
# core/hostos.relaunch_elevated() runs pkexec and the desktop shows its own
# authentication dialog, which is the Linux equivalent of the UAC prompt.
if [ -d /usr/share/polkit-1/actions ]; then
    sed "s|@PREFIX@|$PREFIX|g" "$PREFIX/packaging/linux/com.proxyforce.policy" \
        > /usr/share/polkit-1/actions/com.proxyforce.policy
    chmod 644 /usr/share/polkit-1/actions/com.proxyforce.policy
    echo "Installed polkit action com.proxyforce.run"
else
    echo "polkit not present — run ProxyForce with sudo instead." >&2
fi

# ── desktop entry ─────────────────────────────────────────────────────────────
if [ -d /usr/share/applications ]; then
    sed "s|@PREFIX@|$PREFIX|g" "$PREFIX/packaging/linux/proxyforce.desktop" \
        > /usr/share/applications/proxyforce.desktop
    chmod 644 /usr/share/applications/proxyforce.desktop
    command -v update-desktop-database >/dev/null 2>&1 \
        && update-desktop-database /usr/share/applications || true
    echo "Installed desktop entry"
fi

# ── optional: start the engine at boot ───────────────────────────────────────
# Deliberately opt-in. Installing a service that seizes the routing table at every
# boot is not something an installer should decide on the user's behalf; the same
# switch is available later from the GUI's Autostart checkbox.
if [ "$ENABLE_SERVICE" -eq 1 ]; then
    if command -v systemctl >/dev/null 2>&1; then
        sed "s|@PREFIX@|$PREFIX|g" "$PREFIX/packaging/linux/proxyforce.service" \
            > /etc/systemd/system/proxyforce.service
        chmod 644 /etc/systemd/system/proxyforce.service
        systemctl daemon-reload
        systemctl enable proxyforce.service
        echo "Enabled proxyforce.service (starts at boot, headless)."
        echo "It will not start until a proxy is configured — run ProxyForce once"
        echo "to set the host and port, then: sudo systemctl start proxyforce"
    else
        echo "systemd not found — skipping the service." >&2
    fi
fi

cat <<EOF

ProxyForce installed.

  Launch from your applications menu, or run:  sudo $PREFIX/ProxyForce
  Headless (no GUI):                           sudo $PREFIX/ProxyForce --headless
  Configuration and logs:                      /var/lib/proxyforce
  Uninstall:                                   sudo $PREFIX/packaging/linux/uninstall.sh

ProxyForce needs root: it creates a TUN interface and rewrites the routing table.
EOF
