#!/bin/sh
# ProxyForce — remove what install.sh installed, and nothing else.
#
# ProxyForce restores every system setting it changes when it stops, so a clean
# uninstall means stopping it FIRST and only then deleting the files. Removing the
# binary while the engine is running would leave the routing table, the desktop
# proxy setting and the *_proxy environment variables pointing at a proxy that no
# longer exists — recoverable (the crash-safe backups in /var/lib/proxyforce are
# replayed on the next start), but only by reinstalling.
set -eu

PREFIX="${1:-/opt/proxyforce}"

if [ "$(id -u)" -ne 0 ]; then
    echo "This must run as root: sudo $0 [prefix]" >&2
    exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop proxyforce.service 2>/dev/null || true
    systemctl disable proxyforce.service 2>/dev/null || true
    rm -f /etc/systemd/system/proxyforce.service
    systemctl daemon-reload 2>/dev/null || true
fi

rm -f /usr/share/polkit-1/actions/com.proxyforce.policy
rm -f /usr/share/applications/proxyforce.desktop
command -v update-desktop-database >/dev/null 2>&1 \
    && update-desktop-database /usr/share/applications 2>/dev/null || true

rm -rf "$PREFIX"

cat <<EOF
ProxyForce removed from $PREFIX.

Left in place deliberately:
  /var/lib/proxyforce   configuration, logs, diagnostics and the crash-safe
                        backups of the system settings ProxyForce changed.

If ProxyForce was not stopped cleanly before this, keep that directory: it is what
a reinstall uses to put your original proxy and environment settings back. Once you
are satisfied nothing needs restoring:  sudo rm -rf /var/lib/proxyforce
EOF
