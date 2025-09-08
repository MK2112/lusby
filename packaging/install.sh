#!/usr/bin/env bash
set -euo pipefail

# GuardianUSB install script (manual install without .deb)
# This script assumes binaries are already built and present in target/release/.
# It will install:
# - guardianusb-daemon to /usr/sbin
# - systemd unit, polkit action, apparmor profile
# - /etc/guardianusb configuration, directories, and permissions

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root" >&2
  exit 1
fi

DAEMON_BIN="$(dirname "$0")/../target/release/guardianusb-daemon"
TRAY_BIN="$(dirname "$0")/../target/release/guardianusb-tray"
CLI_BIN="$(dirname "$0")/../target/release/guardianusbctl"
ROOT_DIR="/"

# Verify dependencies
command -v usbguard >/dev/null || { echo "usbguard not found. Install with: apt install usbguard"; exit 1; }

# Install binaries if present
if [[ -f "$DAEMON_BIN" ]]; then
  install -m 0755 -o root -g root "$DAEMON_BIN" /usr/sbin/guardianusb-daemon
fi
if [[ -f "$TRAY_BIN" ]]; then
  install -m 0755 -o root -g root "$TRAY_BIN" /usr/sbin/guardianusb-tray || true
fi
if [[ -f "$CLI_BIN" ]]; then
  install -m 0755 -o root -g root "$CLI_BIN" /usr/sbin/guardianusbctl || true
fi

# Install systemd unit
install -D -m 0644 -o root -g root "$(dirname "$0")/systemd/guardianusb-daemon.service" /lib/systemd/system/guardianusb-daemon.service

# Install polkit action
install -D -m 0644 -o root -g root "$(dirname "$0")/polkit/org.guardianusb.manage.policy" /usr/share/polkit-1/actions/org.guardianusb.manage.policy

# Install AppArmor profile
install -D -m 0644 -o root -g root "$(dirname "$0")/apparmor/usr.sbin.guardianusb-daemon" /etc/apparmor.d/usr.sbin.guardianusb-daemon

# Config and dirs
install -D -m 0600 -o root -g root "$(dirname "$0")/config/config.toml" /etc/guardianusb/config.toml
install -d -m 0700 -o root -g root /etc/guardianusb/baselines
install -d -m 0700 -o root -g root /etc/guardianusb/trusted_pubkeys
install -d -m 0700 -o root -g root /var/lib/guardianusb
install -d -m 0700 -o root -g root /var/log/guardianusb
: > /var/log/guardianusb/audit.log
chmod 0600 /var/log/guardianusb/audit.log

# Enable services and profiles
systemctl enable --now usbguard
apparmor_parser -r -W /etc/apparmor.d/usr.sbin.guardianusb-daemon || true
aa-enforce /etc/apparmor.d/usr.sbin.guardianusb-daemon || true
systemctl enable --now guardianusb-daemon

echo "Install complete. To verify, run:"
echo "  $(dirname "$0")/postinstall_check.sh"
