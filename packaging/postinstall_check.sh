#!/usr/bin/env bash
set -euo pipefail

ok() { echo -e "[OK] $1"; }
warn() { echo -e "[WARN] $1"; }
fail() { echo -e "[FAIL] $1"; exit 1; }

# 1) usbguard service
if systemctl is-enabled usbguard >/dev/null 2>&1 && systemctl is-active usbguard >/dev/null 2>&1; then
  ok "usbguard enabled and active"
else
  warn "usbguard not enabled/active. Run: sudo systemctl enable --now usbguard"
fi

# 2) daemon service
if systemctl is-enabled guardianusb-daemon >/dev/null 2>&1 && systemctl is-active guardianusb-daemon >/dev/null 2>&1; then
  ok "guardianusb-daemon enabled and active"
else
  warn "guardianusb-daemon not enabled/active. Run: sudo systemctl enable --now guardianusb-daemon"
fi

# 3) polkit action
if [[ -f /usr/share/polkit-1/actions/org.guardianusb.manage.policy ]]; then
  ok "polkit action present"
else
  warn "polkit action missing: /usr/share/polkit-1/actions/org.guardianusb.manage.policy"
fi

# 4) apparmor profile
if [[ -f /etc/apparmor.d/usr.sbin.guardianusb-daemon ]]; then
  ok "AppArmor profile present"
else
  warn "AppArmor profile missing: /etc/apparmor.d/usr.sbin.guardianusb-daemon"
fi

# 5) directories and permissions
check_dir() {
  local d=$1; local mode_expect=$2
  if [[ -d "$d" ]]; then
    local mode
    mode=$(stat -c %a "$d")
    if [[ "$mode" == "$mode_expect"* ]]; then ok "$d perms $mode (expected $mode_expect)"; else warn "$d perms $mode (expected $mode_expect)"; fi
  else
    warn "$d missing"
  fi
}

check_file() {
  local f=$1; local mode_expect=$2
  if [[ -f "$f" ]]; then
    local mode
    mode=$(stat -c %a "$f")
    if [[ "$mode" == "$mode_expect"* ]]; then ok "$f perms $mode (expected $mode_expect)"; else warn "$f perms $mode (expected $mode_expect)"; fi
  else
    warn "$f missing"
  fi
}

check_dir /etc/guardianusb 700
check_file /etc/guardianusb/config.toml 600
check_dir /etc/guardianusb/baselines 700
check_dir /etc/guardianusb/trusted_pubkeys 700
check_dir /var/lib/guardianusb 700
check_file /var/log/guardianusb/audit.log 600

# 6) dbus name owned by daemon
if busctl --system --no-pager --no-legend list | awk '{print $1}' | grep -q '^org.guardianusb.Daemon$'; then
  ok "D-Bus name org.guardianusb.Daemon owned"
else
  warn "D-Bus name org.guardianusb.Daemon not owned. Is the daemon running?"
fi

# 7) quick API smoke
if busctl --system call org.guardianusb.Daemon /org/guardianusb/Daemon org.guardianusb.Daemon get_policy_status >/dev/null 2>&1; then
  ok "D-Bus get_policy_status ok"
else
  warn "D-Bus call failed: get_policy_status"
fi

exit 0
