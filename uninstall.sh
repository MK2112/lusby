#!/usr/bin/env bash
#
# Lusby & USBGuard Uninstall Script for Debian/Ubuntu systems
#
# Usage: sudo ./uninstall.sh

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() { echo -e "${BLUE}[*]${NC} $*"; }
ok() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[✗]${NC} $1"; exit 1; }
section() { echo -e "\n${BLUE}═══ $1 ═══${NC}"; }

if [ "$EUID" -ne 0 ]; then
  err "This script must be run as root (use: sudo ./uninstall.sh)"
fi

confirm() {
  local prompt="$1"
  local response
  read -p "$(echo -e ${YELLOW})$prompt (yes/no)${NC} " response
  [[ "$response" =~ ^[Yy][Ee][Ss]$ ]]
}

# Main script
main() {
  echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}║           Lusby & USBGuard Uninstall Script            ║${NC}"
  echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
  echo

  if ! (dpkg -l | grep -q "lusby-daemon" || dpkg -l | grep -q "usbguard"); then
    warn "Neither lusby-daemon nor usbguard appear to be installed."
    if confirm "Continue anyway?"; then
      log "Proceeding with cleanup of config files..."
    else
      log "Exiting."
      exit 0
    fi
  fi

  if [ -f /etc/usbguard/rules.conf ]; then
    log "Creating backup of current usbguard rules..."
    mkdir -p /tmp/lusby-uninstall-backup
    cp /etc/usbguard/rules.conf "/tmp/lusby-uninstall-backup/rules.conf.backup.$(date +%s)"
    ok "Backup saved to /tmp/lusby-uninstall-backup/"
  fi

  section "Step 1: Emergency USB Recovery"
  if [ -d /etc/usbguard ]; then
    log "Allowing all USB devices before removal..."
    sh -c 'echo "allow id *:*" > /etc/usbguard/rules.conf'
    ok "USB policy set to allow all devices"

    if [ -f /etc/usbguard/usbguard-daemon.conf ]; then
      sed -i 's/PresentDevicePolicy=apply-policy/PresentDevicePolicy=allow/' /etc/usbguard/usbguard-daemon.conf
      ok "Updated daemon policy to allow present devices"
    fi
  fi

  section "Step 2: Stop Services"
  log "Stopping lusby-daemon..."
  systemctl stop lusby-daemon 2>/dev/null && ok "lusby-daemon stopped" || warn "lusby-daemon was not running"

  log "Stopping usbguard services..."
  systemctl stop usbguard.service 2>/dev/null && ok "usbguard.service stopped" || warn "usbguard.service was not running"
  systemctl stop usbguard-dbus.service 2>/dev/null && ok "usbguard-dbus.service stopped" || warn "usbguard-dbus.service was not running"

  section "Step 3: Disable Services"
  log "Disabling services from autostart..."
  systemctl disable lusby-daemon 2>/dev/null && ok "lusby-daemon disabled" || true
  systemctl disable usbguard.service 2>/dev/null && ok "usbguard.service disabled" || true
  systemctl disable usbguard-dbus.service 2>/dev/null && ok "usbguard-dbus.service disabled" || true

  section "Step 4: Remove Packages"
  if dpkg -l | grep -q "lusby-daemon"; then
    log "Removing lusby-daemon package..."
    apt remove -y lusby-daemon 2>/dev/null && ok "lusby-daemon removed" || warn "Failed to remove lusby-daemon"
  fi

  if dpkg -l | grep -q "usbguard"; then
    log "Removing usbguard package..."
    apt remove -y usbguard 2>/dev/null && ok "usbguard removed" || warn "Failed to remove usbguard"
    log "Purging usbguard configuration..."
    apt purge -y usbguard 2>/dev/null && ok "usbguard purged" || warn "Failed to purge usbguard"
  fi

  log "Running apt autoremove..."
  apt autoremove -y 2>/dev/null && ok "Obsolete packages removed" || true

  section "Step 5: Remove Configuration Directories"
  log "Removing /etc/usbguard/..."
  if [ -d /etc/usbguard ]; then
    rm -rf /etc/usbguard
    ok "/etc/usbguard/ removed"
  else
    warn "/etc/usbguard/ already missing"
  fi

  log "Removing /etc/lusby/..."
  if [ -d /etc/lusby ]; then
    rm -rf /etc/lusby
    ok "/etc/lusby/ removed"
  else
    warn "/etc/lusby/ already missing"
  fi

  section "Step 6: Remove Runtime/Log Directories"
  log "Removing /var/lib/lusby/..."
  if [ -d /var/lib/lusby ]; then
    rm -rf /var/lib/lusby
    ok "/var/lib/lusby/ removed"
  else
    warn "/var/lib/lusby/ already missing"
  fi

  log "Removing /var/log/lusby/..."
  if [ -d /var/log/lusby ]; then
    rm -rf /var/log/lusby
    ok "/var/log/lusby/ removed"
  else
    warn "/var/log/lusby/ already missing"
  fi

  section "Step 7: Remove Tray Application"
  log "Removing lusby-tray binary..."
  if [ -f /usr/local/bin/lusby-tray ]; then
    rm -f /usr/local/bin/lusby-tray
    ok "/usr/local/bin/lusby-tray removed"
  else
    warn "/usr/local/bin/lusby-tray already missing"
  fi

  section "Step 8: Remove Desktop Autostart"
  log "Removing autostart entry..."
  if [ -f ~/.config/autostart/lusby-tray.desktop ]; then
    rm -f ~/.config/autostart/lusby-tray.desktop
    ok "Autostart entry removed"
  else
    warn "Autostart entry not found (or already removed)"
  fi

  section "Step 9: Remove AppArmor Profile"
  log "Removing AppArmor profile..."
  if [ -f /etc/apparmor.d/usr.sbin.lusby-daemon ]; then
    rm -f /etc/apparmor.d/usr.sbin.lusby-daemon
    ok "AppArmor profile removed"
    if command -v apparmor_parser &>/dev/null; then
      log "Reloading AppArmor..."
      apparmor_parser -R /etc/apparmor.d/usr.sbin.lusby-daemon 2>/dev/null || true
      ok "AppArmor reloaded"
    fi
  else
    warn "AppArmor profile not found"
  fi

  section "Step 10: Remove PolicyKit Action"
  log "Removing PolicyKit action..."
  if [ -f /usr/share/polkit-1/actions/org.lusby.manage.policy ]; then
    rm -f /usr/share/polkit-1/actions/org.lusby.manage.policy
    ok "PolicyKit action removed"
  else
    warn "PolicyKit action not found"
  fi

  section "Step 11: Final Cleanup"
  log "Looking for any remaining lusby/usbguard files..."
  remaining_files=$(find /etc /var/lib /var/log /usr/local -name "*lusby*" -o -name "*usbguard*" 2>/dev/null | wc -l)
  if [ "$remaining_files" -gt 0 ]; then
    warn "Found $remaining_files remaining files related to lusby/usbguard"
    find /etc /var/lib /var/log /usr/local -name "*lusby*" -o -name "*usbguard*" 2>/dev/null | while read -r file; do
      warn "  Removing: $file"
      rm -rf "$file"
    done
  else
    ok "No remaining files found"
  fi

  section "Verification"
  echo
  log "Checking if packages are removed..."
  if dpkg -l | grep -q "lusby-daemon"; then
    err "lusby-daemon still installed!"
  else
    ok "lusby-daemon removed"
  fi

  if dpkg -l | grep -q "usbguard"; then
    err "usbguard still installed!"
  else
    ok "usbguard removed"
  fi

  log "Checking if services are stopped..."
  if systemctl is-active --quiet lusby-daemon; then
    err "lusby-daemon is still running!"
  else
    ok "lusby-daemon stopped"
  fi

  if systemctl is-active --quiet usbguard.service; then
    err "usbguard.service is still running!"
  else
    ok "usbguard.service stopped"
  fi

  section "Post-Uninstall Status"
  echo
  log "Testing USB device visibility..."
  if command -v lsusb &>/dev/null; then
    device_count=$(lsusb | wc -l)
    if [ "$device_count" -gt 0 ]; then
      ok "USB devices visible (found $device_count devices)"
    else
      warn "No USB devices detected (may be normal if no USB devices plugged in)"
    fi
  else
    warn "lsusb not available for testing"
  fi

  echo
  echo -e "${GREEN}╔═════════════════════════╗${NC}"
  echo -e "${GREEN}║   Uninstall Complete!   ║${NC}"
  echo -e "${GREEN}╚═════════════════════════╝${NC}"
  echo

  if confirm "Reboot now to ensure all changes take effect?"; then
    log "Rebooting system..."
    reboot
  else
    warn "Please reboot your system manually to complete the uninstall."
  fi
}

main "$@"
