#!/usr/bin/env bash
set -euo pipefail

####
# guardian-USB Installer Script
#
# Installs guardian-USB daemon and its dependencies on a Debian-based system.
####

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo ./install.sh)"
  exit 1
fi

log() { echo -e "\033[1;37m[+]\033[0m $*"; }
ok() { echo -e "\033[1;32m[OK]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }
fail() { echo -e "\033[1;31m[FAIL]\033[0m $1"; exit 1; }

log "Updating apt..."
sudo apt update

log "Installing required packages..."
APT_PKGS=(
  usbguard policykit-1 pkg-config build-essential
  libudev-dev libgtk-3-dev libayatana-appindicator3-dev
)
sudo apt install -y "${APT_PKGS[@]}"

# Make sure Rust is installed
if ! command -v cargo &>/dev/null; then
  log "Installing Rust (via rustup)..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
else
  log "Rust already installed."
fi

log "Building guardian-USB packages..."
cargo install cargo-deb --locked || true

# Build main workspace
cargo build --release --workspace

# Build and install the tray application with UI support
log "Building tray application..."
cd crates/tray
cargo build --release --features tray-ui
sudo cp target/release/guardianusb-tray /usr/local/bin/

# Create autostart entry for the tray application
log "Setting up tray application autostart..."
mkdir -p ~/.config/autostart
cat > ~/.config/autostart/guardianusb-tray.desktop <<EOL
[Desktop Entry]
Type=Application
Name=GuardianUSB Tray
Exec=/usr/local/bin/guardianusb-tray
Icon=security-high
Categories=System;Utility;
StartupNotify=false
Terminal=false
Comment=USB device management tray for guardian-USB
EOL

# Build the daemon package
cd ../daemon
cargo deb --no-build --no-strip

log "Installing guardian-USB daemon package..."
sudo dpkg -i target/debian/guardianusb-daemon_*.deb
cd ../../

# Set correct permissions for the tray binary
sudo chmod 755 /usr/local/bin/guardianusb-tray

# guardian-USB requires some directories to be created
log "Creating guardian-USB directories..."
sudo mkdir -p /etc/guardian-USB/{baselines,trusted_pubkeys} \
             /var/lib/guardian-USB \
             /var/log/guardian-USB

sudo chown -R root:root /etc/guardian-USB /var/lib/guardian-USB /var/log/guardian-USB
sudo chmod 700 /etc/guardian-USB /var/lib/guardian-USB
sudo chmod 600 /etc/guardian-USB/config.toml

sudo touch /var/log/guardian-USB/audit.log
sudo chmod 600 /var/log/guardian-USB/audit.log

log "Enabling usbguard service..."
sudo systemctl enable --now usbguard

log "Loading AppArmor profile..."
sudo apparmor_parser -r -W /etc/apparmor.d/usr.sbin.guardian-USB-daemon
sudo aa-enforce /etc/apparmor.d/usr.sbin.guardian-USB-daemon

log "Enabling guardian-USB daemon..."
sudo systemctl enable --now guardian-USB-daemon

####
#
# Post-installation smoke test
#
####

if systemctl is-enabled usbguard >/dev/null 2>&1 && systemctl is-active usbguard >/dev/null 2>&1; then
  ok "usbguard enabled and active"
else
  warn "usbguard not enabled/active. Run: sudo systemctl enable --now usbguard"
fi

if systemctl is-enabled guardianusb-daemon >/dev/null 2>&1 && systemctl is-active guardianusb-daemon >/dev/null 2>&1; then
  ok "guardianusb-daemon enabled and active"
else
  warn "guardianusb-daemon not enabled/active. Run: sudo systemctl enable --now guardianusb-daemon"
fi

if [[ -f /usr/share/polkit-1/actions/org.guardianusb.manage.policy ]]; then
  ok "polkit action present"
else
  warn "polkit action missing: /usr/share/polkit-1/actions/org.guardianusb.manage.policy"
fi

if [[ -f /etc/apparmor.d/usr.sbin.guardianusb-daemon ]]; then
  ok "AppArmor profile present"
else
  warn "AppArmor profile missing: /etc/apparmor.d/usr.sbin.guardianusb-daemon"
fi

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

if busctl --system --no-pager --no-legend list | awk '{print $1}' | grep -q '^org.guardianusb.Daemon$'; then
  ok "D-Bus name org.guardianusb.Daemon owned"
else
  warn "D-Bus name org.guardianusb.Daemon not owned. Is the daemon running?"
fi

# Brief API call test
if busctl --system call org.guardianusb.Daemon /org/guardianusb/Daemon org.guardianusb.Daemon get_policy_status >/dev/null 2>&1; then
  ok "D-Bus get_policy_status ok"
else
  warn "D-Bus call failed: get_policy_status"
fi

log "Installation complete!"
echo "Check status with: systemctl status guardian-USB-daemon"
echo "Follow logs with: journalctl -u guardian-USB-daemon -f"
echo "Refer to the documentation for further setup instructions."

exit 0