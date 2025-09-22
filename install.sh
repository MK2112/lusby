#!/usr/bin/env bash
set -euo pipefail

####
# Lusby Installer Script
#
# Installs Lusby daemon and its dependencies on a Debian-based system.
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

log "Building Lusby packages..."
cargo install cargo-deb --locked || true

# Build main workspace
cargo build --release --workspace

# Build and install the tray application with UI support
log "Building tray application..."
cd crates/tray
cargo build --release --features tray-ui
sudo cp target/release/lusby-tray /usr/local/bin/

# Create autostart entry for the tray application
log "Setting up tray application autostart..."
mkdir -p ~/.config/autostart
cat > ~/.config/autostart/lusby-tray.desktop <<EOL
[Desktop Entry]
Type=Application
Name=Lusby Tray
Exec=/usr/local/bin/lusby-tray
Icon=security-high
Categories=System;Utility;
StartupNotify=false
Terminal=false
Comment=USB device management tray for Lusby
EOL

# Build the daemon package
cd ../daemon
cargo deb --no-build --no-strip

log "Installing Lusby daemon package..."
sudo dpkg -i target/debian/lusby-daemon_*.deb
cd ../../

# Set correct permissions for the tray binary
sudo chmod 755 /usr/local/bin/lusby-tray

# Lusby requires some directories to be created
log "Creating Lusby directories..."
sudo mkdir -p /etc/lusby/{baselines,trusted_pubkeys} \
             /var/lib/lusby \
             /var/log/lusby

sudo chown -R root:root /etc/lusby /var/lib/lusby /var/log/lusby
sudo chmod 700 /etc/lusby /var/lib/lusby
sudo chmod 600 /etc/lusby/config.toml

sudo touch /var/log/lusby/audit.log
sudo chmod 600 /var/log/lusby/audit.log

log "Enabling usbguard service..."
sudo systemctl enable --now usbguard

log "Loading AppArmor profile..."
sudo apparmor_parser -r -W /etc/apparmor.d/usr.sbin.lusby-daemon
sudo aa-enforce /etc/apparmor.d/usr.sbin.lusby-daemon

log "Enabling Lusby daemon..."
sudo systemctl enable --now lusby-daemon

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

if systemctl is-enabled lusby-daemon >/dev/null 2>&1 && systemctl is-active lusby-daemon >/dev/null 2>&1; then
  ok "lusby-daemon enabled and active"
else
  warn "lusby-daemon not enabled/active. Run: sudo systemctl enable --now lusby-daemon"
fi

if [[ -f /usr/share/polkit-1/actions/org.lusby.manage.policy ]]; then
  ok "polkit action present"
else
  warn "polkit action missing: /usr/share/polkit-1/actions/org.lusby.manage.policy"
fi

if [[ -f /etc/apparmor.d/usr.sbin.lusby-daemon ]]; then
  ok "AppArmor profile present"
else
  warn "AppArmor profile missing: /etc/apparmor.d/usr.sbin.lusby-daemon"
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

check_dir /etc/lusby 700
check_file /etc/lusby/config.toml 600
check_dir /etc/lusby/baselines 700
check_dir /etc/lusby/trusted_pubkeys 700
check_dir /var/lib/lusby 700
check_file /var/log/lusby/audit.log 600

if busctl --system --no-pager --no-legend list | awk '{print $1}' | grep -q '^org.lusby.Daemon$'; then
  ok "D-Bus name org.lusby.Daemon owned"
else
  warn "D-Bus name org.lusby.Daemon not owned. Is the daemon running?"
fi

# Brief API call test
if busctl --system call org.lusby.Daemon /org/lusby/Daemon org.lusby.Daemon get_policy_status >/dev/null 2>&1; then
  ok "D-Bus get_policy_status ok"
else
  warn "D-Bus call failed: get_policy_status"
fi

log "Installation complete!"
echo "Check status with: systemctl status lusby-daemon"
echo "Follow logs with: journalctl -u lusby-daemon -f"
echo "Refer to the documentation for further setup instructions."

exit 0