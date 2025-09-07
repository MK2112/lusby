# guardianusb

Wrapper around usbguard for Linux Mint/Ubuntu/Debian.

guardianusb enforces a deny‑by‑default policy for USB devices and provides:

- Privileged daemon `guardianusb-daemon` (root): manages usbguard rules, applies signed baselines, writes tamper‑evident audit logs, and exposes a D‑Bus API.
- Unprivileged tray app `guardianusb-tray`: subscribes to daemon signals and shows prompts/notifications (GTK/libappindicator optional; event‑driven, no polling).
- CLI `guardianusbctl`: scripting and configuration helper (e.g., list devices, status, baseline/audit verification).

The system is event‑driven (udev/D‑Bus), low power (no polling), and secure‑by‑default.

## Table of Contents

- Overview and Architecture
- Requirements
- Recommended Installation (via .deb)
- From Source (development)
- Configuration and Paths
- Running the Components
- Security Notes
- Troubleshooting
- Uninstall
- Roadmap

## Overview and Architecture

- `crates/daemon/`: Serves `org.guardianusb.Daemon` on the system D‑Bus at `/org/guardianusb/Daemon`.
  - Deny unknown devices by default.
  - Event‑driven: optional udev listener (feature `udev-monitor`) for add/remove; listens to systemd‑logind to auto‑revoke ephemeral approvals on suspend/lock.
  - Persistent policy via signed baselines (Ed25519). Baseline verification uses canonical JSON and trusted public keys.
  - Tamper‑evident JSONL audit log.
- `crates/tray/`: User tray application subscribing to daemon signals.
- `crates/cli/`: CLI to call D‑Bus methods and to verify baselines/audit logs offline.
- `crates/backend-usbguard/`: Backend integrating with the `usbguard` CLI.
- `crates/common/`: Shared types, fingerprinting, canonical JSON signing/verification, audit utilities.

## Requirements

- Linux Mint (Ubuntu/Debian based)
- System packages:
  - `usbguard` (daemon + CLI)
  - `policykit-1`
  - `pkg-config`, `build-essential` (for building from source)
  - Optional (udev listener): `libudev-dev`
  - Optional (GTK tray): `libgtk-3-dev`, `libayatana-appindicator3-dev`
- Rust toolchain (stable): `rustup`, `cargo`

Install prerequisites:

```bash
sudo apt update
sudo apt install -y usbguard policykit-1 pkg-config build-essential
# Optional for udev feature
sudo apt install -y libudev-dev
# Optional for GTK tray UI
sudo apt install -y libgtk-3-dev libayatana-appindicator3-dev
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

## Recommended Installation (via .deb)

This produces a clean system install with systemd, polkit, AppArmor, and config files in place.

1) Build release artifacts and the .deb

```bash
cargo install cargo-deb --locked
cargo build --release --workspace
cd crates/daemon
cargo deb --no-build --no-strip
```

The `.deb` is created at `crates/daemon/target/debian/guardianusb-daemon_*.deb`.

2) Install the package

```bash
sudo dpkg -i target/debian/guardianusb-daemon_*.deb
```

This installs:

- `/usr/sbin/guardianusb-daemon`
- `/lib/systemd/system/guardianusb-daemon.service`
- `/usr/share/polkit-1/actions/org.guardianusb.manage.policy`
- `/etc/apparmor.d/usr.sbin.guardianusb-daemon`
- `/etc/guardianusb/config.toml`

3) Create and secure directories

```bash
sudo mkdir -p /etc/guardianusb/baselines
sudo mkdir -p /etc/guardianusb/trusted_pubkeys
sudo mkdir -p /var/lib/guardianusb
sudo mkdir -p /var/log/guardianusb
sudo chown -R root:root /etc/guardianusb /var/lib/guardianusb /var/log/guardianusb
sudo chmod 700 /etc/guardianusb /var/lib/guardianusb
sudo chmod 600 /etc/guardianusb/config.toml
sudo touch /var/log/guardianusb/audit.log && sudo chmod 600 /var/log/guardianusb/audit.log
```

4) Configure usbguard

```bash
sudo systemctl enable --now usbguard
```

5) AppArmor

```bash
sudo apparmor_parser -r -W /etc/apparmor.d/usr.sbin.guardianusb-daemon
sudo aa-enforce /etc/apparmor.d/usr.sbin.guardianusb-daemon
```

6) Start and enable the daemon

```bash
sudo systemctl enable --now guardianusb-daemon
systemctl status guardianusb-daemon
journalctl -u guardianusb-daemon -f
```

7) Optional: start the tray app (unprivileged user)

See “From Source” to build and run `guardianusb-tray`. The default tray prints signal messages to stdout; the GTK/libappindicator UI is provided behind the `tray-ui` feature.

## From Source (development)

Clone and build:

```bash
git clone <repository-url>
cd guardianusb
cargo build --release --workspace
```

Prepare config and directories:

```bash
sudo mkdir -p /etc/guardianusb/baselines /etc/guardianusb/trusted_pubkeys /var/lib/guardianusb /var/log/guardianusb
sudo chown -R root:root /etc/guardianusb /var/lib/guardianusb /var/log/guardianusb
sudo chmod 700 /etc/guardianusb /var/lib/guardianusb
sudo cp packaging/config/config.toml /etc/guardianusb/config.toml
sudo chmod 600 /etc/guardianusb/config.toml
sudo touch /var/log/guardianusb/audit.log && sudo chmod 600 /var/log/guardianusb/audit.log
```

Run usbguard:

```bash
sudo systemctl enable --now usbguard
```

Run the daemon (root):

```bash
# basic
sudo target/release/guardianusb-daemon

# with udev listener (requires libudev-dev)
cargo run -p guardianusb-daemon --release --features udev-monitor
```

The daemon exposes D‑Bus:

- Bus name: `org.guardianusb.Daemon`
- Object path: `/org/guardianusb/Daemon`
- Interface: `org.guardianusb.Daemon`

Run the CLI (unprivileged):

```bash
target/release/guardianusbctl status
target/release/guardianusbctl list
target/release/guardianusbctl info --device <ID>

# Baseline verify against a raw 32‑byte Ed25519 public key
guardianusbctl baseline verify --pubkey /etc/guardianusb/trusted_pubkeys/<key>.pub baseline.json

# Audit log chain verify (JSONL)
guardianusbctl audit verify /var/log/guardianusb/audit.log
```

Run the tray (unprivileged):

```bash
# Default: prints daemon signals to stdout
target/release/guardianusb-tray

# GTK libappindicator UI (optional feature build requirements apply)
cargo run -p guardianusb-tray --release --features tray-ui
```

## Configuration and Paths

- Config file: `/etc/guardianusb/config.toml`
  - `policy.deny_unknown = true`
  - `policy.default_ttl_secs = 300`
  - `paths.baselines_system = "/etc/guardianusb/baselines"`
  - `paths.trusted_pubkeys = "/etc/guardianusb/trusted_pubkeys"`
  - `paths.audit_log = "/var/log/guardianusb/audit.log"`
  - `paths.state_dir = "/var/lib/guardianusb"`

- Trusted keys: `/etc/guardianusb/trusted_pubkeys/*.pub`
  - Raw 32‑byte Ed25519 public keys (no PEM/SSH armor).

- Baselines: `/etc/guardianusb/baselines/`
  - Signed canonical JSON baseline files.

- Audit log: `/var/log/guardianusb/audit.log` (JSONL, 0600)

Permissions:

```bash
/etc/guardianusb/ (0700, root:root)
/etc/guardianusb/config.toml (0600, root:root)
/etc/guardianusb/baselines/ (0700)
/etc/guardianusb/trusted_pubkeys/ (0700; .pub files 0644 ok)
/var/lib/guardianusb/ (0700)
/var/log/guardianusb/audit.log (0600)
```

## Running the Components

- Daemon (systemd): `sudo systemctl enable --now guardianusb-daemon`
- Tray: user session process (`guardianusb-tray`)
- CLI: `guardianusbctl` (unprivileged, polkit prompts for persistent changes)

Ephemeral approvals:

- Requested via D‑Bus. Tracked with TTL and auto‑revoked on suspend/lock via systemd‑logind.

Persistent baselines:

- Upload signed baseline and apply via daemon D‑Bus (polkit‑gated by `org.guardianusb.manage`).

## Security Notes

- Deny‑by‑default policy is enforced. Only explicitly approved devices are allowed.
- Persistent changes are protected by PolicyKit action `org.guardianusb.manage`.
- Audit logs are tamper‑evident (hash chained). Keep permissions strict.
- AppArmor profile included to confine the daemon.

## Troubleshooting

- usbguard not found: `sudo apt install usbguard`
- udev build errors: install `libudev-dev` or build without `--features udev-monitor`
- D‑Bus access: ensure daemon runs as root and owns `org.guardianusb.Daemon` on the system bus
- Polkit denied: verify `/usr/share/polkit-1/actions/org.guardianusb.manage.policy` exists and the user is authorized
- AppArmor denials: inspect logs and use `aa-logprof` to adjust as needed

## Uninstall

```bash
sudo systemctl disable --now guardianusb-daemon
sudo dpkg -r guardianusb-daemon
# Optional cleanup (destructive)
sudo rm -rf /etc/guardianusb /var/lib/guardianusb /var/log/guardianusb/audit.log
```