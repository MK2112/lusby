# guardian-USB

guardian-USB enforces a "deny‑by‑default" USB policy on Debian-based Linux distributions (Ubuntu, Mint, etc.) by orchestrating [usbguard](https://github.com/USBGuard/usbguard) via a privileged daemon and user‑space tools. When an unknown USB device is connected, it gets blocked automatically. A user notification about this can be shown via the tray.

**The user can:**
- Approve a device for a limited time (TTL). Temporal approvals are automatically revoked on timeout/suspend/lock,
- Apply a persistent allow‑list using a cryptographically signed baseline (Ed25519); baselines are verified against trusted public keys and then converted into `usbguard` rules,
- Inspect and verify a tamper‑evident audit log of all actions (hash‑chained JSONL).

**guardian-USB consists of:**
- A privileged daemon `guardianusb-daemon` (root) for managing `usbguard` rules, applying signed baselines, writing tamper‑evident audit logs, and exposing a D‑Bus API,
- An unprivileged tray app `guardianusb-tray` that subscribes to daemon signals and shows prompts/notifications,
- A CLI `guardianusbctl`: Scripting and configuration helper (e.g., list devices, status, baseline/audit verification).

## Benefits

- Unknown USB devices get blocked by default,
- Integrates with `usbguard` and confines the daemon with an AppArmor profile,
- Unprivileged users can request short‑lived approvals; persistent changes are gated by PolicyKit (`org.guardianusb.manage`),
- Signed baselines (Ed25519) ensure only approved device lists are ever applicable,
- Append‑only, hash‑chained JSONL audit logs; verifiable via CLI for tamper‑evident auditing,
- Reacts to udev and D‑Bus signals; no polling, low resource demands,
- Optional tray app to surface prompts/notifications and allow for one‑click temporary approvals.

## Requirements

- Linux Mint (Ubuntu/Debian based)
- System packages:
  - `usbguard` (daemon + CLI)
  - `policykit-1`
  - `pkg-config`, `build-essential` (for building from source)
  - Optional (udev listener): `libudev-dev`
  - Optional (GTK tray): `libgtk-3-dev`, `libayatana-appindicator3-dev`
- Rust toolchain (stable): `rustup`, `cargo`

### Quick Install (recommended)
guardian-USB provides an installer script:

```bash
cd guardian-usb
chmod +x install.sh
sudo ./install.sh
```

**The script will:**
- Install required dependencies (system packages + Rust toolchain if not present)
- Build and install the `.deb` package for guardian-USB daemon from source
- Install the accompanying tray application
- Set up configuration and log directories
- Load the AppArmor profile
- Enable and start the systemd service

Once complete, check the status with:
```bash
systemctl status guardianusb-daemon
```

Follow logs with:
```bash
journalctl -u guardianusb-daemon -f
```

### Tray Application

The tray application (`guardianusb-tray`) provides a system tray icon with a user interface for managing USB devices. It shows notifications when unknown devices are detected and allows quick approval/revocation of devices.

#### Features

- **Automatic Startup**: The tray application is automatically set up to start when you log in to your desktop environment.
- **Device Notifications**: Get desktop notifications when unknown USB devices are connected.
- **Quick Actions**: Right-click the tray icon to:
  - **Approve for $X$ minutes**: Temporarily allow the last detected device
  - **Revoke last device**: Revoke access from the last detected device
  - **Show last device details**: View detailed information about the last detected device
  - **Quit**: Exit the tray application

#### Headless Mode (Advanced)

For server environments without a GUI, you can run the tray application in headless mode, which will only log to stdout:

```bash
cargo build --release -p guardianusb-tray --no-default-features
target/release/guardianusb-tray
```

## Quickstart: Using a USB stick temporarily

**Prerequisites:**
- You followed the "Recommended Installation" which automatically starts `guardianusb-daemon` and `usbguard`.
- The tray application should start automatically at login. If not, you can start it manually with `guardianusb-tray &`

1) Plug in the USB stick
- It will be blocked by default. If the tray is running, you’ll see an "Unknown USB device" notification.
- You can also list devices via CLI:
```bash
guardianusbctl list | jq
# Note the device "id" (from usbguard), e.g. "2-1" or similar
```

2) Temporarily allow for 5 minutes
- Via tray: click "Approve for 5 minutes".
- Or via CLI (no root required for temporal approval):
```bash
guardianusbctl allow --device <device-id> --ttl 300
```
- Optional (D‑Bus, advanced):
```bash
ID="<device-id>"          # e.g.  "2-1"
TTL=300                   # seconds
UID=$(id -u)              # recorded for auditing
busctl call org.guardianusb.Daemon \
  /org/guardianusb/Daemon org.guardianusb.Daemon \
  request_ephemeral_allow suu "$ID" $TTL $UID
```
Approvals are auto‑revoked on suspend/lock via `systemd‑logind`.

3) Revoke early (optional)
```bash
guardianusbctl revoke --device <device-id>
```
- Optional (D‑Bus, advanced):
```bash
busctl call org.guardianusb.Daemon \
  /org/guardianusb/Daemon org.guardianusb.Daemon \
  revoke_device s "$ID"
```

4) Verify audit log integrity (optional)
```bash
sudo guardianusbctl audit verify /var/log/guardianusb/audit.log
```

5) Make it persistent later (advanced)
- Prepare a signed baseline JSON (Ed25519). The daemon verifies the baseline against the trusted raw 32‑byte public keys in `/etc/guardianusb/trusted_pubkeys/*.pub` and converts the baseline into `usbguard` rules atomically.
- Apply via D‑Bus (polkit‑gated):
```bash
# Baseline file path must be readable by root; result stored into /etc/guardianusb/baselines
sudo busctl call org.guardianusb.Daemon \
  /org/guardianusb/Daemon org.guardianusb.Daemon \
  apply_persistent_allow ss \
  /path/to/baseline.json "<signer-id-label>"
```
Notes:
- Persistent operations require PolicyKit authorization (`org.guardianusb.manage`).
- Baseline signature and key format: canonical JSON signed with Ed25519; trusted keys are raw 32‑byte public keys (no PEM/SSH armor).

## Quickstart: Permanently allow a USB stick
This shows how to create a signed baseline (Ed25519), verify it, and apply it so the device is allowed persistently via `usbguard` rules.

1) Identify device attributes
```bash
guardianusbctl list | jq
# Note vendor_id (e.g. 0x0781), product_id (e.g. 0x5581), and serial if present.
```

2) Generate an Ed25519 keypair (raw 32‑byte public key)
```bash
guardianusbctl baseline keygen | tee key.out
SECRET_B64=$(grep SECRET_B64 key.out | cut -d= -f2)
PUB_RAW32_B64=$(grep PUB_RAW32_B64 key.out | cut -d= -f2)
```

3) Install the trusted public key (polkit‑gated)
```bash
sudo guardianusbctl keys add mykey --pub-b64 "$PUB_RAW32_B64"
guardianusbctl keys list
```

4) Create a baseline draft (unsigned)
Use CLI to scaffold from a live device. You may override/add `serial` and `comment`.
```bash
guardianusbctl baseline init --device <device-id> --comment "Team USB stick" --out baseline_unsigned.json
```
The file follows `crates/common/src/baseline.rs`:
```json
{
  "version": 1,
  "created_by": "you@example.com",
  "created_at": "2025-09-08T21:00:00Z",
  "devices": [
    {
      "vendor_id": "0x0781",
      "product_id": "0x5581",
      "serial": "1234567890ABCDEF",
      "descriptors_hash": "",
      "device_type": "storage",
      "comment": "Team USB stick"
    }
  ]
}
```
Notes:
- `serial` is optional; include if you want to tie the rule to a specific unit.
- `descriptors_hash` is currently informational in the daemon; leave empty if unknown.

5) Sign the baseline using canonical JSON (Ed25519)
```bash
guardianusbctl baseline sign --secret-b64 "$SECRET_B64" --input baseline_unsigned.json --output baseline.json
```

6) Verify the signed baseline against the trusted key
```bash
guardianusbctl baseline verify --pubkey /etc/guardianusb/trusted_pubkeys/mykey.pub baseline.json
# Expect: OK
```

7) Apply persistently (polkit‑gated). Daemon will atomically apply usbguard rules
```bash
sudo guardianusbctl baseline apply --file baseline.json --signer mykey
```

8) Confirm
```bash
guardianusbctl list | jq
# And inspect /etc/usbguard/rules.conf for the new allow rule
```

## D‑Bus API surface (for integrators)
- Service: `org.guardianusb.Daemon`
- Object path: `/org/guardianusb/Daemon`
- Interface: `org.guardianusb.Daemon`

Methods:
- `get_policy_status() -> PolicyStatus`
- `list_devices() -> Vec<DeviceInfo>`
- `get_device_info(device_id: &str) -> DeviceInfo`
- `request_ephemeral_allow(device_id: &str, ttl_secs: u32, requester_uid: u32) -> bool`
- `revoke_device(device_id: &str) -> bool`
- `apply_persistent_allow(baseline_path: &str, signer_id: &str) -> bool` (polkit‑gated)
- `list_trusted_pubkeys() -> Vec<String>` (polkit‑gated)
- `add_trusted_pubkey(name: &str, key_bytes_b64: &str) -> bool` (polkit‑gated)
- `remove_trusted_pubkey(name: &str) -> bool` (polkit‑gated)

Signals:
- `unknown_device_inserted(DeviceInfo)`
- `device_removed(device_id: &str)`

Example busctl calls:
```bash
# List devices (JSON array of DeviceInfo printed via guardianusbctl is recommended for formatting)
busctl call org.guardianusb.Daemon /org/guardianusb/Daemon org.guardianusb.Daemon list_devices

# Get a single device info
busctl call org.guardianusb.Daemon /org/guardianusb/Daemon org.guardianusb.Daemon get_device_info s "<device-id>"

# Ephemeral allow for 300s, recorded with caller's UID
busctl call org.guardianusb.Daemon /org/guardianusb/Daemon org.guardianusb.Daemon request_ephemeral_allow suu "<device-id>" 300 $(id -u)

# Revoke device
busctl call org.guardianusb.Daemon /org/guardianusb/Daemon org.guardianusb.Daemon revoke_device s "<device-id>"

# Apply a signed baseline (requires polkit authorization); daemon will atomically rewrite usbguard rules
sudo busctl call org.guardianusb.Daemon /org/guardianusb/Daemon org.guardianusb.Daemon apply_persistent_allow ss \
  /path/to/baseline.json "<signer-id-label>"

# Manage trusted keys (raw 32‑byte pubkey, base64‑encoded)
# Add key
sudo busctl call org.guardianusb.Daemon /org/guardianusb/Daemon org.guardianusb.Daemon add_trusted_pubkey ss "mykey" "<base64-raw32>"
# List keys
sudo busctl call org.guardianusb.Daemon /org/guardianusb/Daemon org.guardianusb.Daemon list_trusted_pubkeys
# Remove key
sudo busctl call org.guardianusb.Daemon /org/guardianusb/Daemon org.guardianusb.Daemon remove_trusted_pubkey s "mykey.pub"
```

## Overview and Architecture
- `crates/daemon/` serves `org.guardianusb.Daemon` on the system D‑Bus at `/org/guardianusb/Daemon`.
  - Deny unknown devices by default.
  - Event‑driven: optional `udev` listener (feature `udev-monitor`) for add/remove; listens to `systemd‑logind` to auto‑revoke ephemeral approvals on suspend/lock.
  - Persistent policy via signed baselines (`Ed25519`). Baseline verification uses canonical JSON and trusted public keys.
  - Tamper‑evident JSONL audit log.
- `crates/tray/`: User tray application subscribing to daemon signals.
- `crates/cli/`: CLI to call D‑Bus methods and to verify baselines/audit logs offline.
- `crates/backend-usbguard/`: Backend integrating with the `usbguard` CLI.
- `crates/common/`: Shared types, fingerprinting, canonical JSON signing/verification, audit utilities.

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
