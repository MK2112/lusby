# guardian-usb

guardian-usb enforces a strict USB "deny‑by‑default" policy on Linux Mint/Ubuntu/Debian by orchestrating [usbguard](https://github.com/USBGuard/usbguard) via a privileged daemon and user‑space tools on Linux Mint/Ubuntu/Debian.<br>
When an unknown USB device is connected, it is blocked automatically and a user notification can be shown via the tray. You as the user can:
- Approve a device for a limited time (TTL). Temporal approvals are automatically revoked on timeout/suspend/lock via `systemd‑logind`.
- Apply a persistent allow‑list using a cryptographically signed baseline (Ed25519). Baselines are verified against trusted public keys and then converted into `usbguard` rules atomically.
- Inspect and verify a tamper‑evident audit log of all actions (hash‑chained JSONL).

**To allow for all this, guardian-usb provides:**
- Privileged daemon `guardianusb-daemon` (root) manages usbguard rules, applies signed baselines, writes tamper‑evident audit logs, and exposes a D‑Bus API
- Unprivileged tray app `guardianusb-tray` subscribes to daemon signals and shows prompts/notifications (GTK/libappindicator optional; event‑driven, *no* polling)
- CLI `guardianusbctl`: scripting and configuration helper (e.g., list devices, status, baseline/audit verification)

The system is **event‑driven** (udev/D‑Bus) and **low power** (no polling).

## Key benefits
- Unknown USB devices are blocked by default.
- Integrates with `usbguard` and confines the daemon with an AppArmor profile.
- Unprivileged users can request short‑lived approvals; persistent changes are gated by PolicyKit (`org.guardianusb.manage`).
- Signed baselines (Ed25519) ensure only approved device lists are applied.
- Append‑only, hash‑chained JSONL audit logs; verifiable via CLI for tamper‑evident auditing.
- Reacts to udev and D‑Bus signals; no polling, low resource demands.
- Optional tray app to surface prompts/notifications and one‑click temporary approvals.

## Quickstart: Using a USB stick
This walkthrough shows the most common flow: plugging in a USB mass‑storage device and allowing it temporarily.

**Prerequisites:**
- You have followed "Recommended Installation" and started `guardianusb-daemon` and `usbguard`.
- Optional: start the tray (`guardianusb-tray`) for notifications.

1) Plug in the USB stick
- It will be blocked by default. If the tray is running, you’ll see an "Unknown USB device" notification.
- You can also list devices via CLI:
```bash
guardianusbctl list | jq
# Note the device "id" (from usbguard), e.g. "2-1" or similar
```

2) Temporarily allow for 5 minutes
- Via tray: click "Approve for 5 minutes".
- Or via D‑Bus (no root required for temporal approval):
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

2) Generate an Ed25519 keypair (prints base64 secret and base64 raw public key)
Use a tiny Rust helper to avoid PEM/SSH encodings. Save the secret securely.
```rust
// keygen.rs
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
fn main() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();
    println!("SECRET_B64={}", B64.encode(sk.to_bytes())); // 32 bytes
    println!("PUB_RAW32_B64={}", B64.encode(pk.to_bytes())); // 32 bytes raw
}
```
Build and run:
```bash
rustc -C debuginfo=0 -C opt-level=3 keygen.rs -o keygen
./keygen | tee key.out
# Extract values
SECRET_B64=$(grep SECRET_B64 key.out | cut -d= -f2)
PUB_RAW32_B64=$(grep PUB_RAW32_B64 key.out | cut -d= -f2)
```

3) Install the trusted public key (polkit‑gated)
```bash
# This writes a file /etc/guardianusb/trusted_pubkeys/mykey.pub containing raw 32 bytes
sudo busctl call org.guardianusb.Daemon \
  /org/guardianusb/Daemon org.guardianusb.Daemon \
  add_trusted_pubkey ss "mykey" "$PUB_RAW32_B64"
```

4) Craft a baseline JSON (unsigned)
Create `baseline_unsigned.json` with fields matching `crates/common/src/baseline.rs`:
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

5) Sign the baseline using canonical JSON (Ed25519) and attach signature
```rust
// sign_baseline.rs
use ed25519_dalek::SigningKey;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Serialize, Deserialize, Clone)]
struct DeviceEntry {
    vendor_id: String,
    product_id: String,
    #[serde(skip_serializing_if = "Option::is_none")] serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] bus_path: Option<String>,
    descriptors_hash: String,
    device_type: String,
    #[serde(skip_serializing_if = "Option::is_none")] comment: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Baseline {
    version: u32,
    created_by: String,
    created_at: String,
    devices: Vec<DeviceEntry>,
    #[serde(default)] signature: Option<String>,
}

fn canonical_json_vec<T: serde::Serialize>(v: &T) -> Vec<u8> {
    let val = serde_json::to_value(v).unwrap();
    canonical_json::to_string(&val).unwrap().into_bytes()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: sign_baseline <secret_b64> <in.json> <out.json>");
        std::process::exit(2);
    }
    let secret = B64.decode(&args[1]).unwrap();
    let sk = SigningKey::from_bytes(&secret[..32].try_into().unwrap());

    let mut b: Baseline = serde_json::from_slice(&fs::read(&args[2]).unwrap()).unwrap();
    b.signature = None; // ensure signature is not part of canonical form

    let msg = canonical_json_vec(&b);
    let sig = sk.try_sign(&msg).unwrap().to_bytes();
    b.signature = Some(B64.encode(sig));

    fs::write(&args[3], serde_json::to_string_pretty(&b).unwrap()).unwrap();
}
```
Build and sign:
```bash
rustc -C debuginfo=0 -C opt-level=3 sign_baseline.rs -o sign_baseline
./sign_baseline "$SECRET_B64" baseline_unsigned.json baseline.json
```

6) Verify the signed baseline against the trusted key
```bash
guardianusbctl baseline verify --pubkey /etc/guardianusb/trusted_pubkeys/mykey.pub baseline.json
# Expect: OK
```

7) Apply persistently (polkit‑gated). Daemon will atomically apply usbguard rules
```bash
sudo busctl call org.guardianusb.Daemon \
  /org/guardianusb/Daemon org.guardianusb.Daemon \
  apply_persistent_allow ss \
  $(realpath baseline.json) "mykey"
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

1) Build release artifacts and the `.deb`
```bash
cargo install cargo-deb --locked
cargo build --release --workspace
cd crates/daemon
cargo deb --no-build --no-strip
```

The `.deb` is created at `crates/daemon/target/debian/guardianusb-daemon_*.deb`.

2) Install the package
```bash
sudo dpkg -i guardianusb-daemon_*.deb
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

See "From Source" to build and run `guardianusb-tray`.<br>
The default tray prints signal messages to `stdout`; the GTK/libappindicator UI is provided behind the `tray-ui` feature.

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
