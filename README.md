# lusby

Linux USB denY (lusby), a security framework for handling USB devices on Debian/Ubuntu systems.<br>
Lusby enforces a "deny-by-default" policy through interaction with USBGuard: unknown USB devices are automatically blocked.
Only explicitly approved devices are allowed-temporarily or permanently, cryptographically signed and fully auditable.

## Main Features

- Default blocking of unknown USB devices
- Temporary approvals (e.g., for 5 minutes, automatic revocation on timeout/suspend/lock)
- Permanent approvals via signed baselines (Ed25519, verified against public keys)
- Audit log: tamper-evident, hash-chained, verifiable
- Notifications and quick actions via tray app
- Tray app shows countdown for temporary approvals and provides a "Revoke now" button
- CLI for comprehensive management and verification tasks
- Visual baseline editor (TUI) for easy device selection and baseline creation

## Components

- **lusby-daemon** (root):
  - Manages usbguard rules
  - Applies and verifies baselines
  - Manages audit log
  - Provides D-Bus API
  - AppArmor profile for extra security
- **lusby-tray** (user):
  - System tray with optional UI
  - Notifications for unknown devices
  - Temporary approvals and revocations via click
  - Shows countdown for active temporary approvals and provides a "Revoke now" button
- **lusbyctl** (CLI):
  - List devices, show status
  - Create, sign, verify, and apply baselines
  - Verify audit log
  - Request/set temporary approvals
  - **lusbyctl tui:** Interactive device selection, editing, and baseline creation

## Installation

```bash
cd lusby
chmod +x install.sh
sudo ./install.sh
```

The script installs all dependencies, builds the packages, sets up the tray and daemon, loads the AppArmor profile, and starts the services.

## Quickstart

1. **Plug in USB stick**
   - Device is blocked, tray shows notification
   - Show devices with `lusbyctl list`
2. **Temporarily allow**
   - Tray: "Approve for 5 minutes"
   - CLI: `lusbyctl allow --device <device-id> --ttl 300`
3. **Permanently allow**
   - Use the visual baseline editor: `lusbyctl tui`
     - Select devices, edit serial/comment, save unsigned baseline JSON interactively
   - Or use CLI: `lusbyctl baseline init --device <ID> --out baseline_unsigned.json`
   - Generate key: `lusbyctl baseline keygen`
   - Sign baseline: `lusbyctl baseline sign --secret-b64 ...`
   - Verify: `lusbyctl baseline verify --pubkey ... baseline.json`
   - Apply: `sudo lusbyctl baseline apply --file baseline.json --signer mykey`
4. **Verify audit log**
   - `sudo lusbyctl audit verify /var/log/lusby/audit.log`

## Architecture & Security

- Deny-by-default: Only explicitly approved devices are allowed
- PolicyKit: Persistent changes are protected
- Signed baselines: Ed25519, verified against trusted public keys
- Audit log: hash-chained, only root can read/write
- AppArmor: Daemon is restricted to necessary paths and capabilities
- Event-driven: Reacts to udev/D-Bus events

## How Device Recognition and Approval Work

- **Recognition:**
  - When a device is plugged in, a fingerprint (SHA256 hash over several device-specific fields) is calculated.
  - **No token or key is stored on the device itself.**
  - Approval is determined by matching against the baseline on the system.
- **Approval:**
  - Temporary: via tray or CLI, with TTL, automatically revoked
  - Permanent: create baseline draft -> sign with Ed25519 key -> verify -> apply (PolicyKit authentication required)

## Configuration & Paths

- Config: `/etc/lusby/config.toml`
- Baselines: `/etc/lusby/baselines/`
- Trusted keys: `/etc/lusby/trusted_pubkeys/*.pub`
- Audit log: `/var/log/lusby/audit.log`

- D-Bus API: `org.lusby.Daemon` at `/org/lusby/Daemon`
- Methods: list devices, status, temporary/permanent approvals, baseline and key management
- Signals: `unknown_device_inserted`, `device_removed`

## Uninstall

```bash
sudo systemctl disable --now lusby-daemon
sudo dpkg -r lusby-daemon
sudo rm -rf /etc/lusby /var/lib/lusby /var/log/lusby/audit.log
```

## Troubleshooting

- **USBGuard not running:**  
  Check with `systemctl status usbguard` (required for lusby). Install with `sudo apt install usbguard` and start the service with `sudo systemctl start usbguard`.

- **Daemon won't start - D-Bus/Polkit error:**  
  Ensure the daemon runs as root:  
  `sudo systemctl status lusby-daemon`  
  Check that PolicyKit is installed and configured (`polkitd` must be running). Error messages can be found in `/var/log/syslog` and the lusby log.

- **udev build error:**  
  Missing dependency: Install `libudev-dev` with  
  `sudo apt install libudev-dev`  
  Alternatively, build without the feature:  
  `cargo build --no-default-features`

- **AppArmor blocks functions:**  
  Check AppArmor logs with  
  `sudo journalctl | grep DENIED | grep lusby`  
  Adjust the profile with `sudo aa-logprof` and reload:  
  `sudo apparmor_parser -r /etc/apparmor.d/lusby-daemon`

- **Device not recognized or allowed:**  
  Check with `lusbyctl list` if the device is shown.  
  Check baseline and trusted keys:  
  - Are the correct public keys in `/etc/lusby/trusted_pubkeys/`?
  - Is the baseline correctly signed and applied?

- **Audit log issues:**  
  Check permissions of `/var/log/lusby/audit.log`.  
  Only root can read/write.  
  Verify integrity with:  
  `sudo lusbyctl audit verify /var/log/lusby/audit.log`

- **Other errors:**  
  See log files for details:  
  - `/var/log/lusby/daemon.log`
  - `/var/log/syslog`
  - Tray errors: `~/.cache/lusby-tray.log`

## Roadmap

- [ ] Multiple Policy profiles, switch between them
  - Multiple signed baselines with labels (work, home, travel) and quick switch (polkit-gated) [crates/daemon, CLI]
- [ ] Close off the functionality scope for the standard edition
- [ ] Make an enterprise edition. Should contain:
  - Centralizable policy management with multi-device support,
  - Remote admin,
  - Reporting dashboards
  - ...
