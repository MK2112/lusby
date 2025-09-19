# GuardianUSB UX & Safety Roadmap

Goal: Improve day-to-day UX while preserving the project’s security posture (deny-by-default, cryptographic baselines, tamper-evident auditing) and low idle overhead.

## Guiding principles
- Safety first: deny-by-default remains non-negotiable; persistent changes continue to be polkit-gated (`org.guardianusb.manage`).
- Least privilege: unprivileged flows for temporary approvals only; explicit elevation for persistent policy.
- Event-driven & efficient: no polling; keep footprint low.
- Verifiable: keep cryptographic and audit verification simple and scriptable.

---

## Medium-term (higher impact)
- [ ] Visual baseline editor (optional)
  - TUI (`guardianusbctl tui`) to:
    - Select a detected device -> add to baseline draft (i.e. copy its fingerprint for permanent allow)
    - Edit serial binding, annotate `comment`
    - Save unsigned baseline JSON
    - Sign/apply with prompts (polkit when applying) [crates/cli + tui library]

- [ ] Tray UI enhancements (opt-in feature)
  - Show countdown for active ephemeral approvals; add manual revoke button [crates/tray]

- [ ] Audit viewer
  - `guardianusbctl audit view --follow` with pretty-print, filter by device fingerprint, and chain-status indicator [crates/cli]

- [ ] Safer usbguard rule diffs
  - Simulated apply mode in daemon: generate rules and show `diff` against current `/etc/usbguard/rules.conf` before committing (dry-run flag) [crates/backend-usbguard, crates/daemon]

---

## Long-term (nice to have)
- [ ] Policy profiles
  - Multiple signed baselines with labels (work, home, travel) and quick switch (polkit-gated) [crates/daemon, CLI]

- [ ] Remote attestation / sync
  - Optionally fetch baseline over a secure channel; verify against pre-pinned key (out of scope for now; maintain local-only default)

- [ ] Multi-user environments
  - Per-seat prompts and approvals; integrate better with logind seats [crates/daemon]

---

## Security invariants to preserve
- Deny unknown devices by default (`policy.deny_unknown = true`).
- Persistent changes allowed only after polkit authorization (`org.guardianusb.manage`).
- Baselines must be canonical JSON + Ed25519 signature; trusted keys are raw 32-byte pubkeys in `/etc/guardianusb/trusted_pubkeys`.
- Audit log remains append-only, hash-chained; keep restrictive permissions.
- AppArmor profile confines daemon; keep file path expectations stable.

---

## Implementation mapping
- `crates/cli/`
  - New subcommands: `baseline keygen|init|sign|apply|verify`, `keys add|list|remove`, `allow`, `revoke`, `audit view`
- `crates/daemon/`
  - Optional dry-run apply; more descriptive audit entries; structured error messages
- `crates/tray/`
  - UI actions for TTL and revoke; small status popover; optional countdown
- `crates/backend-usbguard/`
  - Dry-run rules diff utility
- `packaging/`
  - Post-install verifier; sample configs and example baseline