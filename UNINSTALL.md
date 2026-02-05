# Uninstall Lusby & USBGuard

You can remove lusby and usbguard from your system like so:

```bash
chmod +x uninstall.sh
sudo ./uninstall.sh
```

**The uninstaller will:**
- Backup current usbguard rules
- Allow all USB devices
- Stop all services gracefully
- Disable services from autostart
- Remove packages and purge configurations
- Delete all related (created) directories
- Remove AppArmor profiles and PolicyKit actions
- Verify complete removal
- Optionally reboot to finalize

The uninstaller will ask for confirmation before destructive operations and create backups of important files.

**If you cannot access USB devices before running the script, the script will automatically fix this** before proceeding with removal.

If there is still something going wrong:

```bash
# Restore from backup
sudo cp /tmp/lusby-uninstall-backup/rules.conf.backup.* /etc/usbguard/rules.conf

# Allow all devices immediately
sudo sh -c 'echo "allow id *:*" > /etc/usbguard/rules.conf'

# Restart usbguard (if still installed)
sudo systemctl restart usbguard.service

# Reboot
sudo reboot
```

## Verification

After uninstall completes, verify USB devices work:

```bash
# List USB devices
lsusb

# Or check with dmesg for USB recognition
dmesg | tail -20
```

Test by:
- Plugging in an external drive, which now should mount
- Connecting USB keyboard/mouse, which now should work
- Attaching USB printer, which should be recognized