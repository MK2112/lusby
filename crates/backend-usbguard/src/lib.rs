use async_trait::async_trait;
use guardianusb_common::backend::UsbBackend;
use guardianusb_common::types::DeviceInfo;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::str;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("usbguard command failed: {0}")]
    Cmd(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_allows_basic_lines() {
        let sample = r#"
                                    0: allow id 1d6b:0002 serial "" name "xHCI Host Controller" hash "abcd" parent-hash "-" via-port "1-0:1.0" with-interface 09:00:00
                                    1: block id 046d:c534 serial "ABC123" name "USB Receiver" hash "efgh" parent-hash "..." via-port "2-1" with-interface 03:01:01 with-interface +hid
                                    2: allow id 0781:5581 serial "1234567890ABCDEF" name "SanDisk Ultra" hash "ijkl" parent-hash "..." via-port "2-2" with-interface +mass-storage
                                    "#;
        let devices = UsbguardBackend::parse_list_devices(sample);
        assert!(devices
            .iter()
            .any(|d| d.vendor_id == "0x1d6b" && d.product_id == "0x0002"));
        let logi = devices
            .iter()
            .find(|d| d.vendor_id == "0x046d" && d.product_id == "0xC534".to_lowercase());
        assert!(logi.is_some());
        let storage = devices.iter().find(|d| d.vendor_id == "0x0781");
        assert!(storage.is_some());
    }

    /// Atomically write new rules content to /etc/usbguard/rules.conf and reload usbguard.
    /// On reload failure, restore previous rules.
    pub fn apply_rules_atomically(rules_content: &str) -> Result<(), BackendError> {
        let rules_path = "/etc/usbguard/rules.conf";
        let tmp_path = "/etc/usbguard/rules.conf.tmp";
        let bak_path = "/etc/usbguard/rules.conf.bak";

        // Write tmp file with restrictive perms
        {
            let mut f = File::create(tmp_path)
                .map_err(|e| BackendError::Cmd(format!("create tmp: {e}")))?;
            f.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| BackendError::Cmd(format!("chmod tmp: {e}")))?;
            f.write_all(rules_content.as_bytes())
                .map_err(|e| BackendError::Cmd(format!("write tmp: {e}")))?;
            f.sync_all()
                .map_err(|e| BackendError::Cmd(format!("fsync tmp: {e}")))?;
        }

        // Backup existing rules if present
        if fs::metadata(rules_path).is_ok() {
            fs::copy(rules_path, bak_path)
                .map_err(|e| BackendError::Cmd(format!("backup rules: {e}")))?;
        }

        // Move tmp into place
        fs::rename(tmp_path, rules_path)
            .map_err(|e| BackendError::Cmd(format!("rename rules: {e}")))?;

        // Reload usbguard
        match UsbguardBackend::run_usbguard(&["reload"]) {
            Ok(_) => Ok(()),
            Err(e) => {
                if fs::metadata(bak_path).is_ok() {
                    let _ = fs::rename(bak_path, rules_path);
                    let _ = UsbguardBackend::run_usbguard(&["reload"]);
                }
                Err(e)
            }
        }
    }
}

#[derive(Clone, Default)]
pub struct UsbguardBackend;

impl UsbguardBackend {
    fn run_usbguard(args: &[&str]) -> Result<String, BackendError> {
        let out = Command::new("usbguard")
            .args(args)
            .output()
            .map_err(|e| BackendError::Cmd(e.to_string()))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            Err(BackendError::Cmd(
                String::from_utf8_lossy(&out.stderr).to_string(),
            ))
        }
    }

    fn parse_list_devices(output: &str) -> Vec<DeviceInfo> {
        // Very basic parser for `usbguard list-devices` textual output.
        // Example lines (format can vary):
        // 3: allow id 1d6b:0002 serial "" name "xHCI Host Controller" hash "..." parent-hash "..." via-port "..." with-interface ...
        let mut devices = Vec::new();
        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut id = String::new();
            let mut vendor = String::new();
            let mut product = String::new();
            let mut serial = String::new();
            // Extract id vid:pid
            if let Some(idx) = line.find(" id ") {
                let rest = &line[idx + 4..];
                if let Some(space) = rest.find(' ') {
                    let pair = &rest[..space];
                    if let Some(colon) = pair.find(':') {
                        vendor = format!("0x{}", &pair[..colon]);
                        product = format!("0x{}", &pair[colon + 1..]);
                        id = pair.to_string();
                    }
                }
            }
            // Extract serial "..."
            if let Some(sidx) = line.find(" serial \"") {
                let rest = &line[sidx + 8..];
                if let Some(endq) = rest.find('"') {
                    serial = rest[..endq].to_string();
                }
            }
            // Guess type by presence of with-interface strings
            let dtype = if line.contains("with-interface +hid") {
                "hid"
            } else if line.contains("with-interface +mass-storage") {
                "storage"
            } else {
                ""
            };

            if !vendor.is_empty() && !product.is_empty() {
                // fingerprint unknown here; leave empty; daemon can compute if needed
                devices.push(DeviceInfo {
                    id,
                    vendor_id: vendor,
                    product_id: product,
                    serial,
                    fingerprint: String::new(),
                    device_type: dtype.to_string(),
                    allowed: line.starts_with("allow"),
                    persistent: line.contains("allow "),
                });
            }
        }
        devices
    }

    /// Atomically write new rules content to /etc/usbguard/rules.conf and reload usbguard.
    /// On reload failure, restore previous rules.
    pub fn apply_rules_atomically(rules_content: &str) -> Result<(), BackendError> {
        let rules_path = "/etc/usbguard/rules.conf";
        let tmp_path = "/etc/usbguard/rules.conf.tmp";
        let bak_path = "/etc/usbguard/rules.conf.bak";

        // Write tmp file with restrictive perms
        {
            let mut f = File::create(tmp_path)
                .map_err(|e| BackendError::Cmd(format!("create tmp: {e}")))?;
            f.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| BackendError::Cmd(format!("chmod tmp: {e}")))?;
            f.write_all(rules_content.as_bytes())
                .map_err(|e| BackendError::Cmd(format!("write tmp: {e}")))?;
            f.sync_all()
                .map_err(|e| BackendError::Cmd(format!("fsync tmp: {e}")))?;
        }

        // Backup existing rules if present
        if fs::metadata(rules_path).is_ok() {
            fs::copy(rules_path, bak_path)
                .map_err(|e| BackendError::Cmd(format!("backup rules: {e}")))?;
        }

        // Move tmp into place
        fs::rename(tmp_path, rules_path)
            .map_err(|e| BackendError::Cmd(format!("rename rules: {e}")))?;

        // Reload usbguard
        match Self::run_usbguard(&["reload"]) {
            Ok(_) => Ok(()),
            Err(e) => {
                // Attempt rollback
                if fs::metadata(bak_path).is_ok() {
                    let _ = fs::rename(bak_path, rules_path);
                    let _ = Self::run_usbguard(&["reload"]);
                }
                Err(e)
            }
        }
    }
}

#[async_trait]
impl UsbBackend for UsbguardBackend {
    async fn list_devices(&self) -> Vec<DeviceInfo> {
        match tokio::task::spawn_blocking(|| Self::run_usbguard(&["list-devices"]))
            .await
            .ok()
            .and_then(|r| r.ok())
        {
            Some(out) => Self::parse_list_devices(&out),
            None => Vec::new(),
        }
    }

    async fn get_device(&self, device_id: &str) -> Option<DeviceInfo> {
        let list = self.list_devices().await;
        list.into_iter().find(|d| d.id == device_id)
    }

    async fn allow_ephemeral(&self, device_id: &str, _ttl_secs: u32) -> bool {
        // Ephemeral authorization via a temporary allow rule
        let device_id = device_id.to_string();
        tokio::task::spawn_blocking(move || {
            let args = ["allow-device", &device_id];
            Self::run_usbguard(&args)
        })
        .await
        .ok()
        .map(|r| r.is_ok())
        .unwrap_or(false)
    }

    async fn revoke(&self, device_id: &str) -> bool {
        let device_id = device_id.to_string();
        tokio::task::spawn_blocking(move || {
            let args = ["reject-device", &device_id];
            Self::run_usbguard(&args)
        })
        .await
        .ok()
        .map(|r| r.is_ok())
        .unwrap_or(false)
    }
}
