use async_trait::async_trait;
use lusby_common::backend::UsbBackend;
use lusby_common::baseline::is_valid_interface_spec;
use lusby_common::types::DeviceInfo;
use std::fs;
use std::io::Write;
use std::str;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("usbguard command failed: {0}")]
    Cmd(String),
}

/// One logical usbguard section owned by lusby; everything outside these
/// markers belongs to the administrator and is preserved on apply.
const BEGIN_MARK: &str = "# lusby:begin managed rules";
const END_MARK: &str = "# lusby:end managed rules";

const USBGUARD_TIMEOUT: Duration = Duration::from_secs(10);
const USBGUARD_MAX_CONCURRENCY: usize = 4;
const LIST_CACHE_TTL: Duration = Duration::from_secs(2);

fn usbguard_sema() -> &'static tokio::sync::Semaphore {
    static SEMA: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    SEMA.get_or_init(|| tokio::sync::Semaphore::new(USBGUARD_MAX_CONCURRENCY))
}

fn apply_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn list_cache() -> &'static Mutex<Option<(Instant, Vec<DeviceInfo>)>> {
    static CACHE: Mutex<Option<(Instant, Vec<DeviceInfo>)>> = Mutex::new(None);
    &CACHE
}

fn invalidate_list_cache() {
    *list_cache().lock().unwrap() = None;
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

    #[test]
    fn parse_allows_escaped_quotes() {
        let sample = r#"
        10: allow id 1234:5678 serial "AB\"C" name "Test"
        "#;
        let devices = UsbguardBackend::parse_list_devices(sample);
        let dev = devices.first().unwrap();
        assert_eq!(dev.serial, "AB\"C");
    }

    #[test]
    fn parse_uses_numeric_ids_and_normalizes_case() {
        let sample = "7: allow id 046D:C534 serial \"X\" name \"T\"\n";
        let devices = UsbguardBackend::parse_list_devices(sample);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, "7");
        assert_eq!(devices[0].vendor_id, "0x046d");
        assert_eq!(devices[0].product_id, "0xc534");
        assert!(!devices[0].persistent);
    }

    #[test]
    fn parse_skips_malformed_ids() {
        let sample = "x: allow id ZZZZ:1234 serial \"X\" name \"T\"\n";
        assert!(UsbguardBackend::parse_list_devices(sample).is_empty());
    }

    #[test]
    fn parse_extracts_hash_and_interfaces() {
        let sample = "3: allow id 046d:c534 serial \"A\" name \"N\" hash \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\" with-interface 03:01:01 with-interface 03:01:02\n";
        let devices = UsbguardBackend::parse_list_devices(sample);
        assert_eq!(
            devices[0].usbguard_hash,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        );
        assert_eq!(devices[0].interfaces, vec!["03:01:01", "03:01:02"]);
    }

    #[test]
    fn merge_preserves_foreign_rules() {
        let existing = "allow id 1111:2222\nblock id 3333:4444\n";
        let merged = UsbguardBackend::merge_rules(existing, "allow id 046d:c534\n");
        // Foreign rules survive...
        assert!(merged.contains("allow id 1111:2222"));
        assert!(merged.contains("block id 3333:4444"));
        // ...and the managed section is delimited
        assert!(merged.contains(BEGIN_MARK));
        assert!(merged.contains(END_MARK));
        assert!(merged.find("block id 3333:4444").unwrap() < merged.find(BEGIN_MARK).unwrap());
        let again = UsbguardBackend::merge_rules(&merged, "allow id 9999:8888\n");
        assert_eq!(again.matches(BEGIN_MARK).count(), 1);
        assert!(again.contains("allow id 9999:8888"));
        assert!(!again.contains("allow id 046d:c534"));
        assert!(again.contains("allow id 1111:2222"));
        assert!(again.find("block id 3333:4444").unwrap() < again.find(BEGIN_MARK).unwrap());
    }

    #[test]
    fn merge_keeps_admin_block_before_lusby_allow() {
        let merged = UsbguardBackend::merge_rules("block id 046d:c534\n", "allow id 046d:c534\n");
        let admin_block = merged.find("block id 046d:c534").unwrap();
        let lusby_allow = merged.find("allow id 046d:c534").unwrap();
        assert!(
            admin_block < lusby_allow,
            "admin block must be evaluated before lusby allow: {merged}"
        );
    }

    use proptest::prelude::*;
    proptest! {
        #[test]
        fn parser_does_not_crash(s in "\\PC*") {
            // Parser should never panic on random strings
            let _ = UsbguardBackend::parse_list_devices(&s);
        }
    }
}

#[derive(Clone, Default)]
pub struct UsbguardBackend;

impl UsbguardBackend {
    /// Run `usbguard` with a timeout and a concurrency bound so a hung or
    /// flooded backend cannot exhaust the daemon.
    async fn run_usbguard(args: &[&str]) -> Result<String, BackendError> {
        let _permit = usbguard_sema()
            .acquire()
            .await
            .map_err(|_| BackendError::Cmd("usbguard semaphore closed".into()))?;
        let mut cmd = tokio::process::Command::new("usbguard");
        cmd.args(args);
        // A dropped/timeout future must not leave a running child behind.
        cmd.kill_on_drop(true);
        let out = tokio::time::timeout(USBGUARD_TIMEOUT, cmd.output())
            .await
            .map_err(|_| BackendError::Cmd("usbguard command timed out".into()))?
            .map_err(|e| BackendError::Cmd(e.to_string()))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            Err(BackendError::Cmd(
                String::from_utf8_lossy(&out.stderr).to_string(),
            ))
        }
    }

    /// Extract the policy word ("allow" or "block") from a usbguard list-devices line
    fn extract_policy(line: &str) -> &str {
        // Lines look like: "0: allow id 1d6b:0002 ..."
        // or "1: block id 046d:c534 ..."
        if let Some(colon_space) = line.find(": ") {
            let after = &line[colon_space + 2..];
            if let Some(space) = after.find(' ') {
                return &after[..space];
            }
        }
        ""
    }

    fn parse_list_devices(output: &str) -> Vec<DeviceInfo> {
        // Parser for `usbguard list-devices` textual output.
        // Example lines (format can vary):
        // 3: allow id 1d6b:0002 serial "" name "xHCI Host Controller" hash "..." parent-hash "..." via-port "..." with-interface ...
        // serial "AB\"C"
        let mut devices = Vec::new();
        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Numeric rule id is the prefix before the first ':' ("3: allow ...").
            // Previously this used the vid:pid pair as `id`, which never matches
            // the numeric id `usbguard allow-device`/`reject-device` expect.
            let mut id = String::new();
            if let Some(colon) = line.find(':') {
                let prefix = line[..colon].trim();
                if !prefix.is_empty() && prefix.chars().all(|c| c.is_ascii_digit()) {
                    id = prefix.to_string();
                }
            }
            let mut vendor = String::new();
            let mut product = String::new();
            let mut serial = String::new();
            // Extract id vid:pid
            if let Some(idx) = line.find(" id ") {
                let rest = &line[idx + 4..];
                if let Some(space) = rest.find(' ') {
                    let pair = &rest[..space];
                    if let Some(colon) = pair.find(':') {
                        let raw_vid = &pair[..colon];
                        let raw_pid = &pair[colon + 1..];
                        // Normalize for stable matching (daemon compares case-insensitively,
                        // but canonical lowercase avoids duplicate representations).
                        if !raw_vid.is_empty()
                            && !raw_pid.is_empty()
                            && raw_vid.len() <= 8
                            && raw_pid.len() <= 8
                            && raw_vid.chars().all(|c| c.is_ascii_hexdigit())
                            && raw_pid.chars().all(|c| c.is_ascii_hexdigit())
                        {
                            vendor = format!("0x{}", raw_vid.to_lowercase());
                            product = format!("0x{}", raw_pid.to_lowercase());
                            if id.is_empty() {
                                // Fall back to the pair only when no numeric id exists.
                                id = pair.to_lowercase();
                            }
                        }
                    }
                }
            }
            // Extract serial "..."
            if let Some(sidx) = line.find(" serial \"") {
                let rest = &line[sidx + 9..];
                let mut s_acc = String::new();
                let mut escaped = false;
                for c in rest.chars() {
                    if escaped {
                        s_acc.push(c);
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    } else if c == '"' {
                        break;
                    } else {
                        s_acc.push(c);
                    }
                }
                serial = s_acc;
            }
            // Extract the usbguard device hash ("hash \"...\""): identity for
            // baseline rules that binds the descriptor set.
            let mut usbguard_hash = String::new();
            if let Some(idx) = line.find(" hash \"") {
                let rest = &line[idx + 7..];
                if let Some(end) = rest.find('"') {
                    let h = &rest[..end];
                    if !h.is_empty() && h.chars().all(|c| c.is_ascii_hexdigit()) {
                        usbguard_hash = h.to_string();
                    }
                }
            }
            // Extract all well-formed with-interface tokens (skip quoted noise).
            let mut interfaces: Vec<String> = Vec::new();
            for chunk in line.split(" with-interface ").skip(1) {
                let token = chunk.split_whitespace().next().unwrap_or("");
                let token = token.trim_matches('"');
                if is_valid_interface_spec(token) {
                    interfaces.push(token.to_string());
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

            // Determine policy from line: format is "<id>: <policy> id ..."
            let allowed = Self::extract_policy(line) == "allow";

            if !vendor.is_empty() && !product.is_empty() && !id.is_empty() {
                // fingerprint unknown here; leave empty; daemon can compute if needed.
                // persistent is unknown from list-devices output alone (an "allow"
                // line may be ephemeral), so never claim persistence here.
                devices.push(DeviceInfo {
                    id,
                    vendor_id: vendor,
                    product_id: product,
                    serial,
                    fingerprint: String::new(),
                    device_type: dtype.to_string(),
                    allowed,
                    persistent: false,
                    usbguard_hash,
                    interfaces,
                });
            }
        }
        devices
    }

    async fn list_devices_cached(&self) -> Vec<DeviceInfo> {
        {
            let guard = list_cache().lock().unwrap();
            if let Some((at, list)) = guard.as_ref() {
                if at.elapsed() < LIST_CACHE_TTL {
                    return list.clone();
                }
            }
        }
        let devices = match Self::run_usbguard(&["list-devices"]).await {
            Ok(out) => Self::parse_list_devices(&out),
            Err(_) => Vec::new(),
        };
        *list_cache().lock().unwrap() = Some((Instant::now(), devices.clone()));
        devices
    }

    /// The effective implicit policy target ("block"/"allow"), or None.
    async fn implicit_policy_target_raw() -> Option<String> {
        let out = Self::run_usbguard(&["get-parameter", "ImplicitPolicyTarget"])
            .await
            .ok()?;
        let t = out.trim().to_lowercase();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    }

    /// Merge the lusby-managed rules into the existing policy instead of
    /// replacing the whole file: administrator/foreign rules survive, and
    /// re-applying replaces (never duplicates) the managed section
    fn merge_rules(existing: &str, lusby_block: &str) -> String {
        let mut kept: Vec<&str> = Vec::new();
        let mut in_managed = false;
        for line in existing.lines() {
            let t = line.trim();
            if t == BEGIN_MARK {
                in_managed = true;
                continue;
            }
            if t == END_MARK {
                in_managed = false;
                continue;
            }
            if !in_managed {
                kept.push(line);
            }
        }
        let mut out = String::new();
        for l in kept {
            out.push_str(l);
            out.push('\n');
        }
        out.push_str(BEGIN_MARK);
        out.push('\n');
        out.push_str(lusby_block.trim_end());
        out.push('\n');
        out.push_str(END_MARK);
        out.push('\n');
        out
    }

    /// Atomically merge new lusby rules into /etc/usbguard/rules.conf and
    /// reload usbguard. On reload failure, restore previous rules.
    /// Serialized in-process so concurrent applies cannot interleave the
    /// fixed tmp/backup paths.
    pub async fn apply_rules_atomically(rules_content: &str) -> Result<(), BackendError> {
        const MAX_RULES_BYTES: usize = 1024 * 1024;
        if rules_content.len() > MAX_RULES_BYTES {
            return Err(BackendError::Cmd("rules content too large".into()));
        }
        let _guard = apply_lock().lock().await;

        let content = rules_content.to_string();
        // Blocking file work runs off the async workers.
        let merged_len = tokio::task::spawn_blocking(move || Self::fs_apply(&content))
            .await
            .map_err(|e| BackendError::Cmd(format!("apply task: {e}")))?;
        merged_len?;

        // Reload usbguard
        match Self::run_usbguard(&["reload"]).await {
            Ok(_) => {
                invalidate_list_cache();
                Ok(())
            }
            Err(e) => {
                // Attempt rollback (only if a backup exists; otherwise
                // removing the just-installed broken file is unsafe, so keep
                // it and surface the error).
                tokio::task::spawn_blocking(Self::fs_rollback)
                    .await
                    .map_err(|e| BackendError::Cmd(format!("rollback task: {e}")))?;
                invalidate_list_cache();
                Err(e)
            }
        }
    }

    fn fs_apply(rules_content: &str) -> Result<(), BackendError> {
        let rules_path = "/etc/usbguard/rules.conf";
        let tmp_path = "/etc/usbguard/rules.conf.tmp";
        let bak_path = "/etc/usbguard/rules.conf.bak";
        // Merge with (rather than replace) the existing policy so unrelated
        // administrator rules and recovery allowances are preserved.
        let existing = fs::read_to_string(rules_path).unwrap_or_default();
        let merged = Self::merge_rules(&existing, rules_content);
        // Remove a stale tmp file first so `create_new` below is a true
        // exclusive create (no truncating a pre-existing symlink/plant).
        let _ = fs::remove_file(tmp_path);

        // Write tmp file with restrictive perms applied atomically at creation
        // (File::create + set_permissions leaves a umask-dependent window).
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true).mode(0o600);
            let mut f = opts
                .open(tmp_path)
                .map_err(|e| BackendError::Cmd(format!("create tmp: {e}")))?;
            f.write_all(merged.as_bytes())
                .map_err(|e| BackendError::Cmd(format!("write tmp: {e}")))?;
            f.sync_all()
                .map_err(|e| BackendError::Cmd(format!("fsync tmp: {e}")))?;
        }

        // Preserve the previous owner/mode of rules.conf so usbguard daemons
        // running as a dedicated user can still read the file.
        if let Ok(md) = fs::metadata(rules_path) {
            use std::os::unix::fs::MetadataExt;
            let _ = fs::set_permissions(tmp_path, md.permissions());
            #[cfg(unix)]
            unsafe {
                use std::ffi::CString;
                let c_path =
                    CString::new(tmp_path).map_err(|_| BackendError::Cmd("bad tmp path".into()))?;
                libc::chown(c_path.as_ptr(), md.uid(), md.gid());
            }
        }

        // Backup existing rules if present
        if fs::metadata(rules_path).is_ok() {
            fs::copy(rules_path, bak_path)
                .map_err(|e| BackendError::Cmd(format!("backup rules: {e}")))?;
        }

        // Move tmp into place
        fs::rename(tmp_path, rules_path)
            .map_err(|e| BackendError::Cmd(format!("rename rules: {e}")))?;
        // Ensure the rename is durable.
        if let Ok(dir) = fs::File::open("/etc/usbguard") {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    fn fs_rollback() {
        let rules_path = "/etc/usbguard/rules.conf";
        let bak_path = "/etc/usbguard/rules.conf.bak";
        let tmp_path = "/etc/usbguard/rules.conf.tmp";
        if fs::metadata(bak_path).is_ok() {
            let _ = fs::rename(bak_path, rules_path);
            if let Ok(dir) = fs::File::open("/etc/usbguard") {
                let _ = dir.sync_all();
            }
        } else {
            let _ = fs::remove_file(tmp_path);
        }
    }
}

#[async_trait]
impl UsbBackend for UsbguardBackend {
    async fn list_devices(&self) -> Vec<DeviceInfo> {
        self.list_devices_cached().await
    }

    async fn get_device(&self, device_id: &str) -> Option<DeviceInfo> {
        let list = self.list_devices_cached().await;
        list.into_iter().find(|d| d.id == device_id)
    }

    async fn allow_ephemeral(&self, device_id: &str, _ttl_secs: u32) -> bool {
        // Option-injection guard: an id must never parse as a usbguard flag.
        if device_id.is_empty() || device_id.starts_with('-') {
            return false;
        }
        // Ephemeral authorization via a temporary allow rule
        let args = ["allow-device", device_id];
        let ok = Self::run_usbguard(&args).await.is_ok();
        invalidate_list_cache();
        ok
    }

    async fn revoke(&self, device_id: &str) -> bool {
        if device_id.is_empty() || device_id.starts_with('-') {
            return false;
        }
        let args = ["reject-device", device_id];
        let ok = Self::run_usbguard(&args).await.is_ok();
        invalidate_list_cache();
        ok
    }

    async fn implicit_policy_target(&self) -> Option<String> {
        Self::implicit_policy_target_raw().await
    }
}
