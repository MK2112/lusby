use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use zbus::message::Header;
use zbus::{interface, Connection, SignalContext};

use lusby_backend_usbguard::UsbguardBackend;
use lusby_common::backend::UsbBackend;
use lusby_common::baseline::Baseline;
use lusby_common::types::{DeviceInfo, PolicyStatus};

use crate::audit::AuditLogger;
use crate::polkit::{check_manage_authorization, sender_uid};

#[derive(Clone)]
pub struct DaemonState {
    inner: Arc<Mutex<StateInner>>,
    backend: Arc<dyn UsbBackend>,
    audit: Arc<Mutex<AuditLogger>>,
    baselines_dir: PathBuf,
    trusted_pubkeys_dir: PathBuf,
}

impl DaemonState {
    #[allow(dead_code)]
    pub fn ephemeral_count(&self) -> usize {
        //This is a test-only function
        self.inner.lock().unwrap().ephemeral.len()
    }

    pub async fn revoke_all_ephemeral(&self) {
        let ids: Vec<String> = self
            .inner
            .lock()
            .unwrap()
            .ephemeral
            .keys()
            .cloned()
            .collect();
        for id in ids {
            // Best effort: resolve composite ids to backend ids first.
            let target = self.resolve_backend_id(&id).await.unwrap_or(id.clone());
            let _ = self.backend.revoke(&target).await;
            self.audit.lock().unwrap().log(
                "auto_revoke",
                Some(id.clone()),
                "revoke_on_lock_or_sleep",
                None,
            );
        }
        self.inner.lock().unwrap().ephemeral.clear();
    }

    pub async fn cleanup_expired_ephemeral(&self) {
        let expired_ids: Vec<String> = {
            let mut inner = self.inner.lock().unwrap();
            let mut expired = Vec::new();
            let now = std::time::Instant::now();
            inner.ephemeral.retain(|id, expiry| match expiry {
                // None = indefinite (polkit-gated), never expires here.
                None => true,
                Some(t) if now >= *t => {
                    expired.push(id.clone());
                    false
                }
                Some(_) => true,
            });
            expired
        };

        for id in expired_ids {
            tracing::info!("Ephemeral approval expired for device: {}", id);
            // Actually revoke at the backend (previously only logged).
            let target = self.resolve_backend_id(&id).await.unwrap_or(id.clone());
            let revoked = self.backend.revoke(&target).await;
            self.audit.lock().unwrap().log(
                "ephemeral_expired",
                Some(id.clone()),
                if revoked {
                    "auto_revoke_on_expiry"
                } else {
                    "auto_revoke_on_expiry_failed"
                },
                None,
            );
        }
    }

    /// Map a caller-supplied id (backend numeric id or `vid:pid[:serial]`
    /// composite as emitted for udev events) to a backend device id.
    async fn resolve_backend_id(&self, device_id: &str) -> Option<String> {
        let devices = self.backend.list_devices().await;
        if devices.iter().any(|d| d.id == device_id) {
            return Some(device_id.to_string());
        }
        let parts: Vec<&str> = device_id.split(':').collect();
        if parts.len() == 2 || parts.len() == 3 {
            let want_vid = normalize_hex_id(parts[0]);
            let want_pid = normalize_hex_id(parts[1]);
            let want_serial = if parts.len() == 3 {
                Some(parts[2].to_string())
            } else {
                None
            };
            for d in &devices {
                if normalize_hex_id(&d.vendor_id) == want_vid
                    && normalize_hex_id(&d.product_id) == want_pid
                    && want_serial.as_ref().map(|s| s == &d.serial).unwrap_or(true)
                {
                    return Some(d.id.clone());
                }
            }
        }
        None
    }
}

/// Device ids travel to `usbguard allow-device` as a single argv element
/// (no shell), but still reject controls/whitespace/shell metachars so
/// crafted ids cannot pollute logs or surprise the backend.
fn is_valid_device_id(device_id: &str) -> bool {
    !device_id.is_empty()
        && device_id.len() <= 64
        && device_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':' | '.' | '/'))
}

fn normalize_hex_id(s: &str) -> String {
    s.trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_lowercase()
}

fn is_hex4(s: &str) -> bool {
    let t = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    t.len() == 4 && t.chars().all(|c| c.is_ascii_hexdigit())
}

/// Fail-closed validation for signed baselines before rule generation.
fn validate_baseline(b: &Baseline) -> Result<(), String> {
    if b.version != 1 {
        return Err(format!("unsupported baseline version {}", b.version));
    }
    if b.devices.is_empty() {
        return Err("baseline contains no devices".into());
    }
    if b.devices.len() > 1024 {
        return Err("baseline device limit exceeded".into());
    }
    if b.created_by.is_empty() || b.created_by.len() > 256 {
        return Err("invalid created_by".into());
    }
    for (i, d) in b.devices.iter().enumerate() {
        if !is_hex4(&d.vendor_id) {
            return Err(format!("device {} has invalid vendor_id", i));
        }
        if !is_hex4(&d.product_id) {
            return Err(format!("device {} has invalid product_id", i));
        }
        if let Some(s) = &d.serial {
            if s.len() > 128 || s.chars().any(|c| c.is_control()) {
                return Err(format!("device {} has invalid serial", i));
            }
        }
        if d.device_type.len() > 64 {
            return Err(format!("device {} has invalid device_type", i));
        }
        if let Some(c) = &d.comment {
            if c.len() > 512 {
                return Err(format!("device {} has invalid comment", i));
            }
        }
        if d.descriptors_hash.len() > 256 {
            return Err(format!("device {} has invalid descriptors_hash", i));
        }
    }
    Ok(())
}

/// Key file names must stay flat inside the trusted dir (no traversal).
fn is_valid_key_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !name.contains("..")
        && !name.contains('/')
}

fn sanitize_rule_string(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn generate_rules_from_baseline(b: &Baseline) -> String {
    // Very conservative rule builder: allow by vid:pid and optional serial.
    // Example: "allow id 046d:c534 serial \"ABC\" with-interface *:*:*".
    let mut out = String::new();
    for d in &b.devices {
        // Sanitize IDs
        let vid = sanitize_rule_string(&d.vendor_id)
            .trim_start_matches("0x")
            .to_lowercase();
        let pid = sanitize_rule_string(&d.product_id)
            .trim_start_matches("0x")
            .to_lowercase();
        let id = format!("{}:{}", vid, pid);

        if let Some(serial) = &d.serial {
            // Sanitize serial: reject control chars including newlines
            let sanitized_serial = sanitize_rule_string(serial);
            // Must escape backslash BEFORE quote to prevent serial ending with \
            // from escaping the closing quote delimiter
            let escaped_serial = sanitized_serial.replace('\\', "\\\\").replace('"', "\\\"");
            out.push_str(&format!("allow id {} serial \"{}\"\n", id, escaped_serial));
        } else {
            out.push_str(&format!("allow id {}\n", id));
        }
    }
    out
}

#[derive(Default)]
struct StateInner {
    deny_unknown: bool,
    /// None expiry = indefinite approval (polkit-gated at grant time).
    ephemeral: HashMap<String, Option<Instant>>,
}

impl DaemonState {
    pub fn new<B>(backend: B) -> Self
    where
        B: UsbBackend + 'static,
    {
        Self::new_with_audit_path(backend, PathBuf::from("/var/log/lusby/audit.log"))
    }

    pub fn new_with_audit_path<B>(backend: B, audit_path: PathBuf) -> Self
    where
        B: UsbBackend + 'static,
    {
        let audit = AuditLogger::new(audit_path).expect("init audit");
        Self {
            inner: Arc::new(Mutex::new(StateInner {
                deny_unknown: true,
                ephemeral: HashMap::new(),
            })),
            backend: Arc::new(backend),
            audit: Arc::new(Mutex::new(audit)),
            baselines_dir: PathBuf::from("/etc/lusby/baselines"),
            trusted_pubkeys_dir: PathBuf::from("/etc/lusby/trusted_pubkeys"),
        }
    }
}

#[interface(name = "org.lusby.Daemon")]
impl DaemonState {
    async fn get_policy_status(&self) -> PolicyStatus {
        let deny: bool = self.inner.lock().unwrap().deny_unknown;
        PolicyStatus { deny_unknown: deny }
    }

    async fn list_devices(&self) -> Vec<DeviceInfo> {
        self.backend.list_devices().await
    }

    async fn request_ephemeral_allow(
        &self,
        device_id: &str,
        ttl: u32,
        requester_uid: u32,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> bool {
        // Never trust the client-supplied uid for audit; derive it from the bus.
        let real_uid = sender_uid(conn, &header).await.unwrap_or(requester_uid);
        // Eingabevalidierung
        let valid_id: bool = is_valid_device_id(device_id);
        // TTL: 0 = indefinite (privileged), 1-86400 = temporary (1 second to 1 day)
        let valid_ttl: bool = ttl == 0 || (1..=86400).contains(&ttl);
        if !valid_id || !valid_ttl {
            self.audit.lock().unwrap().log(
                "ephemeral_allow_reject",
                Some(device_id.to_string()),
                "invalid_input",
                Some(real_uid),
            );
            return false;
        }
        // Indefinite approvals bypass expiry + baseline signing, so they
        // require the same polkit authorization as persistent changes.
        if ttl == 0
            && !check_manage_authorization(conn, &header)
                .await
                .unwrap_or(false)
        {
            self.audit.lock().unwrap().log(
                "ephemeral_allow_reject",
                Some(device_id.to_string()),
                "polkit_denied_indefinite",
                Some(real_uid),
            );
            return false;
        }
        let target = self
            .resolve_backend_id(device_id)
            .await
            .unwrap_or(device_id.to_string());
        let ok: bool = self.backend.allow_ephemeral(&target, ttl).await;
        self.audit.lock().unwrap().log(
            "ephemeral_allow",
            Some(device_id.to_string()),
            if ok { "allow_ok" } else { "allow_fail" },
            Some(real_uid),
        );
        if ok {
            let expiry: Option<Instant> = if ttl == 0 {
                None
            } else {
                Some(Instant::now() + Duration::from_secs(ttl as u64))
            };
            self.inner
                .lock()
                .unwrap()
                .ephemeral
                .insert(device_id.to_string(), expiry);
        }
        ok
    }

    async fn apply_persistent_allow(
        &self,
        _baseline_path: &str,
        _signer_id: &str,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> bool {
        let real_uid = sender_uid(conn, &header).await;
        // Polkit authorization
        if !check_manage_authorization(conn, &header)
            .await
            .unwrap_or(false)
        {
            self.audit
                .lock()
                .unwrap()
                .log("policy_denied", None, "polkit_denied", real_uid);
            return false;
        }
        if _signer_id.len() > 128 {
            self.audit.lock().unwrap().log(
                "security",
                None,
                "baseline_signer_id_invalid",
                real_uid,
            );
            return false;
        }
        // Load baseline JSON, verify against any trusted key, then copy into baselines_dir
        let path = PathBuf::from(_baseline_path);
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            self.audit.lock().unwrap().log(
                "security",
                None,
                "baseline_path_traversal_attempt",
                real_uid,
            );
            return false;
        }
        // Bound file size before reading (fail-closed against /dev/zero etc.).
        const MAX_BASELINE_BYTES: u64 = 1024 * 1024;
        match fs::metadata(&path) {
            Ok(md) => {
                if !md.is_file() || md.len() > MAX_BASELINE_BYTES {
                    self.audit.lock().unwrap().log(
                        "security",
                        None,
                        "baseline_file_rejected",
                        real_uid,
                    );
                    return false;
                }
            }
            Err(e) => {
                self.audit.lock().unwrap().log(
                    "security",
                    None,
                    &format!("baseline_read_failed: {}", e),
                    real_uid,
                );
                return false;
            }
        }
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                self.audit.lock().unwrap().log(
                    "security",
                    None,
                    &format!("baseline_read_failed: {}", e),
                    real_uid,
                );
                return false;
            }
        };
        let baseline: Baseline = match serde_json::from_slice(&data) {
            Ok(b) => b,
            Err(e) => {
                self.audit.lock().unwrap().log(
                    "security",
                    None,
                    &format!("baseline_parse_failed: {} (path: {:?})", e, path),
                    real_uid,
                );
                return false;
            }
        };
        if let Err(e) = validate_baseline(&baseline) {
            self.audit.lock().unwrap().log(
                "security",
                None,
                &format!("baseline_validation_failed: {}", e),
                real_uid,
            );
            return false;
        }
        // Load trusted keys
        let mut verified = false;
        if let Ok(entries) = fs::read_dir(&self.trusted_pubkeys_dir) {
            for e in entries.flatten() {
                if e.path().extension().and_then(|s| s.to_str()) == Some("pub") {
                    if let Ok(bytes) = fs::read(e.path()) {
                        if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                            let vk = VerifyingKey::from_bytes(&arr);
                            if let Ok(vk) = vk {
                                if let Ok(true) = baseline.verify_signature(&vk) {
                                    verified = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        if !verified {
            self.audit.lock().unwrap().log(
                "security",
                None,
                "baseline_signature_unverified",
                real_uid,
            );
            return false;
        }
        // Copy file into baselines_dir with a unique timestamped name
        // (nanoseconds + pid avoids same-second collisions overwriting).
        let filename = format!(
            "baseline_{}_{}.json",
            chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ"),
            std::process::id()
        );
        let dest = self.baselines_dir.join(filename);
        if let Some(dir) = dest.parent() {
            if let Err(e) = fs::create_dir_all(dir) {
                self.audit.lock().unwrap().log(
                    "security",
                    None,
                    &format!("baseline_dir_create_failed: {}", e),
                    real_uid,
                );
                return false;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
            }
        }
        // (Entfernt: doppelter Schreibvorgang)
        // Schreibe Datei mit restriktiven Berechtigungen (nur Owner darf lesen/schreiben)
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&dest)
        {
            Ok(f) => f,
            Err(e) => {
                self.audit.lock().unwrap().log(
                    "security",
                    None,
                    &format!("baseline_file_create_failed: {}", e),
                    real_uid,
                );
                return false;
            }
        };
        let ok = file.write_all(&data).is_ok() && file.sync_all().is_ok();
        self.audit.lock().unwrap().log(
            "persistent_allow",
            None,
            if ok {
                "baseline_applied"
            } else {
                "baseline_apply_failed"
            },
            real_uid,
        );
        if !ok {
            return false;
        }

        // Generate usbguard rules from baseline and apply atomically, dann reload
        let rules = generate_rules_from_baseline(&baseline);
        if let Err(e) = UsbguardBackend::apply_rules_atomically(&rules) {
            tracing::error!(error=?e, "failed to apply usbguard rules atomically");
            self.audit.lock().unwrap().log(
                "persistent_allow",
                None,
                "baseline_rules_apply_failed",
                real_uid,
            );
            return false;
        }
        true
    }

    async fn revoke_device(
        &self,
        device_id: &str,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> bool {
        let real_uid = sender_uid(conn, &header).await;
        if !is_valid_device_id(device_id) {
            self.audit.lock().unwrap().log(
                "revoke_reject",
                Some(device_id.to_string()),
                "invalid_input",
                real_uid,
            );
            return false;
        }
        let target = self
            .resolve_backend_id(device_id)
            .await
            .unwrap_or(device_id.to_string());
        let ok = self.backend.revoke(&target).await;
        // A manual revoke supersedes any pending ephemeral approval.
        self.inner.lock().unwrap().ephemeral.remove(device_id);
        if target != device_id {
            self.inner.lock().unwrap().ephemeral.remove(&target);
        }
        self.audit.lock().unwrap().log(
            "revoke",
            Some(device_id.to_string()),
            if ok { "revoke_ok" } else { "revoke_fail" },
            real_uid,
        );
        ok
    }

    async fn get_device_info(&self, device_id: &str) -> DeviceInfo {
        if let Some(dev) = self.backend.get_device(device_id).await {
            return dev;
        }
        // Fall back to composite-id resolution (udev-style ids).
        if let Some(target) = self.resolve_backend_id(device_id).await {
            if let Some(dev) = self.backend.get_device(&target).await {
                return dev;
            }
        }
        DeviceInfo {
            id: String::new(),
            vendor_id: String::new(),
            product_id: String::new(),
            serial: String::new(),
            fingerprint: String::new(),
            device_type: String::new(),
            allowed: false,
            persistent: false,
        }
    }

    async fn get_policy_status_string(&self) -> String {
        // Convenience method for quick manual testing
        let deny = self.inner.lock().unwrap().deny_unknown;
        format!("deny_unknown={}", deny)
    }

    /// List file names of trusted public keys
    async fn list_trusted_pubkeys(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Vec<String> {
        if !check_manage_authorization(conn, &header)
            .await
            .unwrap_or(false)
        {
            return vec![];
        }
        let mut names = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.trusted_pubkeys_dir) {
            for e in entries.flatten() {
                if e.path().extension().and_then(|s| s.to_str()) == Some("pub") {
                    if let Some(name) = e.file_name().to_str() {
                        names.push(name.to_string());
                    }
                }
            }
        }
        names
    }

    /// Add a trusted public key (raw 32-byte) as a file named `<name>.pub`
    async fn add_trusted_pubkey(
        &self,
        name: &str,
        key_bytes_b64: &str,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> bool {
        let real_uid = sender_uid(conn, &header).await;
        if !check_manage_authorization(conn, &header)
            .await
            .unwrap_or(false)
        {
            self.audit.lock().unwrap().log(
                "policy_denied",
                None,
                "polkit_denied_add_pubkey",
                real_uid,
            );
            return false;
        }
        // Flat, traversal-free file name.
        let stem = name.strip_suffix(".pub").unwrap_or(name);
        if !is_valid_key_name(stem) || key_bytes_b64.len() > 128 {
            self.audit
                .lock()
                .unwrap()
                .log("security", None, "add_pubkey_invalid_input", real_uid);
            return false;
        }
        let bytes = match base64::engine::general_purpose::STANDARD.decode(key_bytes_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };
        if bytes.len() != 32 {
            return false;
        }
        // Reject bytes that are not a valid ed25519 point.
        if VerifyingKey::from_bytes(&bytes.as_slice().try_into().expect("len checked")).is_err() {
            self.audit
                .lock()
                .unwrap()
                .log("security", None, "add_pubkey_invalid_key", real_uid);
            return false;
        }
        let mut path = self.trusted_pubkeys_dir.clone();
        path.push(format!("{}.pub", stem));
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
            }
        }
        use std::os::unix::fs::OpenOptionsExt;
        let stored = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut f) => {
                let ok = f.write_all(&bytes).is_ok() && f.sync_all().is_ok();
                if !ok {
                    let _ = fs::remove_file(&path);
                }
                ok
            }
            Err(_) => false,
        };
        self.audit.lock().unwrap().log(
            "trust_store",
            None,
            if stored {
                "pubkey_added"
            } else {
                "pubkey_add_failed"
            },
            real_uid,
        );
        stored
    }

    /// Remove a trusted public key by file name
    async fn remove_trusted_pubkey(
        &self,
        name: &str,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> bool {
        let real_uid = sender_uid(conn, &header).await;
        if !check_manage_authorization(conn, &header)
            .await
            .unwrap_or(false)
        {
            self.audit.lock().unwrap().log(
                "policy_denied",
                None,
                "polkit_denied_remove_pubkey",
                real_uid,
            );
            return false;
        }
        let stem = name.strip_suffix(".pub").unwrap_or(name);
        if !is_valid_key_name(stem) {
            self.audit.lock().unwrap().log(
                "security",
                None,
                "remove_pubkey_invalid_input",
                real_uid,
            );
            return false;
        }
        let mut path = self.trusted_pubkeys_dir.clone();
        path.push(format!("{}.pub", stem));
        let ok = fs::remove_file(&path).is_ok();
        self.audit.lock().unwrap().log(
            "trust_store",
            None,
            if ok {
                "pubkey_removed"
            } else {
                "pubkey_remove_failed"
            },
            real_uid,
        );
        ok
    }

    // Signals
    #[zbus(signal)]
    async fn unknown_device_inserted(
        ctxt: &SignalContext<'_>,
        device: &DeviceInfo,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn device_removed(ctxt: &SignalContext<'_>, device_id: &str) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use lusby_common::baseline::DeviceEntry;

    #[test]
    fn test_generate_rules_safeguard() {
        let b = Baseline {
            version: 1,
            created_by: "test".into(),
            created_at: chrono::Utc::now(),
            devices: vec![DeviceEntry {
                vendor_id: "0x1234".into(),
                product_id: "0x5678".into(),
                serial: Some("AB\nC".into()), // malicious newline
                bus_path: None,
                descriptors_hash: "none".into(),
                device_type: "hid".into(),
                comment: None,
            }],
            signature: None,
        };
        let rules = generate_rules_from_baseline(&b);
        // We expect exactly one line because there is one device.
        let lines: Vec<&str> = rules.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "Should produce exactly one line, found: {:?}",
            lines
        );
        assert!(lines[0].contains("serial \"AB?C\""));
    }

    use proptest::prelude::*;

    #[test]
    fn device_id_validation_rejects_controls_and_shell() {
        assert!(is_valid_device_id("2"));
        assert!(is_valid_device_id("0x046d:0xc534:ABC-123"));
        assert!(is_valid_device_id("/dev/bus/usb/002/003"));
        assert!(!is_valid_device_id(""));
        assert!(!is_valid_device_id("a; rm -rf /"));
        assert!(!is_valid_device_id("a b"));
        assert!(!is_valid_device_id("a\nb"));
        assert!(!is_valid_device_id("a\x00b"));
        assert!(!is_valid_device_id(&"a".repeat(65)));
    }

    #[test]
    fn key_name_validation_blocks_traversal() {
        assert!(is_valid_key_name("mykey"));
        assert!(is_valid_key_name("my-key_1.2"));
        assert!(!is_valid_key_name(""));
        assert!(!is_valid_key_name("../../etc"));
        assert!(!is_valid_key_name("a/b"));
        assert!(!is_valid_key_name(".."));
        assert!(!is_valid_key_name("a;rm"));
    }

    #[test]
    fn baseline_validation_rejects_bad_ids() {
        let good = Baseline {
            version: 1,
            created_by: "test".into(),
            created_at: chrono::Utc::now(),
            devices: vec![DeviceEntry {
                vendor_id: "0x1234".into(),
                product_id: "5678".into(),
                serial: None,
                bus_path: None,
                descriptors_hash: "none".into(),
                device_type: "hid".into(),
                comment: None,
            }],
            signature: None,
        };
        assert!(validate_baseline(&good).is_ok());
        let mut bad = good.clone();
        bad.devices[0].vendor_id = "zz; rm".into();
        assert!(validate_baseline(&bad).is_err());
        let mut bad_ver = good.clone();
        bad_ver.version = 99;
        assert!(validate_baseline(&bad_ver).is_err());
        let mut empty = good.clone();
        empty.devices.clear();
        assert!(validate_baseline(&empty).is_err());
    }

    proptest! {
        #[test]
        fn rule_generation_safety(
            vid in "[0-9a-fA-F]{1,10}",
            pid in "[0-9a-fA-F]{1,10}",
            serial in proptest::option::of("\\PC*")
        ) {
             let b = Baseline {
                version: 1,
                created_by: "prop".into(),
                created_at: chrono::Utc::now(),
                devices: vec![DeviceEntry {
                    vendor_id: vid,
                    product_id: pid,
                    serial,
                    bus_path: None,
                    descriptors_hash: "none".into(),
                    device_type: "hid".into(),
                    comment: None,
                }],
                signature: None,
            };
            let rules = generate_rules_from_baseline(&b);
            let lines: Vec<&str> = rules.lines().collect();

            // Safety assertion: The rules string must NOT contain more lines than devices (1).
            // This ensures no newline injection was successfully performed to create extra rules.
            // Note: The generator always adds a newline at the end of each rule, so we expect exactly 1 line
            // if we filter out empty strings or simply count valid rules.
            // Our generator produces "allow ...\n", so `lines()` (which splits on \n) will see 1 item.

            prop_assert_eq!(lines.len(), 1, "Should produce exactly 1 rule line, found {}", lines.len());

            // Further assertion: The rule should verify basic syntax
            let rule = lines[0];
            prop_assert!(rule.starts_with("allow id "));

            // Check for no control characters (except maybe the ones we sanitized to '?' which is safe)
            // The output should be safe 7-bit ASCII or similar?
            // Actually, we replaced controls with '?'.
            // Let's ensure no raw newlines or CRs remain (already checked by lines.len()=1 mostly, but checking chars is good)
            prop_assert!(!rule.contains('\r'));
            prop_assert!(!rule.contains('\n'));
        }
    }
}
