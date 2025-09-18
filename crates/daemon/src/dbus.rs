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

use guardianusb_backend_usbguard::UsbguardBackend;
use guardianusb_common::backend::UsbBackend;
use guardianusb_common::baseline::Baseline;
use guardianusb_common::types::{DeviceInfo, PolicyStatus};

use crate::audit::AuditLogger;
use crate::polkit::check_manage_authorization;

#[derive(Clone)]
pub struct DaemonState {
    inner: Arc<Mutex<StateInner>>,
    backend: Arc<dyn UsbBackend>,
    audit: Arc<Mutex<AuditLogger>>,
    baselines_dir: PathBuf,
    trusted_pubkeys_dir: PathBuf,
}

impl DaemonState {
    pub fn ephemeral_count(&self) -> usize {
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
            let _ = self.backend.revoke(&id).await;
            self.audit.lock().unwrap().log(
                "auto_revoke",
                Some(id.clone()),
                "revoke_on_lock_or_sleep",
                None,
            );
        }
        self.inner.lock().unwrap().ephemeral.clear();
    }
}

fn generate_rules_from_baseline(b: &Baseline) -> String {
    // Very conservative rule builder: allow by vid:pid and optional serial.
    // Example: "allow id 046d:c534 serial \"ABC\" with-interface *:*:*".
    let mut out = String::new();
    for d in &b.devices {
        let id = format!(
            "{}:{}",
            d.vendor_id.trim_start_matches("0x").to_lowercase(),
            d.product_id.trim_start_matches("0x").to_lowercase()
        );
        if let Some(serial) = &d.serial {
            out.push_str(&format!(
                "allow id {} serial \"{}\"\n",
                id,
                serial.replace('"', "\\\"")
            ));
        } else {
            out.push_str(&format!("allow id {}\n", id));
        }
    }
    out
}

#[derive(Default)]
struct StateInner {
    deny_unknown: bool,
    ephemeral: HashMap<String, Instant>,
}

impl DaemonState {
    pub fn new<B>(backend: B) -> Self
    where
        B: UsbBackend + 'static,
    {
        Self::new_with_audit_path(backend, PathBuf::from("/var/log/guardianusb/audit.log"))
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
            baselines_dir: PathBuf::from("/etc/guardianusb/baselines"),
            trusted_pubkeys_dir: PathBuf::from("/etc/guardianusb/trusted_pubkeys"),
        }
    }
}

#[interface(name = "org.guardianusb.Daemon")]
impl DaemonState {
    async fn get_policy_status(&self) -> PolicyStatus {
        let deny: bool = self.inner.lock().unwrap().deny_unknown;
        PolicyStatus { deny_unknown: deny }
    }

    async fn list_devices(&self) -> Vec<DeviceInfo> {
        self.backend.list_devices().await
    }

    async fn request_ephemeral_allow(&self, device_id: &str, ttl: u32, requester_uid: u32) -> bool {
        // Eingabevalidierung
        let valid_id: bool = !device_id.is_empty() && device_id.len() <= 64 && device_id.is_ascii();
        let valid_ttl: bool = (1..=86400).contains(&ttl);
        let valid_uid: bool = requester_uid > 0;
        if !valid_id || !valid_ttl || !valid_uid {
            self.audit.lock().unwrap().log(
                "ephemeral_allow_reject",
                Some(device_id.to_string()),
                "invalid_input",
                Some(requester_uid),
            );
            return false;
        }
        let ok: bool = self.backend.allow_ephemeral(device_id, ttl).await;
        self.audit.lock().unwrap().log(
            "ephemeral_allow",
            Some(device_id.to_string()),
            if ok { "allow_ok" } else { "allow_fail" },
            Some(requester_uid),
        );
        if ok {
            let expiry: Instant = Instant::now() + Duration::from_secs(ttl as u64);
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
        // Polkit authorization
        if !check_manage_authorization(conn, &header)
            .await
            .unwrap_or(false)
        {
            self.audit
                .lock()
                .unwrap()
                .log("policy_denied", None, "polkit_denied", None);
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
                None,
            );
            return false;
        }
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                self.audit.lock().unwrap().log(
                    "security",
                    None,
                    &format!("baseline_read_failed: {}", e),
                    None,
                );
                return false;
            }
        };
        let baseline: Baseline = match serde_json::from_slice(&data) {
            Ok(b) => b,
            Err(_) => return false,
        };
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
            return false;
        }
        // Copy file into baselines_dir with a timestamped name
        let filename = format!(
            "baseline_{}.json",
            chrono::Utc::now().format("%Y%m%dT%H%M%SZ")
        );
        let dest = self.baselines_dir.join(filename);
        if let Some(dir) = dest.parent() {
            if let Err(e) = fs::create_dir_all(dir) {
                self.audit.lock().unwrap().log(
                    "security",
                    None,
                    &format!("baseline_dir_create_failed: {}", e),
                    None,
                );
                return false;
            }
        }
        // (Entfernt: doppelter Schreibvorgang)
        // Schreibe Datei mit restriktiven Berechtigungen (nur Owner darf lesen/schreiben)
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&dest)
        {
            Ok(f) => f,
            Err(e) => {
                self.audit.lock().unwrap().log(
                    "security",
                    None,
                    &format!("baseline_file_create_failed: {}", e),
                    None,
                );
                return false;
            }
        };
        let ok = file.write_all(&data).is_ok();
        self.audit.lock().unwrap().log(
            "persistent_allow",
            None,
            if ok {
                "baseline_applied"
            } else {
                "baseline_apply_failed"
            },
            None,
        );
        if !ok {
            return false;
        }

        // Generate usbguard rules from baseline and apply atomically, dann reload
        let rules = generate_rules_from_baseline(&baseline);
        if let Err(e) = UsbguardBackend::apply_rules_atomically(&rules) {
            tracing::error!(error=?e, "failed to apply usbguard rules atomically");
            return false;
        }
        true
    }

    async fn revoke_device(&self, device_id: &str) -> bool {
        let valid_id = !device_id.is_empty() && device_id.len() <= 64 && device_id.is_ascii();
        if !valid_id {
            self.audit.lock().unwrap().log(
                "revoke_reject",
                Some(device_id.to_string()),
                "invalid_input",
                None,
            );
            return false;
        }
        let ok = self.backend.revoke(device_id).await;
        self.audit.lock().unwrap().log(
            "revoke",
            Some(device_id.to_string()),
            if ok { "revoke_ok" } else { "revoke_fail" },
            None,
        );
        ok
    }

    async fn get_device_info(&self, device_id: &str) -> DeviceInfo {
        self.backend
            .get_device(device_id)
            .await
            .unwrap_or(DeviceInfo {
                id: String::new(),
                vendor_id: String::new(),
                product_id: String::new(),
                serial: String::new(),
                fingerprint: String::new(),
                device_type: String::new(),
                allowed: false,
                persistent: false,
            })
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
        if !check_manage_authorization(conn, &header)
            .await
            .unwrap_or(false)
        {
            return false;
        }
        let bytes = match base64::engine::general_purpose::STANDARD.decode(key_bytes_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };
        if bytes.len() != 32 {
            return false;
        }
        let mut path = self.trusted_pubkeys_dir.clone();
        let fname = if name.ends_with(".pub") {
            name.to_string()
        } else {
            format!("{}.pub", name)
        };
        path.push(fname);
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                if f.write_all(&bytes).is_err() {
                    return false;
                }
                true
            }
            Err(_) => false,
        }
    }

    /// Remove a trusted public key by file name
    async fn remove_trusted_pubkey(
        &self,
        name: &str,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> bool {
        if !check_manage_authorization(conn, &header)
            .await
            .unwrap_or(false)
        {
            return false;
        }
        let mut path = self.trusted_pubkeys_dir.clone();
        let fname = if name.ends_with(".pub") {
            name.to_string()
        } else {
            format!("{}.pub", name)
        };
        path.push(fname);
        fs::remove_file(path).is_ok()
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
