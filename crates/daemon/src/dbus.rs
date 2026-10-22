use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use zbus::message::Header;
use zbus::{interface, Connection, SignalContext};

use lusby_backend_usbguard::UsbguardBackend;
use lusby_common::backend::UsbBackend;
use lusby_common::baseline::{is_usbguard_hash, Baseline, DeviceEntry};
use lusby_common::types::{DeviceInfo, PolicyStatus};

use crate::audit::AuditLogger;
use crate::config::Config;
use crate::polkit::{check_manage_authorization, sender_uid};

/// Max unauthenticated requests per uid per minute (ListDevices,
/// GetDeviceInfo, RequestEphemeralAllow, RevokeDevice share the budget).
const RATE_LIMIT_PER_MINUTE: u32 = 60;
/// Cumulative seconds of temporary access grantable per device within the
/// rolling window without polkit re-authentication.
const GRANT_WINDOW: Duration = Duration::from_secs(24 * 3600);
const GRANT_WINDOW_CAP_SECS: u32 = 86400;

#[derive(Clone, Debug)]
struct EphemeralGrant {
    /// None = indefinite (polkit-gated at grant time).
    expiry: Option<Instant>,
    owner_uid: u32,
}

#[derive(Default)]
struct StateInner {
    /// Desired policy from config; the *reported* status comes from usbguard.
    deny_unknown: bool,
    ephemeral: HashMap<String, EphemeralGrant>,
    /// Per-uid fixed request windows.
    rate: HashMap<u32, (Instant, u32)>,
    /// Per-device rolling grant windows (anti indefinite-renewal).
    grant_window: HashMap<String, (Instant, u32)>,
    /// Device entries of all applied baselines (persistence reporting).
    baselines: Vec<DeviceEntry>,
}

#[derive(Clone)]
pub struct DaemonState {
    inner: Arc<Mutex<StateInner>>,
    backend: Arc<dyn UsbBackend>,
    audit: Arc<Mutex<AuditLogger>>,
    baselines_dir: PathBuf,
    trusted_pubkeys_dir: PathBuf,
    state_dir: PathBuf,
    revoke_on_lock: bool,
    revoke_on_suspend: bool,
    wake: Arc<tokio::sync::Notify>,
}

#[derive(Serialize, Deserialize)]
struct PersistedGrant {
    id: String,
    owner_uid: u32,
    expires_at_ms: Option<u64>,
}

/// Map a caller-supplied id (backend numeric id or `vid:pid[:serial]`
/// composite as emitted for udev events) to a backend device id.
/// Serials may contain `:`, so the composite is split into at most 3 parts.
/// Ambiguous VID/PID-only ids (several identical devices present) resolve to
/// nothing instead of silently picking the first match.
fn resolve_in(devices: &[DeviceInfo], device_id: &str) -> Option<String> {
    if let Some(d) = devices.iter().find(|d| d.id == device_id) {
        return Some(d.id.clone());
    }
    let mut parts = device_id.splitn(3, ':');
    let (Some(vid), Some(pid)) = (parts.next(), parts.next()) else {
        return None;
    };
    let want_serial = parts.next();
    let want_vid = normalize_hex_id(vid);
    let want_pid = normalize_hex_id(pid);
    if want_vid.is_empty() || want_pid.is_empty() {
        return None;
    }
    let matches: Vec<&DeviceInfo> = devices
        .iter()
        .filter(|d| {
            normalize_hex_id(&d.vendor_id) == want_vid
                && normalize_hex_id(&d.product_id) == want_pid
                && want_serial.map(|s| s == d.serial).unwrap_or(true)
        })
        .collect();
    match matches.len() {
        1 => Some(matches[0].id.clone()),
        _ => None,
    }
}

/// Device ids travel to `usbguard allow-device` as a single argv element
/// (no shell). USB serials legitimately contain spaces, `+`, `@`, `#`, etc.,
/// so printable ASCII is accepted; controls and non-ASCII are not. A leading
/// `-` is rejected so an id can never be parsed as an option by the backend.
fn is_valid_device_id(device_id: &str) -> bool {
    if device_id.is_empty() || device_id.len() > 256 {
        return false;
    }
    if device_id.starts_with('-') {
        return false;
    }
    let first_ok = device_id
        .chars()
        .next()
        .map(|c| c.is_ascii_alphanumeric() || c == '/')
        .unwrap_or(false);
    first_ok
        && device_id
            .chars()
            .all(|c| (0x20..=0x7e).contains(&(c as u32)))
}

fn normalize_hex_id(s: &str) -> String {
    s.trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_lowercase()
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
        // Reject dot-only or dot-leading stems like "." or ".hidden".
        && name.chars().next().map(|c| c.is_ascii_alphanumeric()).unwrap_or(false)
        && name.chars().any(|c| c.is_ascii_alphanumeric())
}

fn sanitize_rule_string(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// Rule builder with device identity binding: VID/PID plus optional serial,
/// the usbguard device hash (descriptor hash) when known, and `with-interface`
/// restrictions so a composite device cannot expose extra interfaces.
fn generate_rules_from_baseline(b: &Baseline) -> String {
    let mut out = String::new();
    for d in &b.devices {
        let vid = sanitize_rule_string(&d.vendor_id)
            .trim_start_matches("0x")
            .to_lowercase();
        let pid = sanitize_rule_string(&d.product_id)
            .trim_start_matches("0x")
            .to_lowercase();
        let mut rule = format!("allow id {}:{}", vid, pid);
        if let Some(serial) = &d.serial {
            // Escaping: backslash BEFORE quote, so a trailing backslash cannot
            // escape the closing quote delimiter.
            let sanitized_serial = sanitize_rule_string(serial);
            let escaped_serial = sanitized_serial.replace('\\', "\\\\").replace('"', "\\\"");
            rule.push_str(&format!(" serial \"{}\"", escaped_serial));
        }
        if is_usbguard_hash(&d.descriptors_hash) {
            // Strongest binding available in usbguard's rule language: the
            // hash covers the device descriptors, so a spoofed VID/PID/serial
            // with different descriptors does not match.
            rule.push_str(&format!(" hash \"{}\"", d.descriptors_hash));
        }
        for spec in &d.interfaces {
            rule.push_str(&format!(" with-interface {}", sanitize_rule_string(spec)));
        }
        rule.push('\n');
        out.push_str(&rule);
    }
    out
}

/// Does this baseline entry describe that live device?
fn entry_matches_device(e: &DeviceEntry, d: &DeviceInfo) -> bool {
    if normalize_hex_id(&e.vendor_id) != normalize_hex_id(&d.vendor_id) {
        return false;
    }
    if normalize_hex_id(&e.product_id) != normalize_hex_id(&d.product_id) {
        return false;
    }
    if let Some(s) = &e.serial {
        if s != &d.serial {
            return false;
        }
    }
    if is_usbguard_hash(&e.descriptors_hash) && !d.usbguard_hash.is_empty() {
        return e.descriptors_hash == d.usbguard_hash;
    }
    true
}

fn rate_ok(inner: &mut StateInner, uid: u32) -> bool {
    let now = Instant::now();
    if inner.rate.len() > 256 {
        inner
            .rate
            .retain(|_, (start, _)| now.duration_since(*start) < Duration::from_secs(60));
    }
    let e = inner.rate.entry(uid).or_insert((now, 0));
    if now.duration_since(e.0) >= Duration::from_secs(60) {
        *e = (now, 0);
    }
    if e.1 >= RATE_LIMIT_PER_MINUTE {
        return false;
    }
    e.1 += 1;
    true
}

fn load_ephemeral_state(state_dir: &Path) -> HashMap<String, EphemeralGrant> {
    let mut map = HashMap::new();
    let Ok(data) = fs::read_to_string(state_dir.join("ephemeral.json")) else {
        return map;
    };
    let Ok(entries) = serde_json::from_str::<Vec<PersistedGrant>>(&data) else {
        return map;
    };
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    for e in entries {
        let expiry = match e.expires_at_ms {
            Some(ms) if ms > now_ms => Some(Instant::now() + Duration::from_millis(ms - now_ms)),
            // Already expired while the daemon was down: keep it visible so
            // the first cleanup pass revokes it.
            Some(_) => Some(Instant::now()),
            None => None,
        };
        map.insert(
            e.id,
            EphemeralGrant {
                expiry,
                owner_uid: e.owner_uid,
            },
        );
    }
    map
}

fn load_baseline_entries(baselines_dir: &Path) -> Vec<DeviceEntry> {
    let mut entries = Vec::new();
    let Ok(dir) = fs::read_dir(baselines_dir) else {
        return entries;
    };
    for e in dir.flatten() {
        let path = e.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let Ok(md) = fs::metadata(&path) else {
            continue;
        };
        if !md.is_file() || md.len() > 1024 * 1024 {
            continue;
        }
        let Ok(data) = fs::read(&path) else { continue };
        let Ok(b) = serde_json::from_slice::<Baseline>(&data) else {
            continue;
        };
        if b.validate().is_err() {
            continue;
        }
        entries.extend(b.devices);
    }
    entries
}

impl DaemonState {
    #[allow(dead_code)]
    pub fn ephemeral_count(&self) -> usize {
        //This is a test-only function
        self.inner.lock().unwrap().ephemeral.len()
    }

    pub fn revoke_on_lock(&self) -> bool {
        self.revoke_on_lock
    }

    pub fn revoke_on_suspend(&self) -> bool {
        self.revoke_on_suspend
    }

    pub fn new<B>(backend: B) -> Self
    where
        B: UsbBackend + 'static,
    {
        let cfg = Config::load_default();
        let mut state = Self::new_with_paths(
            backend,
            cfg.paths.audit_log.clone(),
            cfg.paths.state_dir.clone(),
            cfg.paths.baselines_system.clone(),
            cfg.paths.trusted_pubkeys.clone(),
        );
        state.revoke_on_lock = cfg.policy.revoke_on_lock;
        state.revoke_on_suspend = cfg.policy.revoke_on_suspend;
        state.inner.lock().unwrap().deny_unknown = cfg.policy.deny_unknown;
        state
    }

    /// Test entry point with an explicit audit path (used by integration
    /// tests through the library target; unused in the daemon binary).
    #[allow(dead_code)]
    pub fn new_with_audit_path<B>(backend: B, audit_path: PathBuf) -> Self
    where
        B: UsbBackend + 'static,
    {
        let state_dir = audit_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        Self::new_with_paths(
            backend,
            audit_path,
            state_dir,
            PathBuf::from("/etc/lusby/baselines"),
            PathBuf::from("/etc/lusby/trusted_pubkeys"),
        )
    }

    fn new_with_paths<B>(
        backend: B,
        audit_path: PathBuf,
        state_dir: PathBuf,
        baselines_dir: PathBuf,
        trusted_pubkeys_dir: PathBuf,
    ) -> Self
    where
        B: UsbBackend + 'static,
    {
        let audit = AuditLogger::new(audit_path).expect("init audit");
        let ephemeral = load_ephemeral_state(&state_dir);
        let baselines = load_baseline_entries(&baselines_dir);
        Self {
            inner: Arc::new(Mutex::new(StateInner {
                deny_unknown: true,
                ephemeral,
                rate: HashMap::new(),
                grant_window: HashMap::new(),
                baselines,
            })),
            backend: Arc::new(backend),
            audit: Arc::new(Mutex::new(audit)),
            baselines_dir,
            trusted_pubkeys_dir,
            state_dir,
            revoke_on_lock: true,
            revoke_on_suspend: true,
            wake: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Warn when the configured policy and usbguard's effective policy differ.
    pub async fn check_policy_config(&self) {
        let want = self.inner.lock().unwrap().deny_unknown;
        match self.backend.implicit_policy_target().await {
            Some(t) if (t == "block") != want => {
                tracing::warn!(
                    usbguard_target = %t,
                    config_deny_unknown = want,
                    "usbguard ImplicitPolicyTarget disagrees with config.deny_unknown"
                );
            }
            None => {
                tracing::warn!(
                    "cannot read usbguard ImplicitPolicyTarget; policy status is best-effort"
                );
            }
            _ => {}
        }
    }

    async fn raw_list_devices(&self) -> Vec<DeviceInfo> {
        self.backend.list_devices().await
    }

    async fn list_annotated(&self) -> Vec<DeviceInfo> {
        let mut devices = self.raw_list_devices().await;
        {
            let inner = self.inner.lock().unwrap();
            for d in devices.iter_mut() {
                d.persistent = inner.baselines.iter().any(|e| entry_matches_device(e, d));
            }
        }
        devices
    }

    /// `None` = device unknown to the backend; otherwise whether it is allowed.
    /// Used by the udev monitor so only actually blocked devices notify.
    #[allow(dead_code)] // only used by the udev-monitor feature
    pub async fn is_device_allowed(
        &self,
        vendor_id: &str,
        product_id: &str,
        serial: &str,
    ) -> Option<bool> {
        let devices = self.raw_list_devices().await;
        let want_vid = normalize_hex_id(vendor_id);
        let want_pid = normalize_hex_id(product_id);
        let matches: Vec<&DeviceInfo> = devices
            .iter()
            .filter(|d| {
                normalize_hex_id(&d.vendor_id) == want_vid
                    && normalize_hex_id(&d.product_id) == want_pid
                    && d.serial == serial
            })
            .collect();
        match matches.len() {
            0 => None,
            _ => Some(matches.iter().any(|d| d.allowed)),
        }
    }

    fn rate_ok(&self, uid: u32) -> bool {
        rate_ok(&mut self.inner.lock().unwrap(), uid)
    }

    /// True while another `ttl` seconds fit into the unauthenticated grant
    /// window for this device; false once polkit re-authentication is due.
    fn within_grant_window(&self, device_id: &str, ttl: u32) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        if inner.grant_window.len() > 1024 {
            inner
                .grant_window
                .retain(|_, (start, _)| now.duration_since(*start) < GRANT_WINDOW);
        }
        let e = inner
            .grant_window
            .entry(device_id.to_string())
            .or_insert((now, 0));
        if now.duration_since(e.0) >= GRANT_WINDOW {
            *e = (now, 0);
        }
        e.1.saturating_add(ttl) <= GRANT_WINDOW_CAP_SECS
    }

    fn note_grant(&self, device_id: &str, ttl: u32) {
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        let e = inner
            .grant_window
            .entry(device_id.to_string())
            .or_insert((now, 0));
        if now.duration_since(e.0) >= GRANT_WINDOW {
            *e = (now, 0);
        }
        e.1 = e.1.saturating_add(ttl);
    }

    fn notify_grant(&self) {
        self.wake.notify_one();
    }

    pub async fn grant_added(&self) {
        self.wake.notified().await;
    }

    /// Delay until the next cleanup run: the earliest expiry (or a short
    /// retry backoff while failed revocations are pending), capped at 60s.
    pub fn next_cleanup_delay(&self) -> Duration {
        let inner = self.inner.lock().unwrap();
        let now = Instant::now();
        let mut delay = Duration::from_secs(60);
        for grant in inner.ephemeral.values() {
            let delta = match grant.expiry {
                Some(e) if e > now => e.duration_since(now),
                // Past due (revocation pending or failed): back off briefly.
                Some(_) => Duration::from_secs(30),
                None => continue,
            };
            delay = delay.min(delta);
        }
        delay.max(Duration::from_millis(50))
    }

    fn persist_ephemeral(&self) {
        let entries: Vec<PersistedGrant> = {
            let inner = self.inner.lock().unwrap();
            inner
                .ephemeral
                .iter()
                .map(|(id, g)| PersistedGrant {
                    id: id.clone(),
                    owner_uid: g.owner_uid,
                    expires_at_ms: g.expiry.map(|e| {
                        let delta = e.saturating_duration_since(Instant::now());
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0)
                            .saturating_add(delta.as_millis() as u64)
                    }),
                })
                .collect()
        };
        let Ok(data) = serde_json::to_string(&entries) else {
            return;
        };
        let _ = fs::create_dir_all(&self.state_dir);
        let tmp = self.state_dir.join("ephemeral.json.tmp");
        let finalp = self.state_dir.join("ephemeral.json");
        if fs::write(&tmp, &data).is_ok() {
            let _ = fs::rename(&tmp, &finalp);
        }
    }

    fn is_baseline_revoked(&self, hash: &str) -> bool {
        let path = self
            .baselines_dir
            .parent()
            .map(|p| p.join("revoked_baselines"))
            .unwrap_or_else(|| PathBuf::from("/etc/lusby/revoked_baselines"));
        let Ok(text) = fs::read_to_string(path) else {
            return false;
        };
        text.lines()
            .map(|l| l.trim())
            .any(|l| !l.is_empty() && !l.starts_with('#') && l == hash)
    }

    /// Revoke every ephemeral approval (lock/sleep/shutdown). Entries are
    /// drained first so approvals granted concurrently are never dropped
    /// without revocation; failures stay tracked for retry.
    pub async fn revoke_all_ephemeral(&self) {
        let grants: Vec<(String, EphemeralGrant)> = {
            let mut inner = self.inner.lock().unwrap();
            inner.ephemeral.drain().collect()
        };
        if grants.is_empty() {
            return;
        }
        let devices = self.raw_list_devices().await;
        let mut results: Vec<(String, u32, bool)> = Vec::new();
        // Bounded concurrency: lock/suspend must complete quickly even with
        // many approved devices.
        for chunk in grants.chunks(4) {
            let futs = chunk.iter().map(|(id, g)| {
                let devices = &devices;
                async move {
                    let target = resolve_in(devices, id).unwrap_or_else(|| id.clone());
                    let ok = self.backend.revoke(&target).await;
                    (id.clone(), g.owner_uid, ok)
                }
            });
            results.extend(futures_util::future::join_all(futs).await);
        }
        // Deterministic audit order.
        results.sort_by(|a, b| a.0.cmp(&b.0));
        for (id, owner, ok) in results {
            let _ = self.audit.lock().unwrap().log(
                "auto_revoke",
                Some(id.clone()),
                if ok {
                    "revoke_on_lock_or_sleep"
                } else {
                    "revoke_on_lock_or_sleep_failed"
                },
                Some(owner),
            );
            if !ok {
                let mut inner = self.inner.lock().unwrap();
                inner.ephemeral.insert(
                    id,
                    EphemeralGrant {
                        expiry: Some(Instant::now()),
                        owner_uid: owner,
                    },
                );
            }
        }
        self.persist_ephemeral();
    }

    /// Revoke expired approvals. Entries are removed only after a confirmed
    /// revocation; failures stay tracked and are retried on later passes.
    pub async fn cleanup_expired_ephemeral(&self) {
        let expired_ids: Vec<String> = {
            let inner = self.inner.lock().unwrap();
            let now = Instant::now();
            inner
                .ephemeral
                .iter()
                .filter(|(_, g)| g.expiry.map(|e| now >= e).unwrap_or(false))
                .map(|(id, _)| id.clone())
                .collect()
        };
        if expired_ids.is_empty() {
            return;
        }
        let devices = self.raw_list_devices().await;
        for id in expired_ids {
            tracing::info!("Ephemeral approval expired for device: {}", id);
            let target = resolve_in(&devices, &id).unwrap_or_else(|| id.clone());
            let revoked = self.backend.revoke(&target).await;
            if revoked {
                self.inner.lock().unwrap().ephemeral.remove(&id);
            }
            let _ = self.audit.lock().unwrap().log(
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
        self.persist_ephemeral();
    }
}

fn fsync_dir(dir: &Path) {
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

#[interface(name = "org.lusby.Daemon")]
impl DaemonState {
    async fn get_policy_status(&self) -> PolicyStatus {
        // Report the backend's effective policy, not a hardcoded flag.
        let deny = match self.backend.implicit_policy_target().await {
            Some(t) => t == "block",
            None => self.inner.lock().unwrap().deny_unknown,
        };
        PolicyStatus { deny_unknown: deny }
    }

    async fn list_devices(
        &self,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<Vec<DeviceInfo>> {
        let uid = sender_uid(conn, &header).await.unwrap_or(u32::MAX);
        if !self.rate_ok(uid) {
            return Err(zbus::fdo::Error::Failed("rate limited".into()));
        }
        Ok(self.list_annotated().await)
    }

    async fn request_ephemeral_allow(
        &self,
        device_id: &str,
        ttl: u32,
        _requester_uid: u32,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> bool {
        // Never trust the client-supplied uid for audit; derive it from the
        // bus and fail closed when that is not possible.
        let real_uid = match sender_uid(conn, &header).await {
            Some(u) => u,
            None => {
                let _ = self.audit.lock().unwrap().log(
                    "ephemeral_allow_reject",
                    Some(device_id.to_string()),
                    "sender_uid_unavailable",
                    None,
                );
                return false;
            }
        };
        // TTL: 0 = indefinite (privileged), 1-86400 = temporary
        let valid_id = is_valid_device_id(device_id);
        let valid_ttl = ttl == 0 || (1..=86400).contains(&ttl);
        if !valid_id || !valid_ttl {
            let _ = self.audit.lock().unwrap().log(
                "ephemeral_allow_reject",
                Some(device_id.to_string()),
                "invalid_input",
                Some(real_uid),
            );
            return false;
        }
        if !self.rate_ok(real_uid) {
            let _ = self.audit.lock().unwrap().log(
                "ephemeral_allow_reject",
                Some(device_id.to_string()),
                "rate_limited",
                Some(real_uid),
            );
            return false;
        }
        // polkit is required for indefinite grants and once the cumulative
        // unauthenticated grant window for this device is exhausted, so
        // repeated renewal cannot extend access forever without auth.
        let needs_polkit = ttl == 0 || !self.within_grant_window(device_id, ttl);
        if needs_polkit
            && !check_manage_authorization(conn, &header)
                .await
                .unwrap_or(false)
        {
            let _ = self.audit.lock().unwrap().log(
                "ephemeral_allow_reject",
                Some(device_id.to_string()),
                "polkit_denied",
                Some(real_uid),
            );
            return false;
        }
        let devices = self.raw_list_devices().await;
        let Some(target) = resolve_in(&devices, device_id) else {
            let _ = self.audit.lock().unwrap().log(
                "ephemeral_allow_reject",
                Some(device_id.to_string()),
                "device_not_found",
                Some(real_uid),
            );
            return false;
        };
        let ok = self.backend.allow_ephemeral(&target, ttl).await;
        if !ok {
            let _ = self.audit.lock().unwrap().log(
                "ephemeral_allow",
                Some(device_id.to_string()),
                "allow_fail",
                Some(real_uid),
            );
            return false;
        }
        // Fail closed: a grant that cannot be audited is rolled back.
        let logged = self.audit.lock().unwrap().log(
            "ephemeral_allow",
            Some(device_id.to_string()),
            if ttl == 0 {
                "allow_ok_indefinite"
            } else {
                "allow_ok"
            },
            Some(real_uid),
        );
        if logged.is_err() {
            let _ = self.backend.revoke(&target).await;
            return false;
        }
        self.note_grant(device_id, ttl);
        let expiry = if ttl == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(ttl as u64))
        };
        self.inner.lock().unwrap().ephemeral.insert(
            device_id.to_string(),
            EphemeralGrant {
                expiry,
                owner_uid: real_uid,
            },
        );
        self.persist_ephemeral();
        self.notify_grant();
        true
    }

    async fn apply_persistent_allow(
        &self,
        baseline_bytes: Vec<u8>,
        signer_id: &str,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> bool {
        let real_uid = sender_uid(conn, &header).await;
        // Polkit authorization
        if !check_manage_authorization(conn, &header)
            .await
            .unwrap_or(false)
        {
            let _ =
                self.audit
                    .lock()
                    .unwrap()
                    .log("policy_denied", None, "polkit_denied", real_uid);
            return false;
        }
        // The baseline travels as bytes so the caller's filesystem (hidden
        // from the daemon by ProtectHome/PrivateTmp) is never involved.
        const MAX_BASELINE_BYTES: usize = 1024 * 1024;
        if baseline_bytes.is_empty() || baseline_bytes.len() > MAX_BASELINE_BYTES {
            let _ = self.audit.lock().unwrap().log(
                "security",
                None,
                "baseline_file_rejected",
                real_uid,
            );
            return false;
        }
        // Resolve signer to exactly one trusted key.
        let stem = signer_id.strip_suffix(".pub").unwrap_or(signer_id);
        if !is_valid_key_name(stem) {
            let _ = self.audit.lock().unwrap().log(
                "security",
                None,
                "baseline_signer_id_invalid",
                real_uid,
            );
            return false;
        }
        let baseline: Baseline = match serde_json::from_slice(&baseline_bytes) {
            Ok(b) => b,
            Err(e) => {
                let _ = self.audit.lock().unwrap().log(
                    "security",
                    None,
                    &format!("baseline_parse_failed: {}", e),
                    real_uid,
                );
                return false;
            }
        };
        if let Err(e) = baseline.validate() {
            let _ = self.audit.lock().unwrap().log(
                "security",
                None,
                &format!("baseline_validation_failed: {}", e),
                real_uid,
            );
            return false;
        }
        let hash = match baseline.baseline_hash() {
            Ok(h) => h,
            Err(e) => {
                let _ = self.audit.lock().unwrap().log(
                    "security",
                    None,
                    &format!("baseline_hash_failed: {}", e),
                    real_uid,
                );
                return false;
            }
        };
        // Revocation (deny) list: a revoked baseline hash can never be
        // replayed, even while its signature and key still verify.
        if self.is_baseline_revoked(&hash) {
            let _ = self.audit.lock().unwrap().log(
                "security",
                None,
                &format!("baseline_revoked: signer={} hash={}", stem, hash),
                real_uid,
            );
            return false;
        }
        // Verify against the caller-selected key only (not "any key").
        let key_path = self.trusted_pubkeys_dir.join(format!("{}.pub", stem));
        let verified = (|| -> Result<bool, String> {
            let bytes = fs::read(&key_path).map_err(|e| e.to_string())?;
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "invalid pubkey length".to_string())?;
            let vk = VerifyingKey::from_bytes(&arr).map_err(|e| e.to_string())?;
            baseline.verify_signature(&vk)
        })()
        .unwrap_or(false);
        if !verified {
            let _ = self.audit.lock().unwrap().log(
                "security",
                None,
                &format!("baseline_signature_unverified: signer={}", stem),
                real_uid,
            );
            return false;
        }
        // Store the baseline with a unique timestamped name
        // (nanoseconds + pid avoids same-second collisions overwriting).
        let filename = format!(
            "baseline_{}_{}.json",
            chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ"),
            std::process::id()
        );
        let dest = self.baselines_dir.join(filename);
        if let Some(dir) = dest.parent() {
            if let Err(e) = fs::create_dir_all(dir) {
                let _ = self.audit.lock().unwrap().log(
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
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&dest)
        {
            Ok(f) => f,
            Err(e) => {
                let _ = self.audit.lock().unwrap().log(
                    "security",
                    None,
                    &format!("baseline_file_create_failed: {}", e),
                    real_uid,
                );
                return false;
            }
        };
        let ok = file.write_all(&baseline_bytes).is_ok() && file.sync_all().is_ok();
        if !ok {
            let _ = fs::remove_file(&dest);
            let _ = self.audit.lock().unwrap().log(
                "persistent_allow",
                None,
                "baseline_apply_failed",
                real_uid,
            );
            return false;
        }
        fsync_dir(self.baselines_dir.as_path());
        // Audit the stored phase before touching policy; a failure here is
        // fail-closed (no policy change happens without an audit trail).
        if self
            .audit
            .lock()
            .unwrap()
            .log(
                "persistent_allow",
                None,
                &format!("baseline_stored signer={} hash={}", stem, hash),
                real_uid,
            )
            .is_err()
        {
            let _ = fs::remove_file(&dest);
            return false;
        }
        // Generate usbguard rules from baseline and apply atomically, then reload.
        let rules = generate_rules_from_baseline(&baseline);
        if let Err(e) = UsbguardBackend::apply_rules_atomically(&rules).await {
            tracing::error!(error=?e, "failed to apply usbguard rules atomically");
            let _ = self.audit.lock().unwrap().log(
                "persistent_allow",
                None,
                &format!("baseline_rules_apply_failed: {}", e),
                real_uid,
            );
            return false;
        }
        {
            let mut inner = self.inner.lock().unwrap();
            inner.baselines.extend(baseline.devices.clone());
        }
        // Success is logged only after the rules are actually active.
        let _ = self.audit.lock().unwrap().log(
            "persistent_allow",
            None,
            &format!("rules_applied signer={} hash={}", stem, hash),
            real_uid,
        );
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
            let _ = self.audit.lock().unwrap().log(
                "revoke_reject",
                Some(device_id.to_string()),
                "invalid_input",
                real_uid,
            );
            return false;
        }
        let uid = real_uid.unwrap_or(u32::MAX);
        if !self.rate_ok(uid) {
            let _ = self.audit.lock().unwrap().log(
                "revoke_reject",
                Some(device_id.to_string()),
                "rate_limited",
                real_uid,
            );
            return false;
        }
        // Owner-scoped: only the owner of an ephemeral grant (or an
        // admin-authorized caller) may revoke it.
        let owner = self
            .inner
            .lock()
            .unwrap()
            .ephemeral
            .get(device_id)
            .map(|g| g.owner_uid);
        let authorized = match (owner, real_uid) {
            (Some(o), Some(u)) if o == u => true,
            _ => check_manage_authorization(conn, &header)
                .await
                .unwrap_or(false),
        };
        if !authorized {
            let _ = self.audit.lock().unwrap().log(
                "revoke_reject",
                Some(device_id.to_string()),
                "not_authorized",
                real_uid,
            );
            return false;
        }
        let devices = self.raw_list_devices().await;
        let target = resolve_in(&devices, device_id).unwrap_or_else(|| device_id.to_string());
        let ok = self.backend.revoke(&target).await;
        // A manual revoke supersedes any pending ephemeral approval — but a
        // failed revoke must not make the approval disappear unnoticed.
        if ok {
            let mut inner = self.inner.lock().unwrap();
            inner.ephemeral.remove(device_id);
            if target != device_id {
                inner.ephemeral.remove(&target);
            }
            drop(inner);
            self.persist_ephemeral();
        }
        let _ = self.audit.lock().unwrap().log(
            "revoke",
            Some(device_id.to_string()),
            if ok { "revoke_ok" } else { "revoke_fail" },
            real_uid,
        );
        ok
    }

    async fn get_device_info(
        &self,
        device_id: &str,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<DeviceInfo> {
        let uid = sender_uid(conn, &header).await.unwrap_or(u32::MAX);
        if !self.rate_ok(uid) {
            return Err(zbus::fdo::Error::Failed("rate limited".into()));
        }
        let devices = self.list_annotated().await;
        let found = devices
            .iter()
            .find(|d| d.id == device_id)
            .cloned()
            .or_else(|| {
                resolve_in(&devices, device_id)
                    .and_then(|t| devices.iter().find(|d| d.id == t).cloned())
            });
        found.ok_or_else(|| zbus::fdo::Error::Failed("device not found".into()))
    }

    async fn get_policy_status_string(&self) -> String {
        // Convenience method for quick manual testing
        let status = self.get_policy_status().await;
        format!("deny_unknown={}", status.deny_unknown)
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
            let _ = self.audit.lock().unwrap().log(
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
            let _ = self.audit.lock().unwrap().log(
                "security",
                None,
                "add_pubkey_invalid_input",
                real_uid,
            );
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
            let _ = self.audit.lock().unwrap().log(
                "security",
                None,
                "add_pubkey_invalid_key",
                real_uid,
            );
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
            fsync_dir(dir);
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
        if stored {
            if let Some(dir) = path.parent() {
                fsync_dir(dir);
            }
        }
        let _ = self.audit.lock().unwrap().log(
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
            let _ = self.audit.lock().unwrap().log(
                "policy_denied",
                None,
                "polkit_denied_remove_pubkey",
                real_uid,
            );
            return false;
        }
        let stem = name.strip_suffix(".pub").unwrap_or(name);
        if !is_valid_key_name(stem) {
            let _ = self.audit.lock().unwrap().log(
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
        if ok {
            if let Some(dir) = path.parent() {
                fsync_dir(dir);
            }
        }
        let _ = self.audit.lock().unwrap().log(
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

    fn device_entry(
        vendor_id: &str,
        product_id: &str,
        serial: Option<&str>,
        hash: &str,
        interfaces: Vec<&str>,
    ) -> DeviceEntry {
        DeviceEntry {
            vendor_id: vendor_id.into(),
            product_id: product_id.into(),
            serial: serial.map(String::from),
            bus_path: None,
            descriptors_hash: hash.into(),
            device_type: "hid".into(),
            interfaces: interfaces.into_iter().map(String::from).collect(),
            comment: None,
        }
    }

    #[test]
    fn test_generate_rules_safeguard() {
        let b = Baseline {
            version: 1,
            created_by: "test".into(),
            created_at: chrono::Utc::now(),
            expires_at: None,
            devices: vec![device_entry(
                "0x1234",
                "0x5678",
                Some("AB\nC"), // malicious newline
                "",
                vec![],
            )],
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

    #[test]
    fn test_generate_rules_binds_hash_and_interfaces() {
        let b = Baseline {
            version: 1,
            created_by: "test".into(),
            created_at: chrono::Utc::now(),
            expires_at: None,
            devices: vec![device_entry(
                "0x1234",
                "0x5678",
                Some("ABC"),
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                vec!["03:01:01", "+hid"],
            )],
            signature: None,
        };
        let rule = generate_rules_from_baseline(&b);
        assert!(rule.contains("id 1234:5678"));
        assert!(rule.contains("serial \"ABC\""));
        assert!(rule.contains("hash \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\""));
        assert!(rule.contains("with-interface 03:01:01"));
        assert!(rule.contains("with-interface +hid"));
    }

    #[test]
    fn device_id_validation_rejects_controls_and_options() {
        assert!(is_valid_device_id("2"));
        assert!(is_valid_device_id("0x046d:0xc534:ABC-123"));
        assert!(is_valid_device_id("/dev/bus/usb/002/003"));
        // USB serials legitimately contain spaces and punctuation.
        assert!(is_valid_device_id("0x0781:0x5581:SD Card #1 @home+x"));
        assert!(!is_valid_device_id(""));
        assert!(!is_valid_device_id("a\nb"));
        assert!(!is_valid_device_id("a\x00b"));
        assert!(!is_valid_device_id("ä"));
        // Leading '-' could be parsed as an option by the backend.
        assert!(!is_valid_device_id("--help"));
        assert!(!is_valid_device_id("-2"));
        assert!(!is_valid_device_id(&"a".repeat(257)));
    }

    #[test]
    fn key_name_validation_blocks_traversal() {
        assert!(is_valid_key_name("mykey"));
        assert!(is_valid_key_name("my-key_1.2"));
        assert!(!is_valid_key_name(""));
        assert!(!is_valid_key_name("../../etc"));
        assert!(!is_valid_key_name("a/b"));
        assert!(!is_valid_key_name(".."));
        assert!(!is_valid_key_name("."));
        assert!(!is_valid_key_name(".hidden"));
        assert!(!is_valid_key_name("a;rm"));
    }

    #[test]
    fn baseline_validation_rejects_bad_ids() {
        let good = Baseline {
            version: 1,
            created_by: "test".into(),
            created_at: chrono::Utc::now(),
            expires_at: None,
            devices: vec![device_entry("0x1234", "5678", Some("ABC"), "", vec![])],
            signature: None,
        };
        assert!(good.validate().is_ok());
        let mut bad = good.clone();
        bad.devices[0].vendor_id = "zz; rm".into();
        assert!(bad.validate().is_err());
        let mut bad_ver = good.clone();
        bad_ver.version = 99;
        assert!(bad_ver.validate().is_err());
        let mut empty = good.clone();
        empty.devices.clear();
        assert!(empty.validate().is_err());
        // VID/PID alone is not enough identity for a permanent entry.
        let mut weak = good.clone();
        weak.devices[0].serial = None;
        assert!(weak.validate().is_err());
    }

    #[test]
    fn resolve_handles_colon_serials_and_ambiguity() {
        let mk = |id: &str, vid: &str, pid: &str, serial: &str| DeviceInfo {
            id: id.into(),
            vendor_id: vid.into(),
            product_id: pid.into(),
            serial: serial.into(),
            fingerprint: String::new(),
            device_type: String::new(),
            allowed: false,
            persistent: false,
            usbguard_hash: String::new(),
            interfaces: vec![],
        };
        // Serials may contain ':' — splitn(3) keeps them intact.
        let devices = vec![
            mk("1", "0x1234", "0x5678", "SN:with:colons"),
            mk("2", "0xabcd", "0xef01", ""),
        ];
        assert_eq!(
            resolve_in(&devices, "0x1234:0x5678:SN:with:colons"),
            Some("1".into())
        );
        assert_eq!(resolve_in(&devices, "1"), Some("1".into()));
        // Ambiguous vid:pid must not silently pick one of two devices.
        let twin = mk("3", "0xabcd", "0xef01", "");
        let devices2 = vec![devices[1].clone(), twin];
        assert_eq!(resolve_in(&devices2, "0xabcd:0xef01"), None);
        assert_eq!(resolve_in(&devices2, "0xabcd:0xef01:"), None);
    }

    #[test]
    fn entry_matches_device_identity() {
        let entry = device_entry("0x1234", "0x5678", Some("ABC"), "", vec![]);
        let d = DeviceInfo {
            id: "1".into(),
            vendor_id: "0x1234".into(),
            product_id: "0x5678".into(),
            serial: "ABC".into(),
            fingerprint: String::new(),
            device_type: String::new(),
            allowed: true,
            persistent: false,
            usbguard_hash: String::new(),
            interfaces: vec![],
        };
        assert!(entry_matches_device(&entry, &d));
        let mut other = d.clone();
        other.serial = "XYZ".into();
        assert!(!entry_matches_device(&entry, &other));
    }

    use proptest::prelude::*;

    #[test]
    fn rule_generation_safety_static() {
        let b = Baseline {
            version: 1,
            created_by: "prop".into(),
            created_at: chrono::Utc::now(),
            expires_at: None,
            devices: vec![device_entry("1234", "5678", Some("A\"B\\C"), "", vec![])],
            signature: None,
        };
        let rules = generate_rules_from_baseline(&b);
        let lines: Vec<&str> = rules.lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("allow id "));
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
                expires_at: None,
                devices: vec![DeviceEntry {
                    vendor_id: vid,
                    product_id: pid,
                    serial,
                    bus_path: None,
                    descriptors_hash: "none".into(),
                    device_type: "hid".into(),
                    interfaces: vec![],
                    comment: None,
                }],
                signature: None,
            };
            let rules = generate_rules_from_baseline(&b);
            let lines: Vec<&str> = rules.lines().collect();

            // Safety assertion: The rules string must NOT contain more lines than devices (1).
            // This ensures no newline injection was successfully performed to create extra rules.
            prop_assert_eq!(lines.len(), 1, "Should produce exactly 1 rule line, found {}", lines.len());

            // Further assertion: The rule should verify basic syntax
            let rule = lines[0];
            prop_assert!(rule.starts_with("allow id "));

            // Check for no control characters (except maybe the ones we sanitized to '?' which is safe)
            prop_assert!(!rule.contains('\r'));
            prop_assert!(!rule.contains('\n'));
        }
    }
}
