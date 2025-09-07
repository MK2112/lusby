use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntryPayload {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub device_fingerprint: Option<String>,
    pub action: String,
    pub requester_uid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub payload: AuditEntryPayload,
    pub prev_hash: Option<String>,
    pub entry_hash: String,
}

impl AuditEntry {
    pub fn compute_hash(prev_hash: Option<&str>, payload: &AuditEntryPayload) -> String {
        let mut hasher = Sha256::new();
        if let Some(p) = prev_hash { hasher.update(p.as_bytes()); }
        // Serialize payload deterministically (order stable for struct)
        let bytes = serde_json::to_vec(payload).expect("serialize payload");
        hasher.update(&bytes);
        let digest = hasher.finalize();
        format!("sha256:{}", hex::encode(digest))
    }

    pub fn new(prev_hash: Option<String>, payload: AuditEntryPayload) -> Self {
        let entry_hash = Self::compute_hash(prev_hash.as_deref(), &payload);
        Self { payload, prev_hash, entry_hash }
    }
}

pub fn verify_chain(entries: &[AuditEntry]) -> bool {
    let mut last: Option<&str> = None;
    for e in entries {
        let expected = AuditEntry::compute_hash(last, &e.payload);
        if expected != e.entry_hash { return false; }
        match (&last, &e.prev_hash) {
            (None, None) => {}
            (Some(l), Some(p)) if *l == p => {}
            (None, Some(_)) => return false,
            (Some(_), None) => return false,
            _ => return false,
        }
        last = Some(&e.entry_hash);
    }
    true
}
