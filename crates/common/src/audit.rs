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
        if let Some(p) = prev_hash {
            hasher.update(p.as_bytes());
        }
        // Serialize payload deterministically (order stable for struct)
        let bytes = serde_json::to_vec(payload).expect("serialize payload");
        hasher.update(&bytes);
        let digest = hasher.finalize();
        format!("sha256:{}", hex::encode(digest))
    }

    pub fn new(prev_hash: Option<String>, payload: AuditEntryPayload) -> Self {
        let entry_hash = Self::compute_hash(prev_hash.as_deref(), &payload);
        Self {
            payload,
            prev_hash,
            entry_hash,
        }
    }
}

/// Streaming chain verification (constant memory): returns the number of
/// verified entries; Err on a broken chain, unparsable content, or an empty
/// log (an empty/truncated log must never verify as valid).
pub fn verify_stream<R: std::io::BufRead>(reader: R) -> Result<usize, String> {
    let mut last: Option<String> = None;
    let mut count = 0usize;
    for line in reader.lines() {
        let line = line.map_err(|e| format!("read error: {}", e))?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry =
            serde_json::from_str(&line).map_err(|e| format!("parse error: {}", e))?;
        let expected = AuditEntry::compute_hash(last.as_deref(), &entry.payload);
        let link_ok = match (&last, &entry.prev_hash) {
            (None, None) => true,
            (Some(l), Some(p)) => l == p,
            _ => false,
        };
        if !link_ok || expected != entry.entry_hash {
            return Err("chain verification failed".into());
        }
        last = Some(entry.entry_hash);
        count += 1;
    }
    if count == 0 {
        return Err("empty log".into());
    }
    Ok(count)
}

pub fn verify_chain(entries: &[AuditEntry]) -> bool {
    // An empty (or fully truncated) log must not be reported as valid.
    if entries.is_empty() {
        return false;
    }
    let mut last: Option<&str> = None;
    for e in entries {
        let expected = AuditEntry::compute_hash(last, &e.payload);
        if expected != e.entry_hash {
            return false;
        }
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
