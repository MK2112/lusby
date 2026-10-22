use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{canonical_json_vec, sign_canonical, verify_canonical};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceEntry {
    pub vendor_id: String,
    pub product_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bus_path: Option<String>,
    /// usbguard device hash (the `hash "..."` attribute from `list-devices`).
    /// When present, generated rules match on it instead of VID/PID alone.
    pub descriptors_hash: String,
    pub device_type: String, // "hid" | "storage" | "net" | etc.
    /// USB interface specs (e.g. "03:01:01" or "+hid") enforced via
    /// `with-interface` so a composite device cannot expose extra interfaces.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Baseline {
    pub version: u32,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    /// Optional hard expiry: the baseline may not be applied after this time
    /// (bounds the replay window of a signed baseline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub devices: Vec<DeviceEntry>,
    #[serde(default)]
    pub signature: Option<String>, // base64(ed25519)
}

/// A valid usbguard device hash: hex string of plausible digest length.
pub fn is_usbguard_hash(s: &str) -> bool {
    (32..=128).contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// A valid usbguard `with-interface` spec: "cc:ss:pp" hex/wildcard triplet
/// or a class name such as "+hid".
pub fn is_valid_interface_spec(s: &str) -> bool {
    if let Some(name) = s.strip_prefix('+') {
        return !name.is_empty()
            && name.len() <= 32
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
    }
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty() && p.len() <= 2 && p.chars().all(|c| c.is_ascii_hexdigit() || c == '*')
        })
}

pub fn is_hex4(s: &str) -> bool {
    let t = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    t.len() == 4 && t.chars().all(|c| c.is_ascii_hexdigit())
}

impl Baseline {
    pub fn without_signature(&self) -> Self {
        let mut b = self.clone();
        b.signature = None;
        b
    }

    pub fn sign_attach(&mut self, signing_key: &SigningKey) -> Result<(), String> {
        // Sign canonical form without signature field.
        let unsigned = self.without_signature();
        let sig_b64 = sign_canonical(signing_key, &unsigned).map_err(|e| e.to_string())?;
        self.signature = Some(sig_b64);
        Ok(())
    }

    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<bool, String> {
        match &self.signature {
            Some(sig) => {
                let unsigned = self.without_signature();
                verify_canonical(verifying_key, &unsigned, sig).map_err(|e| e.to_string())
            }
            None => Ok(false),
        }
    }

    /// Stable identity of the signed content (canonical JSON of the baseline
    /// without the signature field). Used for audit attribution and the
    /// revocation (deny) list.
    pub fn baseline_hash(&self) -> Result<String, String> {
        let unsigned = self.without_signature();
        let bytes = canonical_json_vec(&unsigned).map_err(|e| e.to_string())?;
        Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }

    /// Fail-closed structural and policy validation (independent of signatures).
    pub fn validate(&self) -> Result<(), String> {
        self.validate_at(Utc::now())
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!("unsupported baseline version {}", self.version));
        }
        if self.devices.is_empty() {
            return Err("baseline contains no devices".into());
        }
        if self.devices.len() > 1024 {
            return Err("baseline device limit exceeded".into());
        }
        if self.created_by.is_empty() || self.created_by.len() > 256 {
            return Err("invalid created_by".into());
        }
        // Clock-skew tolerance of five minutes for "created in the future".
        if self.created_at > now + chrono::Duration::minutes(5) {
            return Err("baseline created_at is in the future".into());
        }
        if let Some(expires) = self.expires_at {
            if expires <= self.created_at {
                return Err("baseline expires_at must be after created_at".into());
            }
            if expires <= now {
                return Err("baseline has expired".into());
            }
        }
        for (i, d) in self.devices.iter().enumerate() {
            if !is_hex4(&d.vendor_id) {
                return Err(format!("device {} has invalid vendor_id", i));
            }
            if !is_hex4(&d.product_id) {
                return Err(format!("device {} has invalid product_id", i));
            }
            if let Some(s) = &d.serial {
                if s.is_empty() || s.len() > 128 || s.chars().any(|c| c.is_control()) {
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
            if d.interfaces.len() > 16 {
                return Err(format!("device {} has too many interfaces", i));
            }
            for spec in &d.interfaces {
                if !is_valid_interface_spec(spec) {
                    return Err(format!("device {} has invalid interface spec", i));
                }
            }
            // Identity binding: VID/PID alone is spoofable, so a permanent
            // entry must carry at least one additional identity signal
            // (serial, usbguard device hash, or interface restrictions).
            let has_hash = is_usbguard_hash(&d.descriptors_hash);
            if d.serial.is_none() && d.interfaces.is_empty() && !has_hash {
                return Err(format!(
                    "device {} has no identity beyond vid/pid (need serial, device hash, or interfaces)",
                    i
                ));
            }
        }
        Ok(())
    }
}
