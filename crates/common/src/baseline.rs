use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::crypto::{sign_canonical, verify_canonical};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceEntry {
    pub vendor_id: String,
    pub product_id: String,
    #[serde(skip_serializing_if = "Option::is_none")] 
    pub serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] 
    pub bus_path: Option<String>,
    pub descriptors_hash: String,
    pub device_type: String, // "hid" | "storage" | "net" | etc.
    #[serde(skip_serializing_if = "Option::is_none")] 
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Baseline {
    pub version: u32,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub devices: Vec<DeviceEntry>,
    #[serde(default)]
    pub signature: Option<String>, // base64(ed25519)
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
}
