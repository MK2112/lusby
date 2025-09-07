use serde::{Deserialize, Serialize};
use zvariant::Type;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Type)]
pub struct PolicyStatus {
    pub deny_unknown: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Type)]
pub struct DeviceInfo {
    pub id: String,
    pub vendor_id: String,
    pub product_id: String,
    pub serial: String,
    pub fingerprint: String,
    pub device_type: String,
    pub allowed: bool,
    pub persistent: bool,
}
