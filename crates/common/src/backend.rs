use crate::types::DeviceInfo;
use async_trait::async_trait;

#[async_trait]
pub trait UsbBackend: Send + Sync {
    async fn list_devices(&self) -> Vec<DeviceInfo>;
    async fn get_device(&self, device_id: &str) -> Option<DeviceInfo>;
    async fn allow_ephemeral(&self, device_id: &str, ttl_secs: u32) -> bool;
    async fn revoke(&self, device_id: &str) -> bool;
    /// The backend's effective implicit policy target ("block"/"allow"),
    /// or None when it cannot be determined.
    async fn implicit_policy_target(&self) -> Option<String> {
        None
    }
}
