use async_trait::async_trait;
use crate::types::DeviceInfo;

#[async_trait]
pub trait UsbBackend: Send + Sync {
    async fn list_devices(&self) -> Vec<DeviceInfo>;
    async fn get_device(&self, device_id: &str) -> Option<DeviceInfo>;
    async fn allow_ephemeral(&self, device_id: &str, ttl_secs: u32) -> bool;
    async fn revoke(&self, device_id: &str) -> bool;
}
