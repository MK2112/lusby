use guardianusb_common::backend::UsbBackend;
use guardianusb_common::types::DeviceInfo;
use async_trait::async_trait;

#[derive(Clone, Default)]
pub struct MockBackend {
    devices: std::sync::Arc<std::sync::Mutex<Vec<DeviceInfo>>>,
}

impl MockBackend {
    pub fn new_with_sample() -> Self {
        let sample = DeviceInfo {
            id: "dev1".into(),
            vendor_id: "0x046d".into(),
            product_id: "0xc534".into(),
            serial: "ABC".into(),
            fingerprint: "sha256:deadbeef".into(),
            device_type: "hid".into(),
            allowed: false,
            persistent: false,
        };
        Self { devices: std::sync::Arc::new(std::sync::Mutex::new(vec![sample])) }
    }
}

#[async_trait]
impl UsbBackend for MockBackend {
    async fn list_devices(&self) -> Vec<DeviceInfo> {
        self.devices.lock().unwrap().clone()
    }

    async fn get_device(&self, device_id: &str) -> Option<DeviceInfo> {
        self.devices.lock().unwrap().iter().find(|d| d.id == device_id).cloned()
    }

    async fn allow_ephemeral(&self, _device_id: &str, _ttl_secs: u32) -> bool {
        true
    }

    async fn revoke(&self, _device_id: &str) -> bool {
        true
    }
}
