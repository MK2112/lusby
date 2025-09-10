use crate::dbus::DaemonProxy;
use anyhow::Result;
use guardianusb_common::fingerprint::{compute_fingerprint, FingerprintInput};
use guardianusb_common::types::DeviceInfo;
use tokio::io::unix::AsyncFd;
use zbus::Connection;

const DBUS_PATH: &str = "/org/guardianusb/Daemon";

pub async fn run_udev_listener(connection: Connection) -> Result<()> {
    // Build a udev monitor for USB subsystem
    let mut builder = udev::MonitorBuilder::new()?;
    builder.match_subsystem("usb")?;
    let socket = builder.listen()?; // blocking fd
    let async_fd = AsyncFd::new(socket)?;

    loop {
        let mut guard = async_fd.readable().await?;
        match guard.try_io(|inner| {
            let sock = inner.get_ref();
            // Receive one event
            match sock.next() {
                Ok(event) => {
                    let action = event.action().unwrap_or("");
                    let devnode = event
                        .devnode()
                        .and_then(|p| p.to_str())
                        .unwrap_or("")
                        .to_string();
                    let vendor = event
                        .property_value("ID_VENDOR_ID")
                        .and_then(|s| s.to_str())
                        .map(|s| format!("0x{}", s))
                        .unwrap_or_default();
                    let product = event
                        .property_value("ID_MODEL_ID")
                        .and_then(|s| s.to_str())
                        .map(|s| format!("0x{}", s))
                        .unwrap_or_default();
                    let serial = event
                        .property_value("ID_SERIAL_SHORT")
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_string();
                    let dtype = event
                        .property_value("ID_USB_DRIVER")
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_string();

                    let fp = compute_fingerprint(&FingerprintInput {
                        vendor_id: &vendor,
                        product_id: &product,
                        serial: if serial.is_empty() {
                            None
                        } else {
                            Some(&serial)
                        },
                        manufacturer: event.property_value("ID_VENDOR").and_then(|s| s.to_str()),
                        product: event.property_value("ID_MODEL").and_then(|s| s.to_str()),
                        raw_descriptors: None,
                    });

                    let info = DeviceInfo {
                        id: devnode.clone(),
                        vendor_id: vendor,
                        product_id: product,
                        serial,
                        fingerprint: fp,
                        device_type: dtype,
                        allowed: false,
                        persistent: false,
                    };

                    // Emit D-Bus signal based on action
                    let conn = connection.clone();
                    tokio::spawn(async move {
                        if let Ok(proxy) = crate::dbus::DaemonProxy::new(&conn).await {
                            if action == "add" {
                                let _ = proxy.unknown_device_inserted(&info).await;
                            } else if action == "remove" {
                                let _ = proxy.device_removed(&info.id).await;
                            }
                        }
                    });
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }) {
            Ok(Ok(())) => {}
            Ok(Err(_e)) => {}
            Err(_would_block) => continue,
        }
        guard.clear_ready();
    }
}
