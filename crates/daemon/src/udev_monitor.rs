use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::thread;

use anyhow::Result;
use tokio::io::unix::AsyncFd;
use zbus::Connection;

use guardianusb_common::fingerprint::{compute_fingerprint, FingerprintInput};
use guardianusb_common::types::DeviceInfo;

use crate::dbus::DaemonState;

const DBUS_PATH: &str = "/org/guardianusb/Daemon";

pub async fn run_udev_listener(connection: Connection) -> Result<()> {
    // Build a udev monitor for USB subsystem
    let mut monitor = udev::MonitorBuilder::new()?;
    monitor.match_subsystem("usb")?;
    let socket = monitor.listen()?;

    // Create a Unix datagram socket for async I/O
    let (sock1, sock2) = UnixDatagram::pair()?;
    let async_fd = AsyncFd::new(sock1)?;

    // Spawn a thread to forward udev events to our socket
    thread::spawn(move || {
        let mut buffer = [0; 1];
        loop {
            if socket.receive_event().is_ok() {
                // Just notify that we got an event
                let _ = sock2.send(&[1]);
            }
        }
    });

    loop {
        let mut guard = async_fd.readable_mut().await?;
        let _ = guard.try_io(|_| {
            // Clear the notification
            let mut buf = [0; 1];
            let _ = async_fd.get_ref().recv(&mut buf);

            // Process all pending udev events
            match socket.receive_event() {
                Ok(event) => {
                    let action = event.action().unwrap_or("unknown").to_string();
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
                    let info_clone = info.clone();
                    tokio::spawn(async move {
                        match DaemonState::new_daemon(&conn).await {
                            Ok(proxy) => {
                                if action == "add" || action == "bind" {
                                    if let Err(e) = proxy.unknown_device_inserted(&info_clone).await
                                    {
                                        eprintln!("Failed to emit device inserted signal: {}", e);
                                    }
                                } else if action == "remove" || action == "unbind" {
                                    if let Err(e) = proxy.device_removed(&info_clone.id).await {
                                        eprintln!("Failed to emit device removed signal: {}", e);
                                    }
                                }
                            }
                            Err(e) => eprintln!("Failed to create D-Bus proxy: {}", e),
                        }
                    });
                }
                Err(e) => eprintln!("Error receiving udev event: {}", e),
            }
            Ok(())
        })?;
        guard.clear_ready();
    }
}
