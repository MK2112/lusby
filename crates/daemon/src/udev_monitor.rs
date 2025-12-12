use std::os::unix::net::UnixDatagram;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::unix::AsyncFd;
use zbus::Connection;

use lusby_common::fingerprint::{compute_fingerprint, FingerprintInput};
use lusby_common::types::DeviceInfo;

const DBUS_PATH: &str = "/org/lusby/Daemon";

/// Minimal serialisable struct sent from the blocking thread to the async task.
#[derive(Serialize, Deserialize, Debug)]
struct RawUdevEvent {
    action: String,
    devnode: String,
    vendor_id: String,
    product_id: String,
    serial: String,
    device_type: String,
    vendor: Option<String>,
    product: Option<String>,
}

pub async fn run_udev_listener(connection: Connection) -> Result<()> {
    // Create a Unix datagram pair for thread -> async notifications
    let (sock1, sock2) = UnixDatagram::pair().context("creating unix datagram pair")?;
    // Make the tokio async fd from one end (sock1)
    let mut async_fd = AsyncFd::new(sock1).context("creating AsyncFd")?;

    // Spawn an OS thread that creates the udev monitor (so udev's non-Send types never cross thread boundary).
    thread::spawn(move || {
        // Create monitor inside this thread. This keeps the non-Send udev types on this thread only.
        let socket = match udev::MonitorBuilder::new()
            .and_then(|b| b.match_subsystem("usb"))
            .and_then(|b| b.listen())
        {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to set up udev monitor: {}", e);
                return;
            }
        };

        // Iterate blocking for udev events, serialise some fields and send to the async side.
        for event in socket.iter() {
            // Build a RawUdevEvent with the fields we care about
            let action = event
                .action()
                .and_then(|a| a.to_str())
                .unwrap_or("unknown")
                .to_string();
            let devnode = event
                .devnode()
                .and_then(|p| p.to_str())
                .unwrap_or("")
                .to_string();

            let vendor_id = event
                .property_value("ID_VENDOR_ID")
                .and_then(|s| s.to_str())
                .map(|s| format!("0x{}", s))
                .unwrap_or_default();
            let product_id = event
                .property_value("ID_MODEL_ID")
                .and_then(|s| s.to_str())
                .map(|s| format!("0x{}", s))
                .unwrap_or_default();
            let serial = event
                .property_value("ID_SERIAL_SHORT")
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            let device_type = event
                .property_value("ID_USB_DRIVER")
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();

            let vendor = event
                .property_value("ID_VENDOR")
                .and_then(|s| s.to_str())
                .map(|s| s.to_string());
            let product = event
                .property_value("ID_MODEL")
                .and_then(|s| s.to_str())
                .map(|s| s.to_string());

            let raw = RawUdevEvent {
                action,
                devnode,
                vendor_id,
                product_id,
                serial,
                device_type,
                vendor,
                product,
            };

            match serde_json::to_vec(&raw) {
                Ok(j) => {
                    // If send fails, print error and continue (peer may be closed on shutdown)
                    if let Err(e) = sock2.send(&j) {
                        eprintln!("Failed to send udev event to main thread: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to serialise udev event: {}", e);
                }
            }

            // Tiny sleep to avoid tight loop storms
            thread::sleep(Duration::from_millis(10));
        }
    });

    // Async loop: wait for datagrams, parse them and process the event.
    let mut buf = vec![0u8; 16 * 1024]; // large enough buffer for the JSON payload
    loop {
        // Clone the underlying UnixDatagram (duplicates the fd) BEFORE taking the mutable read guard.
        // The temporary immutable borrow taken by `get_ref()` ends immediately after try_clone() returns,
        // so there is no overlap with the later mutable borrow `readable_mut()`.
        let recv_sock = async_fd
            .get_ref()
            .try_clone()
            .context("cloning unix datagram for recv")?;

        // Now wait until the datagram socket is readable
        let mut guard = async_fd.readable_mut().await?;

        let result = guard.try_io(|_| {
            match recv_sock.recv(&mut buf) {
                Ok(len) => {
                    if len == 0 {
                        // peer closed
                        return Ok(());
                    }

                    let slice = &buf[..len];
                    match serde_json::from_slice::<RawUdevEvent>(slice) {
                        Ok(raw) => {
                            let fp = compute_fingerprint(&FingerprintInput {
                                vendor_id: &raw.vendor_id,
                                product_id: &raw.product_id,
                                serial: if raw.serial.is_empty() {
                                    None
                                } else {
                                    Some(&raw.serial)
                                },
                                manufacturer: raw.vendor.as_deref(),
                                product: raw.product.as_deref(),
                                raw_descriptors: None,
                            });

                            let info = DeviceInfo {
                                id: raw.devnode.clone(),
                                vendor_id: raw.vendor_id.clone(),
                                product_id: raw.product_id.clone(),
                                serial: raw.serial.clone(),
                                fingerprint: fp,
                                device_type: raw.device_type.clone(),
                                allowed: false,
                                persistent: false,
                            };

                            let conn = connection.clone();
                            let info_clone = info.clone();
                            let action = raw.action.clone();
                            tokio::spawn(async move {
                                if action == "add" || action == "bind" {
                                    if let Err(e) = conn
                                        .emit_signal(
                                            Option::<&str>::None,
                                            DBUS_PATH,
                                            "org.lusby.Daemon",
                                            "unknown_device_inserted",
                                            &(&info_clone,),
                                        )
                                        .await
                                    {
                                        eprintln!(
                                            "Failed to emit unknown_device_inserted signal: {}",
                                            e
                                        );
                                    }
                                } else if action == "remove" || action == "unbind" {
                                    if let Err(e) = conn
                                        .emit_signal(
                                            Option::<&str>::None,
                                            DBUS_PATH,
                                            "org.lusby.Daemon",
                                            "device_removed",
                                            &(&info_clone.id,),
                                        )
                                        .await
                                    {
                                        eprintln!("Failed to emit DeviceRemoved signal: {}", e);
                                    }
                                }
                            });
                        }
                        Err(e) => eprintln!("Failed to parse raw udev event JSON: {}", e),
                    }
                }
                Err(e) => eprintln!("Error receiving on unix datagram: {}", e),
            }
            Ok(())
        });

        if let Err(e) = result {
            eprintln!("Error processing udev notification: {:?}", e);
        }
        guard.clear_ready();
    }
}
