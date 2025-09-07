use anyhow::Result;
use zbus::Connection;
use futures_util::StreamExt;
use guardianusb_common::types::DeviceInfo;
use std::sync::{Arc, Mutex};
#[cfg(feature = "tray-ui")]
mod ui;
use notify_rust::Notification;
use libc::geteuid;

#[tokio::main]
async fn main() -> Result<()> {
    println!("guardianusb-tray starting");
    let conn = Connection::system().await?;
    let path_str = "/org/guardianusb/Daemon";
    let iface = "org.guardianusb.Daemon";
    let last_seen: Arc<Mutex<Option<DeviceInfo>>> = Arc::new(Mutex::new(None));

    #[cfg(feature = "tray-ui")]
    {
        ui::start_indicator(last_seen.clone())?;
    }

    let mut stream = zbus::MessageStream::from(&conn);
    while let Some(Ok(msg)) = stream.next().await {
        let header = msg.header();
        let path_ok = header.path().map(|p| p.as_str().to_string()) == Some(path_str.to_string());
        let iface_ok = header.interface().map(|i| i.as_str().to_string()) == Some(iface.to_string());
        if msg.message_type() == zbus::MessageType::Signal && path_ok && iface_ok
        {
            if let Some(member) = header.member().map(|m| m.as_str().to_string()) {
                match member.as_str() {
                    "unknown_device_inserted" => {
                        if let Ok((d,)) = msg.body().deserialize::<(DeviceInfo,)>() {
                            println!("Unknown USB device: {} {} serial={} type={}", d.vendor_id, d.product_id, d.serial, d.device_type);
                            *last_seen.lock().unwrap() = Some(d);
                            if let Some(dev) = last_seen.lock().unwrap().as_ref() {
                                let mut notif = Notification::new();
                                notif
                                    .summary("GuardianUSB: Unknown device")
                                    .body(&format!("{} {} serial={} type={}", dev.vendor_id, dev.product_id, dev.serial, dev.device_type))
                                    .icon("security-high")
                                    .action("approve", "Approve for 5 minutes");

                                if let Ok(handle) = notif.show() {
                                    // Spawn a short-lived thread to wait for at most one action
                                    let device_id = dev.id.clone();
                                    std::thread::spawn(move || {
                                        handle.wait_for_action(|action| {
                                            if action == "approve" {
                                                let uid = unsafe { geteuid() } as u32;
                                                let ttl: u32 = 300;
                                                // Use a small runtime for this one-off call
                                                let rt = tokio::runtime::Runtime::new().unwrap();
                                                rt.block_on(async move {
                                                    if let Ok(conn) = zbus::Connection::system().await {
                                                        if let Ok(proxy) = zbus::Proxy::new(&conn, "org.guardianusb.Daemon", "/org/guardianusb/Daemon", "org.guardianusb.Daemon").await {
                                                            let _ = proxy.call("request_ephemeral_allow", &(device_id, ttl, uid)).await as zbus::Result<bool>;
                                                        }
                                                    }
                                                });
                                            }
                                        });
                                    });
                                }
                            }
                        }
                    }
                    "device_removed" => {
                        if let Ok((dev_id,)) = msg.body().deserialize::<(String,)>() {
                            println!("USB device removed: {}", dev_id);
                            let mut guard = last_seen.lock().unwrap();
                            if let Some(d) = guard.as_ref() {
                                if d.id == dev_id { *guard = None; }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
