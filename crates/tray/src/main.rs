use anyhow::Result;
use futures_util::StreamExt;
use std::sync::{Arc, Mutex};
use zbus::Connection;
#[cfg(feature = "tray-ui")]
mod ui;
use libc::geteuid;
use lusby_common::fingerprint::short_fingerprint;
use lusby_common::types::DeviceInfo;
use notify_rust::Notification;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ConfigPolicy {
    #[serde(default = "default_ttl")]
    default_ttl_secs: u32,
}
impl Default for ConfigPolicy {
    fn default() -> Self {
        Self {
            default_ttl_secs: default_ttl(),
        }
    }
}
#[derive(Debug, Deserialize)]
struct Config {
    #[serde(default)]
    policy: ConfigPolicy,
}
fn default_ttl() -> u32 {
    300
}

fn load_config_ttl() -> u32 {
    let path = "/etc/lusby/config.toml";
    if let Ok(text) = std::fs::read_to_string(path) {
        if let Ok(cfg) = toml::from_str::<Config>(&text) {
            return cfg.policy.default_ttl_secs;
        }
    }
    default_ttl()
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("lusby-tray starting");
    let conn = Connection::system().await?;
    let path_str = "/org/lusby/Daemon";
    let iface = "org.lusby.Daemon";
    let last_seen: Arc<Mutex<Option<DeviceInfo>>> = Arc::new(Mutex::new(None));
    let default_ttl = load_config_ttl();

    #[cfg(feature = "tray-ui")]
    {
        ui::start_indicator(last_seen.clone(), default_ttl)?;
    }

    let mut stream = zbus::MessageStream::from(&conn);
    while let Some(Ok(msg)) = stream.next().await {
        let header = msg.header();
        let path_ok = header.path().as_ref().map(|p| p.as_str()) == Some(path_str);
        let iface_ok = header.interface().as_ref().map(|i| i.as_str()) == Some(iface);
        if msg.message_type() == zbus::MessageType::Signal && path_ok && iface_ok {
            if let Some(member) = header.member().as_ref().map(|m| m.as_str()) {
                match member {
                    "unknown_device_inserted" => {
                        let body = msg.body();
                        if let Ok((d,)) = body.deserialize::<(DeviceInfo,)>() {
                            println!(
                                "Unknown USB device: {} {} serial={} type={}",
                                d.vendor_id, d.product_id, d.serial, d.device_type
                            );
                            *last_seen.lock().unwrap() = Some(d);
                            if let Some(dev) = last_seen.lock().unwrap().as_ref() {
                                let mut notif = Notification::new();
                                let fp_short = if dev.fingerprint.is_empty() {
                                    String::from("")
                                } else {
                                    short_fingerprint(&dev.fingerprint)
                                };
                                notif
                                    .summary("Lusby: Unknown device")
                                    .body(&format!(
                                        "{} {}\nserial={} type={}\nfingerprint={}",
                                        dev.vendor_id,
                                        dev.product_id,
                                        dev.serial,
                                        dev.device_type,
                                        fp_short
                                    ))
                                    .icon("security-high")
                                    .action(
                                        "approve",
                                        &format!(
                                            "Approve for {} minutes",
                                            (default_ttl / 60).max(1)
                                        ),
                                    )
                                    .action("revoke", "Revoke device");

                                if let Ok(handle) = notif.show() {
                                    // Spawn a short-lived thread to wait for at most one action
                                    let device_id = dev.id.clone();
                                    let ttl = default_ttl;
                                    std::thread::spawn(move || {
                                        handle.wait_for_action(|action| {
                                            if action == "approve" {
                                                let uid = unsafe { geteuid() } as u32;
                                                let ttl: u32 = ttl;
                                                // Use a small runtime for this one-off call
                                                let rt = tokio::runtime::Runtime::new().unwrap();
                                                rt.block_on(async move {
                                                    if let Ok(conn) =
                                                        zbus::Connection::system().await
                                                    {
                                                        if let Ok(proxy) = zbus::Proxy::new(
                                                            &conn,
                                                            "org.lusby.Daemon",
                                                            "/org/lusby/Daemon",
                                                            "org.lusby.Daemon",
                                                        )
                                                        .await
                                                        {
                                                            let _ = proxy
                                                                .call(
                                                                    "request_ephemeral_allow",
                                                                    &(device_id, ttl, uid),
                                                                )
                                                                .await
                                                                as zbus::Result<bool>;
                                                        }
                                                    }
                                                });
                                            } else if action == "revoke" {
                                                let rt = tokio::runtime::Runtime::new().unwrap();
                                                let dev = device_id.clone();
                                                rt.block_on(async move {
                                                    if let Ok(conn) =
                                                        zbus::Connection::system().await
                                                    {
                                                        if let Ok(proxy) = zbus::Proxy::new(
                                                            &conn,
                                                            "org.lusby.Daemon",
                                                            "/org/lusby/Daemon",
                                                            "org.lusby.Daemon",
                                                        )
                                                        .await
                                                        {
                                                            let res: zbus::Result<bool> = proxy
                                                                .call("revoke_device", &(dev))
                                                                .await;
                                                            let _ = res;
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
                        let body = msg.body();
                        if let Ok((id,)) = body.deserialize::<(String,)>() {
                            println!("USB device removed: {}", id);
                            let mut guard = last_seen.lock().unwrap();
                            if let Some(d) = guard.as_ref() {
                                if d.id == *id {
                                    *guard = None;
                                }
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
