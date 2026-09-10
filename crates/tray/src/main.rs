use anyhow::Result;
use futures_util::StreamExt;
use std::sync::{Arc, Mutex};
use tracing::info;
use zbus::Connection;
#[cfg(feature = "tray-ui")]
mod ui;
use libc::geteuid;
use lusby_common::fingerprint::short_fingerprint;
use lusby_common::types::DeviceInfo;
use notify_rust::Notification;
fn load_config_ttl() -> u32 {
    lusby_tray::load_config_ttl()
}

fn setup_logging() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = fmt::layer()
        .with_target(true)
        .with_timer(fmt::time::UtcTime::rfc_3339());
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
}

fn main() -> Result<()> {
    setup_logging();
    info!("lusby-tray starting");

    #[cfg(feature = "tray-ui")]
    {
        ui::start_with_gtk()
    }

    #[cfg(not(feature = "tray-ui"))]
    {
        run_headless()
    }
}

pub async fn run_dbus_listener(
    last_seen: Arc<Mutex<Option<DeviceInfo>>>,
    default_ttl: u32,
) -> Result<()> {
    let conn = Connection::system().await?;
    let path_str = "/org/lusby/Daemon";
    let iface = "org.lusby.Daemon";

    // Subscribe to signals from the daemon using D-Bus AddMatch
    let match_rule = format!("type='signal',path='{}',interface='{}'", path_str, iface);
    let bus_proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await?;
    bus_proxy
        .call::<_, _, ()>("AddMatch", &(match_rule,))
        .await?;

    let mut stream = zbus::MessageStream::from(&conn);
    while let Some(Ok(msg)) = stream.next().await {
        let header = msg.header();
        let path_ok = header.path().as_ref().map(|p| p.as_str()) == Some(path_str);
        let iface_ok = header.interface().as_ref().map(|i| i.as_str()) == Some(iface);
        if msg.message_type() == zbus::MessageType::Signal && path_ok && iface_ok {
            if let Some(member) = header.member().as_ref().map(|m| m.as_str()) {
                match member {
                    "UnknownDeviceInserted" => {
                        let body = msg.body();
                        if let Ok((d,)) = body.deserialize::<(DeviceInfo,)>() {
                            println!(
                                "Unknown USB device: {} {} serial={} type={}",
                                d.vendor_id, d.product_id, d.serial, d.device_type
                            );
                            *last_seen.lock().unwrap() = Some(d.clone());
                            // Clone under a single lock; never hold the
                            // mutex while building/sending notifications.
                            let dev = d.clone();
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
                                    "approve_temp",
                                    &format!("Approve for {} minutes", (default_ttl / 60).max(1)),
                                )
                                .action("revoke", "Revoke device");

                            if let Ok(handle) = notif.show() {
                                // Spawn a short-lived thread to wait for at most one action.
                                // Note: indefinite approvals are intentionally not
                                // offered here; TTL=0 now requires polkit
                                // authorization server-side. Permanent access
                                // goes through signed baselines instead.
                                let device_id = dev.id.clone();
                                let ttl = default_ttl;
                                std::thread::spawn(move || {
                                    handle.wait_for_action(|action| {
                                            // One runtime per notification thread,
                                            // reused for whichever action fires.
                                            let rt = match tokio::runtime::Runtime::new() {
                                                Ok(rt) => rt,
                                                Err(e) => {
                                                    eprintln!("Failed to create runtime: {}", e);
                                                    return;
                                                }
                                            };
                                            match action {
                                                "approve_temp" => {
                                                    let uid = unsafe { geteuid() } as u32;
                                                    let ttl: u32 = ttl;
                                                    let dev_id = device_id.clone();
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
                                                                let result: zbus::Result<bool> = proxy
                                                                    .call(
                                                                        "RequestEphemeralAllow",
                                                                        &(dev_id, ttl, uid),
                                                                    )
                                                                    .await;
                                                                match result {
                                                                    Ok(_) => println!("Temporary approval granted"),
                                                                    Err(e) => eprintln!("Failed to approve device temporarily: {}", e),
                                                                }
                                                            }
                                                        }
                                                    });
                                                }
                                                "revoke" => {
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
                                                                let result: zbus::Result<bool> = proxy
                                                                    .call("RevokeDevice", &(dev))
                                                                    .await;
                                                                match result {
                                                                    Ok(_) => println!("Device revoked"),
                                                                    Err(e) => eprintln!("Failed to revoke device: {}", e),
                                                                }
                                                            }
                                                        }
                                                    });
                                                }
                                                _ => eprintln!("Unknown action: {}", action),
                                            }
                                        });
                                });
                            }
                        }
                    }
                    "DeviceRemoved" => {
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

#[cfg(not(feature = "tray-ui"))]
fn run_headless() -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let last_seen = Arc::new(Mutex::new(None));
    let default_ttl = load_config_ttl();
    rt.block_on(run_dbus_listener(last_seen, default_ttl))
}
