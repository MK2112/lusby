use anyhow::Result;
use futures_util::StreamExt;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};
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

/// One long-lived runtime for all approval/revoke work. Creating a runtime
/// per notification or click leaks threads under hotplug storms.
pub(crate) fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("tokio runtime"))
}

/// Connection shared by UI actions (P-11); established by the listener.
static SHARED_CONN: Mutex<Option<Connection>> = Mutex::new(None);

#[cfg_attr(not(feature = "tray-ui"), allow(dead_code))] // consumed by the tray UI
pub(crate) fn shared_conn() -> Option<Connection> {
    SHARED_CONN.lock().unwrap().clone()
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

/// Field-size caps for device data arriving over D-Bus. The daemon is the
/// only intended sender (verified separately), but a crafted body must not
/// be able to balloon memory or crash the tray.
fn valid_signal_device(d: &DeviceInfo) -> bool {
    !d.id.is_empty()
        && d.id.len() <= 256
        && d.vendor_id.len() <= 16
        && d.product_id.len() <= 16
        && d.serial.len() <= 1024
        && d.fingerprint.len() <= 256
        && d.device_type.len() <= 64
}

async fn name_owner(bus: &zbus::Proxy<'_>, name: &str) -> Option<String> {
    bus.call::<_, _, String>("GetNameOwner", &(name,))
        .await
        .ok()
}

/// Report the daemon call result honestly: the daemon returns a plain bool
/// and `false` means the request was rejected (F-08).
fn report_result(what: &str, result: zbus::Result<bool>) {
    match result {
        Ok(true) => println!("{}", what),
        Ok(false) => eprintln!("{}: rejected by daemon", what),
        Err(e) => eprintln!("{}: failed: {}", what, e),
    }
}

pub async fn run_dbus_listener(
    last_seen: Arc<Mutex<Option<DeviceInfo>>>,
    default_ttl: u32,
) -> Result<()> {
    let conn = Connection::system().await?;
    *SHARED_CONN.lock().unwrap() = Some(conn.clone());
    let path_str = "/org/lusby/Daemon";
    let iface = "org.lusby.Daemon";

    // Subscribe to signals from the daemon only (S-04): the sender is
    // restricted in the match rule AND verified per message below.
    let match_rule = format!(
        "type='signal',sender='org.lusby.Daemon',path='{}',interface='{}'",
        path_str, iface
    );
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

    // Devices with a notification currently on screen, so repeated hotplug
    // events do not spawn unbounded notification threads.
    let pending: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let mut daemon_owner = name_owner(&bus_proxy, "org.lusby.Daemon").await;

    let mut stream = zbus::MessageStream::from(&conn);
    while let Some(Ok(msg)) = stream.next().await {
        let header = msg.header();
        let path_ok = header.path().as_ref().map(|p| p.as_str()) == Some(path_str);
        let iface_ok = header.interface().as_ref().map(|i| i.as_str()) == Some(iface);
        if msg.message_type() != zbus::MessageType::Signal || !path_ok || !iface_ok {
            continue;
        }
        // Verify the sender is the current owner of org.lusby.Daemon.
        let sender = header.sender().map(|s| s.as_str().to_string());
        let Some(sender) = sender else { continue };
        if daemon_owner.as_deref() != Some(sender.as_str()) {
            daemon_owner = name_owner(&bus_proxy, "org.lusby.Daemon").await;
            if daemon_owner.as_deref() != Some(sender.as_str()) {
                continue;
            }
        }
        let Some(member) = header.member().as_ref().map(|m| m.as_str()) else {
            continue;
        };
        match member {
            "UnknownDeviceInserted" => {
                let body = msg.body();
                let Ok((d,)) = body.deserialize::<(DeviceInfo,)>() else {
                    continue;
                };
                if !valid_signal_device(&d) {
                    tracing::warn!("dropping oversized/invalid device signal");
                    continue;
                }
                println!(
                    "Unknown USB device: {} {} serial={} type={}",
                    d.vendor_id, d.product_id, d.serial, d.device_type
                );
                *last_seen.lock().unwrap() = Some(d.clone());
                // One pending notification per device id.
                {
                    let mut p = pending.lock().unwrap();
                    if !p.insert(d.id.clone()) {
                        continue;
                    }
                }
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
                        dev.vendor_id, dev.product_id, dev.serial, dev.device_type, fp_short
                    ))
                    .icon("security-high")
                    .action(
                        "approve_temp",
                        &format!("Approve for {} minutes", (default_ttl / 60).max(1)),
                    )
                    .action("revoke", "Revoke device");

                match notif.show() {
                    Ok(handle) => {
                        // The action captures the device id it belongs to —
                        // it never acts on whichever device arrived last.
                        // Note: indefinite approvals are intentionally not
                        // offered here; TTL=0 requires polkit authorization
                        // server-side. Permanent access goes through signed
                        // baselines instead.
                        let device_id = dev.id.clone();
                        let pending_id = dev.id.clone();
                        let ttl = default_ttl;
                        let conn_for_action = conn.clone();
                        let pending = pending.clone();
                        std::thread::spawn(move || {
                            handle.wait_for_action(|action| {
                                let uid = unsafe { geteuid() } as u32;
                                let rt = runtime();
                                let conn = conn_for_action.clone();
                                let device_id = device_id.clone();
                                rt.block_on(async move {
                                    let proxy: Option<zbus::Proxy<'_>> = zbus::Proxy::new(
                                        &conn,
                                        "org.lusby.Daemon",
                                        "/org/lusby/Daemon",
                                        "org.lusby.Daemon",
                                    )
                                    .await
                                    .ok();
                                    let Some(proxy) = proxy else {
                                        eprintln!("Failed to reach lusby-daemon");
                                        return;
                                    };
                                    match action {
                                        "approve_temp" => {
                                            let result: zbus::Result<bool> = proxy
                                                .call(
                                                    "RequestEphemeralAllow",
                                                    &(device_id.clone(), ttl, uid),
                                                )
                                                .await;
                                            report_result("Temporary approval", result);
                                        }
                                        "revoke" => {
                                            let result: zbus::Result<bool> =
                                                proxy.call("RevokeDevice", &(device_id,)).await;
                                            report_result("Revoke", result);
                                        }
                                        _ => eprintln!("Unknown action: {}", action),
                                    }
                                });
                            });
                            pending.lock().unwrap().remove(&pending_id);
                        });
                    }
                    Err(e) => {
                        pending.lock().unwrap().remove(&d.id);
                        eprintln!("Failed to show notification: {}", e);
                    }
                }
            }
            "DeviceRemoved" => {
                let body = msg.body();
                if let Ok((id,)) = body.deserialize::<(String,)>() {
                    if id.len() > 256 {
                        continue;
                    }
                    println!("USB device removed: {}", id);
                    let mut guard = last_seen.lock().unwrap();
                    if let Some(d) = guard.as_ref() {
                        if d.id == id {
                            *guard = None;
                        }
                    }
                }
            }
            _ => {}
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
