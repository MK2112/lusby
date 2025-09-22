use anyhow::Result;
use glib::Continue;
#[cfg(feature = "tray-ui")]
use gtk::prelude::*;
#[cfg(feature = "tray-ui")]
use libappindicator::{AppIndicator, AppIndicatorStatus};
use libc::geteuid;
use lusby_common::types::DeviceInfo;
use std::sync::{Arc, Mutex};

// Minimal GTK/libappindicator system tray with approval actions.
// Keeps idle footprint low by avoiding polling; UI updates are user-driven.
#[cfg(feature = "tray-ui")]
pub fn start_indicator(
    last_seen: Arc<Mutex<Option<DeviceInfo>>>,
    default_ttl_secs: u32,
) -> Result<()> {
    if !gtk::is_initialized_main_thread() {
        gtk::init()?;
    }

    let mut indicator = AppIndicator::new("lusby", "security-high");
    indicator.set_status(AppIndicatorStatus::Active);

    let mut menu = gtk::Menu::new();

    // Countdown state
    let approval_end = Arc::new(Mutex::new(None::<std::time::Instant>));

    // Approve for N minutes (starts countdown)
    let approve_item = gtk::MenuItem::with_label(&format!(
        "Approve for {} minutes",
        (default_ttl_secs / 60).max(1)
    ));
    {
        let last_seen = last_seen.clone();
        let approval_end = approval_end.clone();
        let ttl = default_ttl_secs;
        approve_item.connect_activate(move |_| {
            if let Some(dev) = last_seen.lock().unwrap().clone() {
                let device_id = dev.id.clone();
                let uid = unsafe { geteuid() } as u32;
                let ttl: u32 = ttl;
                let end = std::time::Instant::now() + std::time::Duration::from_secs(ttl as u64);
                *approval_end.lock().unwrap() = Some(end);
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async move {
                        if let Ok(conn) = zbus::Connection::system().await {
                            if let Ok(proxy) = zbus::Proxy::new(
                                &conn,
                                "org.lusby.Daemon",
                                "/org/lusby/Daemon",
                                "org.lusby.Daemon",
                            )
                            .await
                            {
                                let _: bool = proxy
                                    .call_method("request_ephemeral_allow", &(device_id, ttl, uid))
                                    .await
                                    .expect("D-Bus call failed")
                                    .body()
                                    .deserialize()
                                    .expect("Failed to deserialize response");
                            }
                        }
                    });
                });
            }
        });
    }
    menu.append(&approve_item);

    // Countdown display
    let countdown_item = gtk::MenuItem::with_label("Countdown: --");
    {
        let approval_end = approval_end.clone();
        let countdown_item_clone = countdown_item.clone();
        gtk::glib::timeout_add_local(std::time::Duration::from_secs(1), move || {
            let label = if let Some(end) = *approval_end.lock().unwrap() {
                let now = std::time::Instant::now();
                if now < end {
                    let secs = (end - now).as_secs();
                    format!("Countdown: {}s", secs)
                } else {
                    // Auto-revoke
                    "Countdown: expired".to_string()
                }
            } else {
                "Countdown: --".to_string()
            };
            countdown_item_clone.set_label(&label);
            Continue(true)
        });
    }
    menu.append(&countdown_item);

    // Manual revoke button
    let revoke_now_item = gtk::MenuItem::with_label("Revoke now");
    {
        let last_seen = last_seen.clone();
        let approval_end = approval_end.clone();
        revoke_now_item.connect_activate(move |_| {
            if let Some(dev) = last_seen.lock().unwrap().clone() {
                let device_id = dev.id.clone();
                *approval_end.lock().unwrap() = None;
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async move {
                        if let Ok(conn) = zbus::Connection::system().await {
                            if let Ok(proxy) = zbus::Proxy::new(
                                &conn,
                                "org.lusby.Daemon",
                                "/org/lusby/Daemon",
                                "org.lusby.Daemon",
                            )
                            .await
                            {
                                let _: bool = proxy
                                    .call_method("revoke_device", &(device_id))
                                    .await
                                    .expect("D-Bus call failed")
                                    .body()
                                    .deserialize()
                                    .expect("Failed to deserialize response");
                            }
                        }
                    });
                });
            }
        });
    }
    menu.append(&revoke_now_item);

    // Revoke last device
    let revoke_item = gtk::MenuItem::with_label("Revoke last device");
    {
        let last_seen = last_seen.clone();
        revoke_item.connect_activate(move |_| {
            if let Some(dev) = last_seen.lock().unwrap().clone() {
                let device_id = dev.id.clone();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async move {
                        if let Ok(conn) = zbus::Connection::system().await {
                            if let Ok(proxy) = zbus::Proxy::new(
                                &conn,
                                "org.lusby.Daemon",
                                "/org/lusby/Daemon",
                                "org.lusby.Daemon",
                            )
                            .await
                            {
                                let _: bool = proxy
                                    .call_method("revoke_device", &(device_id))
                                    .await
                                    .expect("D-Bus call failed")
                                    .body()
                                    .deserialize()
                                    .expect("Failed to deserialize response");
                            }
                        }
                    });
                });
            }
        });
    }
    menu.append(&revoke_item);

    // Show last device details
    let details_item = gtk::MenuItem::with_label("Show last device details");
    {
        let last_seen = last_seen.clone();
        details_item.connect_activate(move |_| {
            if let Some(dev) = last_seen.lock().unwrap().clone() {
                let text = format!(
                    "Vendor: {}\nProduct: {}\nSerial: {}\nType: {}\nFingerprint: {}",
                    dev.vendor_id, dev.product_id, dev.serial, dev.device_type, dev.fingerprint
                );
                let dialog = gtk::MessageDialog::new(
                    None::<&gtk::Window>,
                    gtk::DialogFlags::MODAL,
                    gtk::MessageType::Info,
                    gtk::ButtonsType::Ok,
                    &text,
                );
                dialog.run();
                unsafe {
                    dialog.destroy();
                }
            }
        });
    }
    menu.append(&details_item);

    // Quit
    let quit_item = gtk::MenuItem::with_label("Quit");
    quit_item.connect_activate(move |_| {
        gtk::main_quit();
    });
    menu.append(&quit_item);

    menu.show_all();
    indicator.set_menu(&mut menu);

    // Run GTK main loop in a background thread to avoid blocking async tasks
    std::thread::spawn(gtk::main);

    Ok(())
}

// No-op stub if feature is off
#[cfg(not(feature = "tray-ui"))]
pub fn start_indicator(
    _last_seen: Arc<Mutex<Option<DeviceInfo>>>,
    _default_ttl_secs: u32,
) -> Result<()> {
    Ok(())
}
