use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

mod dbus;
use dbus::DaemonState;
use guardianusb_backend_usbguard::UsbguardBackend;
mod audit;
mod logind;
mod polkit;
#[cfg(feature = "udev-monitor")]
mod udev_monitor;

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();
    info!(target: "guardianusb", event = "daemon_start", "guardianusb-daemon starting");

    // Register D-Bus service on system bus org.guardianusb.Daemon
    let backend = UsbguardBackend::default();
    let state = DaemonState::new(backend);
    // Keep a clone to use in background listeners
    let state_clone = state.clone();
    let connection = zbus::ConnectionBuilder::system()?
        .name("org.guardianusb.Daemon")?
        .serve_at("/org/guardianusb/Daemon", state)?
        .build()
        .await?;

    // Start udev listener to emit D-Bus signals (event-driven)
    #[cfg(feature = "udev-monitor")]
    {
        let conn_clone = connection.clone();
        tokio::spawn(async move {
            if let Err(e) = udev_monitor::run_udev_listener(conn_clone).await {
                tracing::error!(error=?e, "udev listener exited with error");
            }
        });
    }

    // Start logind listener for suspend/lock to auto-revoke ephemeral approvals
    let conn2 = connection.clone();
    let state_for_logind = state_clone.clone();
    tokio::spawn(async move {
        if let Err(e) = logind::run_logind_listener(conn2, state_for_logind).await {
            tracing::error!(error=?e, "logind listener exited with error");
        }
    });

    // Run until SIGINT/SIGTERM
    tokio::signal::ctrl_c().await?;
    info!("received ctrl_c, exiting");
    Ok(())
}

fn setup_logging() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = fmt::layer()
        .json()
        .with_target(true)
        .with_timer(fmt::time::UtcTime::rfc_3339());
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
}

#[derive(Debug, Serialize, Deserialize)]
struct PolicyStatus {
    deny_unknown: bool,
}
