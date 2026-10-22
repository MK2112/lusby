use anyhow::Result;
use tracing::info;

mod dbus;
use dbus::DaemonState;
use lusby_backend_usbguard::UsbguardBackend;
mod audit;
mod config;
mod logind;
mod polkit;
#[cfg(feature = "udev-monitor")]
mod udev_monitor;

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();
    info!(target: "lusby", event = "daemon_start", "lusby-daemon starting");

    // Register D-Bus service on system bus org.lusby.Daemon
    let backend = UsbguardBackend;
    let state = DaemonState::new(backend);
    // Keep a clone to use in background listeners
    let state_clone = state.clone();
    let connection = zbus::ConnectionBuilder::system()?
        .name("org.lusby.Daemon")?
        .serve_at("/org/lusby/Daemon", state)?
        .build()
        .await?;

    // Cross-check the configured policy against usbguard's effective policy.
    state_clone.check_policy_config().await;

    // Start udev listener to emit D-Bus signals (event-driven). A listener
    // failure is logged and retried so the daemon never runs silently
    // without USB events.
    #[cfg(feature = "udev-monitor")]
    {
        let conn_clone = connection.clone();
        let state_for_udev = state_clone.clone();
        tokio::spawn(async move {
            loop {
                match udev_monitor::run_udev_listener(conn_clone.clone(), state_for_udev.clone())
                    .await
                {
                    Ok(()) => tracing::warn!("udev listener exited; restarting"),
                    Err(e) => tracing::error!(error=?e, "udev listener failed; restarting"),
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
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

    // Ephemeral approval cleanup: sleep until the next expiry (or wake when
    // a new grant is added) so TTLs are enforced promptly instead of on a
    // coarse fixed tick.
    let state_for_cleanup = state_clone.clone();
    tokio::spawn(async move {
        loop {
            let delay = state_for_cleanup.next_cleanup_delay();
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = state_for_cleanup.grant_added() => {}
            }
            state_for_cleanup.cleanup_expired_ephemeral().await;
        }
    });

    // Run until SIGINT/SIGTERM
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("received ctrl_c, exiting");
        }
        _ = sigterm.recv() => {
            info!("received SIGTERM, exiting");
        }
    }
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
