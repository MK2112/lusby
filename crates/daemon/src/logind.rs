use anyhow::Result;
use futures_util::StreamExt;
use zbus::Connection;

/// Listen to org.freedesktop.login1 signals on the system bus and revoke
/// ephemeral approvals on lock/sleep/shutdown.
///
/// Failures are logged and the listener reconnects instead of silently dying.
/// Signal senders are verified against the login1 bus name owner so any local
/// process cannot fake a `PrepareForSleep`/`Lock` signal and force revokes.
pub async fn run_logind_listener(
    connection: Connection,
    state: crate::dbus::DaemonState,
) -> Result<()> {
    loop {
        match listen_once(&connection, &state).await {
            Ok(()) => tracing::warn!("logind listener stream ended; restarting"),
            Err(e) => tracing::error!(error = ?e, "logind listener failed; restarting"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn get_name_owner(bus: &zbus::Proxy<'_>, name: &str) -> Option<String> {
    bus.call::<_, _, String>("GetNameOwner", &(name,))
        .await
        .ok()
}

async fn listen_once(connection: &Connection, state: &crate::dbus::DaemonState) -> Result<()> {
    let bus = zbus::Proxy::new(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await?;
    // Restrict matches to the real login1 sender (defense in depth; the
    // sender is also verified per message).
    for rule in [
        "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager'",
        "type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Session',member='Lock'",
    ] {
        // A failed AddMatch means we would silently receive nothing — surface it.
        bus.call::<_, _, ()>("AddMatch", &(rule,))
            .await
            .map_err(|e| anyhow::anyhow!("AddMatch failed: {e}"))?;
    }
    let mut login1_owner = get_name_owner(&bus, "org.freedesktop.login1").await;
    let mut stream = zbus::MessageStream::from(connection);
    while let Some(msg) = stream.next().await {
        // A stream error ends this attempt; the outer loop restarts it.
        let msg = msg?;
        let header = msg.header();
        if msg.message_type() != zbus::MessageType::Signal {
            continue;
        }
        // Verify the sender is the current owner of org.freedesktop.login1.
        let sender = header.sender().map(|s| s.as_str().to_string());
        let Some(sender) = sender else { continue };
        if login1_owner.as_deref() != Some(sender.as_str()) {
            login1_owner = get_name_owner(&bus, "org.freedesktop.login1").await;
            if login1_owner.as_deref() != Some(sender.as_str()) {
                continue;
            }
        }
        let iface = header.interface().map(|i| i.as_str()).unwrap_or("");
        // Session lock: revoke ephemeral approvals on workstation lock.
        if iface == "org.freedesktop.login1.Session"
            && header.member().map(|m| m.as_str()) == Some("Lock")
        {
            if state.revoke_on_lock() {
                state.revoke_all_ephemeral().await;
            }
            continue;
        }
        if iface != "org.freedesktop.login1.Manager" {
            continue;
        }
        if let Some(member) = header.member().map(|m| m.as_str().to_string()) {
            match member.as_str() {
                "PrepareForSleep" => {
                    if let Ok((going_to_sleep,)) = msg.body().deserialize::<(bool,)>() {
                        if going_to_sleep && state.revoke_on_suspend() {
                            state.revoke_all_ephemeral().await;
                        }
                    }
                }
                "PrepareForShutdown" => {
                    if let Ok((will_shutdown,)) = msg.body().deserialize::<(bool,)>() {
                        // Shutdown is final: always revoke, regardless of the
                        // suspend flag.
                        if will_shutdown {
                            state.revoke_all_ephemeral().await;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}
