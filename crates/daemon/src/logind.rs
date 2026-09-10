use anyhow::Result;
use futures_util::StreamExt;
use zbus::Connection;

// Listen to org.freedesktop.login1.Manager signals on system bus
pub async fn run_logind_listener(
    connection: Connection,
    state: crate::dbus::DaemonState,
) -> Result<()> {
    // Without an explicit match rule the system bus will not deliver
    // login1 broadcasts to us at all (previous silent failure).
    if let Ok(bus) = zbus::Proxy::new(
        &connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await
    {
        for rule in [
            "type='signal',interface='org.freedesktop.login1.Manager'",
            "type='signal',interface='org.freedesktop.login1.Session',member='Lock'",
        ] {
            let _: Result<(), _> = bus.call("AddMatch", &(rule,)).await.map(|_: ()| ());
        }
    }
    let mut stream = zbus::MessageStream::from(&connection);
    // Filter messages in-process
    while let Some(Ok(msg)) = stream.next().await {
        let header = msg.header();
        if msg.message_type() != zbus::MessageType::Signal {
            continue;
        }
        let iface = header.interface().map(|i| i.as_str()).unwrap_or("");
        // Session lock: revoke ephemeral approvals on workstation lock.
        if iface == "org.freedesktop.login1.Session"
            && header.member().map(|m| m.as_str()) == Some("Lock")
        {
            state.revoke_all_ephemeral().await;
            continue;
        }
        let iface_ok = iface == "org.freedesktop.login1.Manager";
        if !iface_ok {
            continue;
        }
        if let Some(member) = header.member().map(|m| m.as_str().to_string()) {
            match member.as_str() {
                "PrepareForSleep" => {
                    if let Ok((going_to_sleep,)) = msg.body().deserialize::<(bool,)>() {
                        if going_to_sleep {
                            // Revoke all ephemeral approvals immediately
                            state.revoke_all_ephemeral().await;
                        }
                    }
                }
                "PrepareForShutdown" => {
                    if let Ok((will_shutdown,)) = msg.body().deserialize::<(bool,)>() {
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
