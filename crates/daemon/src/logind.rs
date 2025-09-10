use anyhow::Result;
use futures_util::StreamExt;
use zbus::Connection;

// Listen to org.freedesktop.login1.Manager signals on system bus
pub async fn run_logind_listener(
    connection: Connection,
    state: crate::dbus::DaemonState,
) -> Result<()> {
    let mut stream = zbus::MessageStream::from(&connection);
    // Filter messages in-process
    while let Some(Ok(msg)) = stream.next().await {
        let header = msg.header();
        if msg.message_type() != zbus::MessageType::Signal {
            continue;
        }
        let iface_ok =
            header.interface().map(|i| i.as_str()) == Some("org.freedesktop.login1.Manager");
        if !iface_ok {
            continue;
        }
        if let Some(member) = header.member().map(|m| m.as_str().to_string()) {
            if member.as_str() == "PrepareForSleep" {
                if let Ok((going_to_sleep,)) = msg.body().deserialize::<(bool,)>() {
                    if going_to_sleep {
                        // Revoke all ephemeral approvals immediately
                        state.revoke_all_ephemeral().await;
                    }
                }
            }
        }
    }
    Ok(())
}
