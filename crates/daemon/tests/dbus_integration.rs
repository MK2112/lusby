use anyhow::Result;
use zbus::Connection;

// These integration tests require the daemon running on the system bus and appropriate permissions.
// Enable with: GU_TEST_SYSTEM=1 cargo test -p guardianusb-daemon --test dbus_integration -- --ignored

#[tokio::test]
#[ignore]
async fn get_policy_status_roundtrip() -> Result<()> {
    if std::env::var("GU_TEST_SYSTEM").ok().as_deref() != Some("1") { return Ok(()); }
    let conn = Connection::system().await?;
    let proxy = zbus::Proxy::new(&conn,
        "org.guardianusb.Daemon",
        "/org/guardianusb/Daemon",
        "org.guardianusb.Daemon").await?;
    let status: guardianusb_common::types::PolicyStatus = proxy.call("get_policy_status", &()).await?;
    println!("status: deny_unknown={}", status.deny_unknown);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn auto_revoke_on_prepare_for_sleep() -> Result<()> {
    if std::env::var("GU_TEST_SYSTEM").ok().as_deref() != Some("1") { return Ok(()); }
    let conn = Connection::system().await?;

    // There is no safe way to emit PrepareForSleep on org.freedesktop.login1 without privileges.
    // This test is a placeholder to manually validate that inserting a device, approving it
    // ephemerally, then suspending the machine causes it to be revoked on resume.
    // Steps:
    // 1. guardianusbctl list -> get device id
    // 2. guardianusbctl (or D-Bus call) request_ephemeral_allow(id, 60, uid)
    // 3. systemctl suspend (or lock), then resume
    // 4. Ensure device is revoked (guardianusbctl list, and audit log indicates auto_revoke)

    // Programmatically, we at least verify that the proxy is reachable here.
    let _proxy = zbus::Proxy::new(&conn,
        "org.guardianusb.Daemon",
        "/org/guardianusb/Daemon",
        "org.guardianusb.Daemon").await?;
    Ok(())
}
