use anyhow::Result;
use lusby_backend_mock::MockBackend;
use lusby_daemon::DaemonState;

#[test]
fn daemonstate_initialization() {
    let backend = MockBackend::default();
    // Log into a private temp dir: the audit logger may create its log
    // directory, and must never be pointed at a shared parent like /tmp.
    let dir = tempfile::tempdir().expect("create tempdir");
    let state = DaemonState::new_with_audit_path(backend, dir.path().join("audit.log"));
    assert_eq!(state.ephemeral_count(), 0);
}

#[tokio::test]
async fn dbus_name_conflict() -> Result<()> {
    // Try to acquire a reserved name, should fail. Skip when no session bus
    // is available instead of panicking (T-02).
    let Ok(builder) = zbus::ConnectionBuilder::session() else {
        println!("skipping: no session bus available");
        return Ok(());
    };
    let result = builder.name("org.freedesktop.DBus").unwrap().build().await;
    assert!(result.is_err());
    Ok(())
}
