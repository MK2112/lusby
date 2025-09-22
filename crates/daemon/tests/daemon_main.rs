use anyhow::Result;
use lusby_backend_mock::MockBackend;
use lusby_daemon::DaemonState;

#[test]
fn daemonstate_initialization() {
    let backend = MockBackend::default();
    let state = DaemonState::new_with_audit_path(
        backend,
        std::path::PathBuf::from("/tmp/lusby-test-audit.log"),
    );
    assert_eq!(state.ephemeral_count(), 0);
}

#[tokio::test]
async fn dbus_name_conflict() -> Result<()> {
    // Try to acquire a reserved name, should fail
    let builder = zbus::ConnectionBuilder::session().unwrap();
    let result = builder.name("org.freedesktop.DBus").unwrap().build().await;
    assert!(result.is_err());
    Ok(())
}
