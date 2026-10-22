// Regression tests for the packaging fixes:
// F-02: the AppArmor profile must allow writing the rename destination
//       /etc/usbguard/rules.conf, or `baseline apply` fails at rename time.
// F-17: the D-Bus policy must expose the polkit-gated management methods to
//       the default policy so the daemon's polkit check is reachable.

#[test]
fn apparmor_allows_rules_conf_rename_destination() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packaging/apparmor/usr.sbin.lusby-daemon"
    );
    let text = std::fs::read_to_string(path).expect("read AppArmor profile");
    assert!(
        text.contains("/etc/usbguard/rules.conf rw,"),
        "rename destination /etc/usbguard/rules.conf must be writable"
    );
    // The managed tmp/backup files must stay writable too.
    assert!(text.contains("/etc/usbguard/rules.conf.tmp rw,"));
    assert!(text.contains("/etc/usbguard/rules.conf.bak rw,"));
}

#[test]
fn dbus_policy_allows_polkit_gated_methods() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packaging/dbus/org.lusby.Daemon.conf"
    );
    let text = std::fs::read_to_string(path).expect("read D-Bus policy");
    for member in [
        "ApplyPersistentAllow",
        "AddTrustedPubkey",
        "RemoveTrustedPubkey",
        "ListTrustedPubkeys",
    ] {
        assert!(
            text.contains(&format!("send_member=\"{}\"", member)),
            "default policy must allow {} so polkit can authenticate it",
            member
        );
    }
}

#[test]
fn polkit_policy_requires_auth_admin() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packaging/polkit/org.lusby.manage.policy"
    );
    let text = std::fs::read_to_string(path).expect("read polkit policy");
    assert!(text.contains("<allow_active>auth_admin</allow_active>"));
    assert!(text.contains("<allow_any>no</allow_any>"));
}
