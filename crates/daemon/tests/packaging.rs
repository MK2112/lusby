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

#[test]
fn deb_metadata_ships_complete_suite() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let manifest = std::fs::read_to_string(format!("{root}/crates/daemon/Cargo.toml"))
        .expect("read daemon manifest");
    let parsed: toml::Value = toml::from_str(&manifest).expect("parse daemon manifest");
    let deb = &parsed["package"]["metadata"]["deb"];

    let assets = deb["assets"].as_array().expect("deb assets");
    let sources: Vec<&str> = assets
        .iter()
        .map(|asset| asset.as_array().unwrap()[0].as_str().unwrap())
        .collect();
    let destinations: Vec<&str> = assets
        .iter()
        .map(|asset| asset.as_array().unwrap()[1].as_str().unwrap())
        .collect();

    for source in [
        "target/release/lusby-daemon",
        "target/release/lusbyctl",
        "target/release/lusby-tray",
        "../../packaging/dbus/system-services/org.lusby.Daemon.service",
        "../../packaging/udev/80-lusby.rules",
        "../../packaging/desktop/lusby-tray.desktop",
    ] {
        assert!(sources.contains(&source), "missing asset source: {source}");
    }
    for destination in [
        "usr/sbin/lusby-daemon",
        "usr/bin/lusbyctl",
        "usr/bin/lusby-tray",
        "usr/share/dbus-1/system-services/org.lusby.Daemon.service",
        "etc/udev/rules.d/80-lusby.rules",
        "etc/xdg/autostart/lusby-tray.desktop",
        "usr/share/applications/lusby-tray.desktop",
    ] {
        assert!(
            destinations.contains(&destination),
            "missing asset destination: {destination}"
        );
    }

    assert_eq!(
        deb["maintainer-scripts"].as_str(),
        Some("../../packaging/debian")
    );
    assert_eq!(
        deb["systemd-units"]["unit-scripts"].as_str(),
        Some("../../packaging/systemd")
    );
    let depends = deb["depends"].as_str().expect("depends");
    assert!(depends.contains("usbguard"));
    assert!(depends.contains("libayatana-appindicator3-1"));
}

#[test]
fn deb_integration_files_are_loadable() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

    let postinst =
        std::fs::read_to_string(format!("{root}/packaging/debian/postinst")).expect("postinst");
    assert!(postinst.contains("#DEBHELPER#"));
    assert!(postinst.contains("/var/log/lusby/audit.log"));
    assert!(postinst.contains("apparmor_parser"));

    for script in ["prerm", "postrm"] {
        let text = std::fs::read_to_string(format!("{root}/packaging/debian/{script}"))
            .unwrap_or_else(|_| panic!("read {script}"));
        assert!(
            text.contains("#DEBHELPER#"),
            "{script} lacks debhelper hook"
        );
    }

    let desktop = std::fs::read_to_string(format!("{root}/packaging/desktop/lusby-tray.desktop"))
        .expect("desktop file");
    assert!(desktop.contains("Exec=/usr/bin/lusby-tray"));

    let activation = std::fs::read_to_string(format!(
        "{root}/packaging/dbus/system-services/org.lusby.Daemon.service"
    ))
    .expect("D-Bus activation file");
    assert!(activation.contains("Exec=/usr/sbin/lusby-daemon"));
    assert!(activation.contains("SystemService=true"));
}
