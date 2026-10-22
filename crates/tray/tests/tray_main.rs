use lusby_tray::{clamp_ttl, default_ttl, load_config_ttl_from, ConfigPolicy};

#[test]
fn test_default_ttl() {
    assert_eq!(default_ttl(), 300);
}

#[test]
fn test_load_config_ttl_fallback() {
    // Isolated from the host's /etc/lusby/config.toml (T-02): a missing
    // config must yield the default.
    assert_eq!(load_config_ttl_from("/nonexistent/lusby/config.toml"), 300);
}

#[test]
fn test_load_config_ttl_reads_file() {
    let dir = std::env::temp_dir().join(format!("lusby-tray-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.toml");
    std::fs::write(&path, "[policy]\ndefault_ttl_secs = 900\n").unwrap();
    assert_eq!(load_config_ttl_from(path.to_str().unwrap()), 900);
    // Out-of-range values are clamped into the daemon-accepted range.
    std::fs::write(&path, "[policy]\ndefault_ttl_secs = 999999\n").unwrap();
    assert_eq!(load_config_ttl_from(path.to_str().unwrap()), 86400);
    std::fs::write(&path, "[policy]\ndefault_ttl_secs = 0\n").unwrap();
    assert_eq!(load_config_ttl_from(path.to_str().unwrap()), 1);
    // Broken config logs loudly and falls back.
    std::fs::write(&path, "not = [valid").unwrap();
    assert_eq!(load_config_ttl_from(path.to_str().unwrap()), 300);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_config_policy_default() {
    let policy = ConfigPolicy::default();
    assert_eq!(policy.default_ttl_secs, 300);
}

#[test]
fn test_clamp_ttl() {
    assert_eq!(clamp_ttl(0), 1);
    assert_eq!(clamp_ttl(300), 300);
    assert_eq!(clamp_ttl(999_999_999), 86400);
}
