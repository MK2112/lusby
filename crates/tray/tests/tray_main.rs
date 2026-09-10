use lusby_tray::{clamp_ttl, default_ttl, load_config_ttl, ConfigPolicy};

#[test]
fn test_default_ttl() {
    assert_eq!(default_ttl(), 300);
}

#[test]
fn test_load_config_ttl_fallback() {
    assert_eq!(load_config_ttl(), 300);
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
