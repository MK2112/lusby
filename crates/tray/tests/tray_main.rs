use lusby_tray::{default_ttl, load_config_ttl, ConfigPolicy};

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
