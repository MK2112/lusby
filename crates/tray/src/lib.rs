use serde::Deserialize;

/// Daemon-accepted ephemeral TTL range (seconds). Keeps tray requests from
/// being rejected after a hand-edited config sets absurd values.
pub const MAX_TTL_SECS: u32 = 86400;
pub const MIN_TTL_SECS: u32 = 1;

#[derive(Debug, Deserialize)]
pub struct ConfigPolicy {
    #[serde(default = "default_ttl")]
    pub default_ttl_secs: u32,
}
impl Default for ConfigPolicy {
    fn default() -> Self {
        Self {
            default_ttl_secs: default_ttl(),
        }
    }
}
#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub policy: ConfigPolicy,
}
pub fn default_ttl() -> u32 {
    300
}
pub fn clamp_ttl(ttl: u32) -> u32 {
    ttl.clamp(MIN_TTL_SECS, MAX_TTL_SECS)
}
pub fn load_config_ttl_from(path: &str) -> u32 {
    match std::fs::read_to_string(path) {
        Ok(text) => match toml::from_str::<Config>(&text) {
            Ok(cfg) => return clamp_ttl(cfg.policy.default_ttl_secs),
            Err(e) => eprintln!(
                "lusby-tray: config parse error in {}: {}; using default TTL",
                path, e
            ),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!("lusby-tray: cannot read {}: {}; using default TTL", path, e),
    }
    default_ttl()
}

pub fn load_config_ttl() -> u32 {
    load_config_ttl_from("/etc/lusby/config.toml")
}
