use serde::Deserialize;

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
pub fn load_config_ttl() -> u32 {
    let path = "/etc/lusby/config.toml";
    if let Ok(text) = std::fs::read_to_string(path) {
        if let Ok(cfg) = toml::from_str::<Config>(&text) {
            return cfg.policy.default_ttl_secs;
        }
    }
    default_ttl()
}
