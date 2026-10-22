//! Daemon configuration (`/etc/lusby/config.toml`).
//!
//! The file is loaded and honored by the daemon; parse/read errors are
//! logged loudly and fall back to the defaults instead of failing silently.

use serde::Deserialize;
use std::path::{Path, PathBuf};

fn default_true() -> bool {
    true
}
fn default_ttl() -> u32 {
    300
}
fn default_baselines() -> PathBuf {
    PathBuf::from("/etc/lusby/baselines")
}
fn default_pubkeys() -> PathBuf {
    PathBuf::from("/etc/lusby/trusted_pubkeys")
}
fn default_audit_log() -> PathBuf {
    PathBuf::from("/var/log/lusby/audit.log")
}
fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/lusby")
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_true")]
    pub deny_unknown: bool,
    #[serde(default = "default_ttl")]
    pub default_ttl_secs: u32,
    #[serde(default = "default_true")]
    pub revoke_on_lock: bool,
    #[serde(default = "default_true")]
    pub revoke_on_suspend: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            deny_unknown: default_true(),
            default_ttl_secs: default_ttl(),
            revoke_on_lock: default_true(),
            revoke_on_suspend: default_true(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PathsConfig {
    #[serde(default = "default_baselines")]
    pub baselines_system: PathBuf,
    #[serde(default = "default_pubkeys")]
    pub trusted_pubkeys: PathBuf,
    #[serde(default = "default_audit_log")]
    pub audit_log: PathBuf,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            baselines_system: default_baselines(),
            trusted_pubkeys: default_pubkeys(),
            audit_log: default_audit_log(),
            state_dir: default_state_dir(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub paths: PathsConfig,
}

impl Config {
    /// Load the config, clamping values into the daemon-accepted ranges.
    /// A missing file yields defaults; a broken file logs loudly and yields
    /// defaults (never a silent fallback).
    pub fn load(path: &Path) -> Self {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!(path = %path.display(), "no config file, using defaults");
                return Self::default();
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "config unreadable, using defaults");
                return Self::default();
            }
        };
        match toml::from_str::<Config>(&text) {
            Ok(mut cfg) => {
                cfg.policy.default_ttl_secs = cfg.policy.default_ttl_secs.clamp(1, 86400);
                cfg
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "config parse error, using defaults");
                Self::default()
            }
        }
    }

    pub fn load_default() -> Self {
        let path = std::env::var("LUSBY_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/etc/lusby/config.toml"));
        Self::load(&path)
    }
}
