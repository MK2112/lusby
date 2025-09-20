use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "guardianusbctl", version, about = "GuardianUSB CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Clone)]
pub enum Commands {
    List,
    Info { device: String },
    Status,
    Allow(AllowArgs),
    Revoke { device: String },
    /// Launch visual baseline editor (TUI)
    Tui,
}

#[derive(Args, Clone)]
pub struct AllowArgs {
    pub device: String,
    #[arg(long, default_value_t = 300)]
    pub ttl: u32,
}
