use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "lusbyctl", version, about = "Lusby CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// List devices
    List,
    /// Show info on a device
    Info { device: String },
    /// Show policy status
    Status,
    /// Baseline operations
    Baseline {
        #[command(subcommand)]
        cmd: BaselineCmd,
    },
    /// Audit log verification
    Audit {
        #[command(subcommand)]
        cmd: AuditCmd,
    },
    /// Trusted key management
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
    /// Ephemeral authorization (no root)
    Allow(AllowArgs),
    /// Revoke a device immediately
    Revoke { device: String },
    /// Launch TUI for baseline editing
    Tui,
}

#[derive(Subcommand)]
pub enum BaselineCmd {
    /// Generate an Ed25519 keypair and print base64 values
    Keygen,
    /// Sign a baseline JSON (canonical JSON) with a base64 secret key, writing signature into the file
    Sign {
        /// Base64 32-byte secret (prefer --secret-file or LUSBY_SECRET_B64 env)
        #[arg(long, env = "LUSBY_SECRET_B64", conflicts_with = "secret_file")]
        secret_b64: Option<String>,
        /// Read the base64 secret from a file
        #[arg(long, conflicts_with = "secret_b64")]
        secret_file: Option<PathBuf>,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Initialize an unsigned baseline from a live device id
    Init {
        device: String,
        #[arg(long)]
        serial: Option<String>,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Apply a signed baseline over D-Bus (polkit-gated)
    Apply {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        signer: String,
    },
    /// Verify a signed baseline JSON using an ed25519 public key
    Verify {
        #[arg(long)]
        pubkey: PathBuf,
        file: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum AuditCmd {
    /// Verify a JSONL audit log chain
    Verify { file: PathBuf },
}

#[derive(Subcommand)]
pub enum KeysCmd {
    /// Add a trusted public key (raw 32 bytes) from base64
    Add {
        name: String,
        #[arg(long)]
        pub_b64: String,
    },
    /// List trusted public keys
    List,
    /// Remove a trusted public key by name (with or without .pub)
    Remove { name: String },
}

#[derive(Args)]
pub struct AllowArgs {
    /// usbguard device id (e.g., 2-1)
    pub device: String,
    /// TTL seconds (0 = indefinite, polkit-gated; 1-86400 = temporary)
    #[arg(long, default_value_t = 300)]
    pub ttl: u32,
}
