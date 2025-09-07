use anyhow::Result;
use clap::{Parser, Subcommand};
use zbus::Connection;
use guardianusb_common::types::DeviceInfo;
use serde_json;
use std::fs;
use std::path::PathBuf;
use guardianusb_common::baseline::Baseline;
use guardianusb_common::audit::{verify_chain, AuditEntry};
use ed25519_dalek::VerifyingKey;

#[derive(Parser)]
#[command(name = "guardianusbctl", version, about = "GuardianUSB CLI")] 
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List devices (stub)
    List,
    /// Show info on a device (stub)
    Info { device: String },
    /// Show policy status
    Status,
    /// Baseline operations
    Baseline { #[command(subcommand)] cmd: BaselineCmd },
    /// Audit log verification
    Audit { #[command(subcommand)] cmd: AuditCmd },
}

#[derive(Subcommand)]
enum BaselineCmd {
    /// Verify a signed baseline JSON using an ed25519 public key
    Verify { #[arg(long)] pubkey: PathBuf, file: PathBuf },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Verify a JSONL audit log chain
    Verify { file: PathBuf },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let conn = Connection::system().await?;
    let proxy = zbus::Proxy::new(&conn, "org.guardianusb.Daemon", "/org/guardianusb/Daemon", "org.guardianusb.Daemon").await?;
    match cli.command {
        Commands::List => {
            let devices: Vec<DeviceInfo> = proxy.call("list_devices", &()).await?;
            println!("{}", serde_json::to_string_pretty(&devices)?);
        }
        Commands::Info { device } => {
            let info: DeviceInfo = proxy.call("get_device_info", &(device)).await?;
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        Commands::Status => {
            let status: guardianusb_common::types::PolicyStatus = proxy.call("get_policy_status", &()).await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        Commands::Baseline { cmd } => {
            match cmd {
                BaselineCmd::Verify { pubkey, file } => {
                    let data = fs::read(&file)?;
                    let baseline: Baseline = serde_json::from_slice(&data)?;
                    let pk_bytes = fs::read(&pubkey)?;
                    let vk = VerifyingKey::from_bytes(&pk_bytes.try_into().map_err(|_| anyhow::anyhow!("invalid pubkey length"))?)?;
                    let ok = baseline.verify_signature(&vk).map_err(|e| anyhow::anyhow!(e))?;
                    if ok { println!("OK"); } else { eprintln!("FAIL"); std::process::exit(1); }
                }
            }
        }
        Commands::Audit { cmd } => {
            match cmd {
                AuditCmd::Verify { file } => {
                    let text = fs::read_to_string(&file)?;
                    let mut entries: Vec<AuditEntry> = Vec::new();
                    for line in text.lines() {
                        if line.trim().is_empty() { continue; }
                        let e: AuditEntry = serde_json::from_str(line)?;
                        entries.push(e);
                    }
                    if verify_chain(&entries) { println!("OK"); } else { eprintln!("FAIL"); std::process::exit(1); }
                }
            }
        }
    }
    Ok(())
}
