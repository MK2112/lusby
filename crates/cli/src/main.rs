use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use lusby_common::audit::{verify_chain, AuditEntry};
use lusby_common::baseline::{Baseline, DeviceEntry};
use lusby_common::types::DeviceInfo;
use rand::rngs::OsRng;
use std::fs;
use std::path::PathBuf;
use zbus::Connection;

mod tui;

#[derive(Parser)]
#[command(name = "lusbyctl", version, about = "Lusby CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
enum BaselineCmd {
    /// Generate an Ed25519 keypair and print base64 values
    Keygen,
    /// Sign a baseline JSON (canonical JSON) with a base64 secret key, writing signature into the file
    Sign {
        #[arg(long)]
        secret_b64: String,
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
enum AuditCmd {
    /// Verify a JSONL audit log chain
    Verify { file: PathBuf },
}

#[derive(Subcommand)]
enum KeysCmd {
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
struct AllowArgs {
    /// usbguard device id (e.g., 2-1)
    device: String,
    /// TTL seconds
    #[arg(long, default_value_t = 300)]
    ttl: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let conn = Connection::system().await?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.lusby.Daemon",
        "/org/lusby/Daemon",
        "org.lusby.Daemon",
    )
    .await?;
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
            let status: lusby_common::types::PolicyStatus =
                proxy.call("get_policy_status", &()).await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        Commands::Baseline { cmd } => {
            match cmd {
                BaselineCmd::Keygen => {
                    let sk = SigningKey::generate(&mut OsRng);
                    let pk = sk.verifying_key();
                    println!("SECRET_B64={}", B64.encode(sk.to_bytes()));
                    println!("PUB_RAW32_B64={}", B64.encode(pk.to_bytes()));
                }
                BaselineCmd::Sign {
                    secret_b64,
                    input,
                    output,
                } => {
                    let data = fs::read(&input)?;
                    let mut baseline: Baseline = serde_json::from_slice(&data)?;
                    // decode 32-byte secret
                    let secret = B64.decode(secret_b64)?;
                    if secret.len() != 32 {
                        anyhow::bail!("secret must be 32 raw bytes in base64");
                    }
                    let sk = SigningKey::from_bytes(&secret.clone().try_into().unwrap());
                    baseline.sign_attach(&sk).map_err(|e| anyhow::anyhow!(e))?;
                    fs::write(&output, serde_json::to_string_pretty(&baseline)?)?;
                    println!("Signed baseline written: {}", output.display());
                }
                BaselineCmd::Init {
                    device,
                    serial,
                    comment,
                    output,
                } => {
                    let info: DeviceInfo = proxy.call("get_device_info", &(device)).await?;
                    if info.id.is_empty() {
                        anyhow::bail!("device not found");
                    }
                    let dev = DeviceEntry {
                        vendor_id: info.vendor_id,
                        product_id: info.product_id,
                        serial: serial.or({
                            if info.serial.is_empty() {
                                None
                            } else {
                                Some(info.serial)
                            }
                        }),
                        bus_path: None,
                        descriptors_hash: String::new(),
                        device_type: if info.device_type.is_empty() {
                            String::from("")
                        } else {
                            info.device_type
                        },
                        comment,
                    };
                    let baseline = Baseline {
                        version: 1,
                        created_by: whoami::username(),
                        created_at: Utc::now(),
                        devices: vec![dev],
                        signature: None,
                    };
                    fs::write(&output, serde_json::to_string_pretty(&baseline)?)?;
                    println!("Baseline draft written: {}", output.display());
                }
                BaselineCmd::Apply { file, signer } => {
                    let path = file.canonicalize()?;
                    let ok: bool = proxy
                        .call(
                            "apply_persistent_allow",
                            &(path.to_string_lossy().to_string(), signer),
                        )
                        .await?;
                    if ok {
                        println!("OK");
                    } else {
                        anyhow::bail!("apply failed (see daemon logs)");
                    }
                }
                BaselineCmd::Verify { pubkey, file } => {
                    let data = fs::read(&file)?;
                    let baseline: Baseline = serde_json::from_slice(&data)?;
                    let pk_bytes = fs::read(&pubkey)?;
                    let vk = VerifyingKey::from_bytes(
                        &pk_bytes
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("invalid pubkey length"))?,
                    )?;
                    let ok = baseline
                        .verify_signature(&vk)
                        .map_err(|e| anyhow::anyhow!(e))?;
                    if ok {
                        println!("OK");
                    } else {
                        eprintln!("FAIL");
                        std::process::exit(1);
                    }
                }
            }
        }
        Commands::Audit { cmd } => match cmd {
            AuditCmd::Verify { file } => {
                let text = fs::read_to_string(&file)?;
                let mut entries: Vec<AuditEntry> = Vec::new();
                for line in text.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let e: AuditEntry = serde_json::from_str(line)?;
                    entries.push(e);
                }
                if verify_chain(&entries) {
                    println!("OK");
                } else {
                    eprintln!("FAIL");
                    std::process::exit(1);
                }
            }
        },
        Commands::Keys { cmd } => match cmd {
            KeysCmd::Add { name, pub_b64 } => {
                let ok: bool = proxy.call("add_trusted_pubkey", &(name, pub_b64)).await?;
                if ok {
                    println!("OK");
                } else {
                    anyhow::bail!("add key failed");
                }
            }
            KeysCmd::List => {
                let names: Vec<String> = proxy.call("list_trusted_pubkeys", &()).await?;
                for n in names {
                    println!("{}", n);
                }
            }
            KeysCmd::Remove { name } => {
                let ok: bool = proxy.call("remove_trusted_pubkey", &(name)).await?;
                if ok {
                    println!("OK");
                } else {
                    anyhow::bail!("remove key failed");
                }
            }
        },
        Commands::Allow(args) => {
            let uid = unsafe { libc::geteuid() } as u32;
            let ok: bool = proxy
                .call("request_ephemeral_allow", &(args.device, args.ttl, uid))
                .await?;
            if ok {
                println!("OK");
            } else {
                eprintln!("FAIL");
                std::process::exit(1);
            }
        }
        Commands::Revoke { device } => {
            let ok: bool = proxy.call("revoke_device", &(device)).await?;
            if ok {
                println!("OK");
            } else {
                eprintln!("FAIL");
                std::process::exit(1);
            }
        }
        Commands::Tui => {
            let devices: Vec<DeviceInfo> = proxy.call("list_devices", &()).await?;
            match tui::run_baseline_editor(devices) {
                Ok(Some(baseline)) => {
                    let path: String = format!(
                        "baseline_{}.json",
                        chrono::Utc::now().format("%Y%m%dT%H%M%S")
                    );
                    fs::write(&path, serde_json::to_string_pretty(&baseline)?)?;
                    println!("Baseline draft saved: {}", path);
                    println!(
                        "You can now sign/apply this baseline using lusbyctl baseline sign/apply."
                    );
                }
                Ok(None) => println!("TUI cancelled."),
                Err(e) => eprintln!("TUI error: {}", e),
            }
        }
    }
    Ok(())
}
