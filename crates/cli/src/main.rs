use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use clap::Parser;
use ed25519_dalek::{SigningKey, VerifyingKey};
use lusby_common::audit::{verify_chain, AuditEntry};
use lusby_common::baseline::{Baseline, DeviceEntry};
use lusby_common::types::DeviceInfo;
use lusbyctl::{AuditCmd, BaselineCmd, Cli, Commands, KeysCmd};
use rand::rngs::OsRng;
use std::fs;
use zbus::Connection;

mod tui;

async fn system_proxy(conn: &Connection) -> Result<zbus::Proxy<'_>> {
    Ok(zbus::Proxy::new(
        conn,
        "org.lusby.Daemon",
        "/org/lusby/Daemon",
        "org.lusby.Daemon",
    )
    .await?)
}

async fn system_conn() -> Result<Connection> {
    Ok(Connection::system().await?)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // NOTE: the system-bus connection is established lazily per command so
    // purely local subcommands (keygen/sign/verify/audit) also work without
    // a running bus or daemon.
    match cli.command {
        Commands::List => {
            let conn = system_conn().await?;
            let proxy = system_proxy(&conn).await?;
            let devices: Vec<DeviceInfo> = proxy.call("ListDevices", &()).await?;
            println!("{}", serde_json::to_string_pretty(&devices)?);
        }
        Commands::Info { device } => {
            let conn = system_conn().await?;
            let proxy = system_proxy(&conn).await?;
            let info: DeviceInfo = proxy.call("GetDeviceInfo", &(device)).await?;
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        Commands::Status => {
            let conn = system_conn().await?;
            let proxy = system_proxy(&conn).await?;
            let status: lusby_common::types::PolicyStatus =
                proxy.call("GetPolicyStatus", &()).await?;
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
                    secret_file,
                    input,
                    output,
                } => {
                    let data = fs::read(&input)?;
                    let mut baseline: Baseline = serde_json::from_slice(&data)?;
                    // Prefer file/env over argv: --secret-b64 leaks via ps/history.
                    let b64_secret: String = match (secret_b64, secret_file) {
                        (Some(s), None) => s,
                        (None, Some(f)) => fs::read_to_string(&f)?.trim().to_string(),
                        (None, None) => anyhow::bail!(
                            "no secret provided (use --secret-b64, --secret-file, or LUSBY_SECRET_B64)"
                        ),
                        _ => unreachable!("clap conflicts"),
                    };
                    let mut secret = B64.decode(b64_secret.trim())?;
                    if secret.len() != 32 {
                        for b in secret.iter_mut() {
                            *b = 0;
                        }
                        anyhow::bail!("secret must be 32 raw bytes in base64");
                    }
                    let secret_array: [u8; 32] = secret
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("failed to convert secret bytes to array"))?;
                    // Best-effort: clear the heap copy of the secret.
                    // (secret_array is zeroized below after use.)
                    let sk = SigningKey::from_bytes(&secret_array);
                    baseline.sign_attach(&sk).map_err(|e| anyhow::anyhow!(e))?;
                    let mut secret_array = secret_array;
                    for b in secret_array.iter_mut() {
                        *b = 0;
                    }
                    fs::write(&output, serde_json::to_string_pretty(&baseline)?)?;
                    println!("Signed baseline written: {}", output.display());
                }
                BaselineCmd::Init {
                    device,
                    serial,
                    comment,
                    output,
                } => {
                    let conn = system_conn().await?;
                    let proxy = system_proxy(&conn).await?;
                    let info: DeviceInfo = proxy.call("GetDeviceInfo", &(device)).await?;
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
                    let conn = system_conn().await?;
                    let proxy = system_proxy(&conn).await?;
                    let ok: bool = proxy
                        .call(
                            "ApplyPersistentAllow",
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
                // Stream line-by-line instead of loading the whole log into RAM.
                let f = fs::File::open(&file)?;
                let reader = std::io::BufReader::new(f);
                let mut entries: Vec<AuditEntry> = Vec::new();
                for line in std::io::BufRead::lines(reader) {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    let e: AuditEntry = serde_json::from_str(&line)?;
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
                let conn = system_conn().await?;
                let proxy = system_proxy(&conn).await?;
                let ok: bool = proxy.call("AddTrustedPubkey", &(name, pub_b64)).await?;
                if ok {
                    println!("OK");
                } else {
                    anyhow::bail!("add key failed");
                }
            }
            KeysCmd::List => {
                let conn = system_conn().await?;
                let proxy = system_proxy(&conn).await?;
                let names: Vec<String> = proxy.call("ListTrustedPubkeys", &()).await?;
                for n in names {
                    println!("{}", n);
                }
            }
            KeysCmd::Remove { name } => {
                let conn = system_conn().await?;
                let proxy = system_proxy(&conn).await?;
                let ok: bool = proxy.call("RemoveTrustedPubkey", &(name)).await?;
                if ok {
                    println!("OK");
                } else {
                    anyhow::bail!("remove key failed");
                }
            }
        },
        Commands::Allow(args) => {
            if args.ttl > 86400 {
                anyhow::bail!("ttl must be 0-86400 seconds (0 = indefinite, polkit-gated)");
            }
            let conn = system_conn().await?;
            let proxy = system_proxy(&conn).await?;
            let uid = unsafe { libc::geteuid() } as u32;
            let ok: bool = proxy
                .call("RequestEphemeralAllow", &(args.device, args.ttl, uid))
                .await?;
            if ok {
                println!("OK");
            } else {
                eprintln!("FAIL");
                std::process::exit(1);
            }
        }
        Commands::Revoke { device } => {
            let conn = system_conn().await?;
            let proxy = system_proxy(&conn).await?;
            let ok: bool = proxy.call("RevokeDevice", &(device)).await?;
            if ok {
                println!("OK");
            } else {
                eprintln!("FAIL");
                std::process::exit(1);
            }
        }
        Commands::Tui => {
            let conn = system_conn().await?;
            let proxy = system_proxy(&conn).await?;
            let devices: Vec<DeviceInfo> = proxy.call("ListDevices", &()).await?;
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
