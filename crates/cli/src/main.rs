use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use clap::Parser;
use ed25519_dalek::{SigningKey, VerifyingKey};
use lusby_common::audit::verify_stream;
use lusby_common::baseline::{Baseline, DeviceEntry};
use lusby_common::types::DeviceInfo;
use lusbyctl::{AuditCmd, BaselineCmd, Cli, Commands, KeysCmd};
use rand::rngs::OsRng;
use std::fs;
use std::io::Write as _;
use zbus::Connection;
use zeroize::Zeroizing;

mod tui;

const MAX_BASELINE_BYTES: u64 = 1024 * 1024;

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

/// Write a secret to a new file with owner-only permissions.
fn write_secret_file(path: &std::path::Path, secret_b64: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(secret_b64.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    Ok(())
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
            match proxy
                .call::<_, _, DeviceInfo>("GetDeviceInfo", &(device,))
                .await
            {
                Ok(info) => println!("{}", serde_json::to_string_pretty(&info)?),
                Err(e) => {
                    eprintln!("device not found: {}", e);
                    std::process::exit(1);
                }
            }
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
                BaselineCmd::Keygen {
                    secret_out,
                    print_secret,
                } => {
                    let sk = SigningKey::generate(&mut OsRng);
                    let pk = sk.verifying_key();
                    let secret_bytes = Zeroizing::new(sk.to_bytes());
                    let secret_b64 = Zeroizing::new(B64.encode(*secret_bytes));
                    if print_secret {
                        println!("SECRET_B64={}", *secret_b64);
                    } else {
                        let path = secret_out
                            .unwrap_or_else(|| std::path::PathBuf::from("lusby_signing.key"));
                        write_secret_file(&path, &secret_b64)?;
                        println!("SECRET_FILE={}", path.display());
                        println!(
                            "(secret written with mode 0600; pass --print-secret to print it instead)"
                        );
                    }
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
                        (None, Some(f)) => {
                            // Refuse secrets from group/world-accessible files.
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                let mode = fs::metadata(&f)?.permissions().mode();
                                if mode & 0o077 != 0 {
                                    anyhow::bail!(
                                        "secret file {} is group/world accessible (mode {:o}); fix with: chmod 600 {}",
                                        f.display(),
                                        mode & 0o777,
                                        f.display()
                                    );
                                }
                            }
                            fs::read_to_string(&f)?.trim().to_string()
                        }
                        (None, None) => anyhow::bail!(
                            "no secret provided (use --secret-b64, --secret-file, or LUSBY_SECRET_B64)"
                        ),
                        _ => unreachable!("clap conflicts"),
                    };
                    // Keep every secret-bearing buffer in zeroizing memory.
                    let b64_secret = Zeroizing::new(b64_secret);
                    let secret = Zeroizing::new(B64.decode(b64_secret.trim())?);
                    if secret.len() != 32 {
                        anyhow::bail!("secret must be 32 raw bytes in base64");
                    }
                    let secret_array = Zeroizing::new(<[u8; 32]>::try_from(secret.as_slice())?);
                    let sk = SigningKey::from_bytes(&secret_array);
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
                    let conn = system_conn().await?;
                    let proxy = system_proxy(&conn).await?;
                    let info: DeviceInfo = match proxy.call("GetDeviceInfo", &(device,)).await {
                        Ok(i) => i,
                        Err(e) => {
                            eprintln!("device not found: {}", e);
                            std::process::exit(1);
                        }
                    };
                    let dev = DeviceEntry {
                        vendor_id: info.vendor_id.clone(),
                        product_id: info.product_id.clone(),
                        serial: serial.or({
                            if info.serial.is_empty() {
                                None
                            } else {
                                Some(info.serial.clone())
                            }
                        }),
                        bus_path: None,
                        // Identity binding data captured from the live device.
                        descriptors_hash: info.usbguard_hash.clone(),
                        device_type: info.device_type.clone(),
                        interfaces: info.interfaces.clone(),
                        comment,
                    };
                    let baseline = Baseline {
                        version: 1,
                        created_by: whoami::username(),
                        created_at: Utc::now(),
                        expires_at: None,
                        devices: vec![dev],
                        signature: None,
                    };
                    // Fail early instead of producing a draft the daemon rejects.
                    baseline.validate().map_err(|e| anyhow::anyhow!(e))?;
                    fs::write(&output, serde_json::to_string_pretty(&baseline)?)?;
                    println!("Baseline draft written: {}", output.display());
                }
                BaselineCmd::Apply { file, signer } => {
                    let data = fs::read(&file)?;
                    if data.len() as u64 > MAX_BASELINE_BYTES {
                        anyhow::bail!("baseline file too large (max 1 MiB)");
                    }
                    // The baseline travels over D-Bus as bytes: the daemon runs
                    // in a sandbox that cannot see the user's home or /tmp.
                    let conn = system_conn().await?;
                    let proxy = system_proxy(&conn).await?;
                    let ok: bool = proxy.call("ApplyPersistentAllow", &(data, signer)).await?;
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
                // Streaming verification: constant memory even for huge logs.
                let f = fs::File::open(&file)?;
                let reader = std::io::BufReader::new(f);
                match verify_stream(reader) {
                    Ok(n) => println!("OK ({} entries)", n),
                    Err(e) => {
                        eprintln!("FAIL: {}", e);
                        std::process::exit(1);
                    }
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
                    // The TUI validates too, but never persist a draft the
                    // daemon would reject.
                    baseline.validate().map_err(|e| anyhow::anyhow!(e))?;
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
