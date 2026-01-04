use chrono::Utc;
use lusby_common::audit::{AuditEntry, AuditEntryPayload};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[derive(Clone)]
pub struct AuditLogger {
    path: PathBuf,
    last_hash: Option<String>,
}

impl AuditLogger {
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            // Audit-Log-Verzeichnis mit restriktiven Berechtigungen anlegen
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                match builder.create(dir) {
                    Ok(_) => (),
                    Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                    Err(e) => return Err(e),
                }
            }
            #[cfg(not(unix))]
            {
                fs::create_dir_all(dir)?;
            }
        }
        Ok(Self {
            path,
            last_hash: None,
        })
    }

    pub fn log(
        &mut self,
        event_type: &str,
        device_fingerprint: Option<String>,
        action: &str,
        requester_uid: Option<u32>,
    ) {
        let payload = AuditEntryPayload {
            timestamp: Utc::now(),
            event_type: event_type.into(),
            device_fingerprint,
            action: action.into(),
            requester_uid,
        };
        let prev = self.last_hash.clone();
        let entry = AuditEntry::new(prev, payload);
        self.last_hash = Some(entry.entry_hash.clone());

        let entry_clone = entry.clone();
        let path = self.path.clone();
        let event_type_str = event_type.to_string();
        let action_str = action.to_string();

        std::thread::spawn(move || {
            let mut retry_count = 0;
            const MAX_RETRIES: u32 = 3;

            while retry_count < MAX_RETRIES {
                match OpenOptions::new().create(true).append(true).open(&path) {
                    Ok(mut f) => {
                        if let Ok(line) = serde_json::to_string(&entry_clone) {
                            match writeln!(f, "{}", line) {
                                Ok(_) => {
                                    if let Err(e) = f.sync_all() {
                                        eprintln!("Failed to sync audit log: {}", e);
                                    }
                                    return;
                                }
                                Err(e) => {
                                    eprintln!(
                                        "Failed to write audit entry (attempt {}): {}",
                                        retry_count + 1,
                                        e
                                    );
                                    retry_count += 1;
                                    if retry_count < MAX_RETRIES {
                                        std::thread::sleep(std::time::Duration::from_millis(
                                            100 * (retry_count as u64),
                                        ));
                                    }
                                }
                            }
                        } else {
                            eprintln!(
                                "Failed to serialize audit entry (attempt {})",
                                retry_count + 1
                            );
                            retry_count += 1;
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "Failed to open audit log file (attempt {}): {}",
                            retry_count + 1,
                            e
                        );
                        retry_count += 1;
                        if retry_count < MAX_RETRIES {
                            std::thread::sleep(std::time::Duration::from_millis(
                                100 * (retry_count as u64),
                            ));
                        }
                    }
                }
            }

            if retry_count >= MAX_RETRIES {
                eprintln!("CRITICAL: Failed to write audit log entry after {} retries. Event: {} Action: {}", MAX_RETRIES, event_type_str, action_str);
            }
        });
    }
}
