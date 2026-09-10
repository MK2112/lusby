use chrono::Utc;
use lusby_common::audit::{AuditEntry, AuditEntryPayload};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

#[derive(Clone)]
pub struct AuditLogger {
    path: PathBuf,
    last_hash: Option<String>,
}

fn tight_dir(dir: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(dir) {
            Ok(_) => (),
            Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Harden pre-existing directories as well (fail-closed perms).
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
                }
            }
            Err(e) => {
                eprintln!("Failed to create audit log dir {}: {}", dir.display(), e);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = fs::create_dir_all(dir);
    }
}

/// Read the entry_hash of the last non-empty line so a restarted daemon
/// continues the hash chain instead of forking it with prev_hash=None.
fn read_last_hash(path: &std::path::Path) -> Option<String> {
    let f = fs::File::open(path).ok()?;
    let reader = BufReader::new(f);
    let mut last: Option<String> = None;
    for line in reader.lines() {
        let line = line.ok()?;
        if line.trim().is_empty() {
            continue;
        }
        // Only accept well-formed entries; ignore torn trailing lines.
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
            last = Some(entry.entry_hash);
        }
    }
    last
}

impl AuditLogger {
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            tight_dir(dir);
        }
        let last_hash = read_last_hash(&path);
        // Ensure the log file exists with owner-only permissions.
        if fs::metadata(&path).is_err() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let _ = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .open(&path)?;
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            }
            #[cfg(not(unix))]
            {
                let _ = OpenOptions::new().create(true).append(true).open(&path)?;
            }
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            }
        }
        Ok(Self { path, last_hash })
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

        // Synchronous, serialized write: callers hold the Mutex<AuditLogger>
        // across this call, so file order always matches hash-chain order.
        // (The previous fire-and-forget thread per entry could reorder lines
        // and break `verify_chain`.)
        let line = match serde_json::to_string(&entry) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Failed to serialize audit entry: {}", e);
                return;
            }
        };
        for attempt in 1..=3u32 {
            let open = {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .mode(0o600)
                        .open(&self.path)
                }
                #[cfg(not(unix))]
                {
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&self.path)
                }
            };
            match open {
                Ok(mut f) => match writeln!(f, "{}", line) {
                    Ok(_) => {
                        if let Err(e) = f.sync_all() {
                            eprintln!("Failed to sync audit log: {}", e);
                        }
                        return;
                    }
                    Err(e) => {
                        eprintln!("Failed to write audit entry (attempt {}): {}", attempt, e);
                    }
                },
                Err(e) => {
                    eprintln!("Failed to open audit log file (attempt {}): {}", attempt, e);
                }
            }
        }
        eprintln!(
            "CRITICAL: Failed to write audit log entry after 3 retries. Event: {} Action: {}",
            event_type, action
        );
    }
}
