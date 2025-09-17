use chrono::Utc;
use guardianusb_common::audit::{AuditEntry, AuditEntryPayload};
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
        // Best-effort write
        if let Ok(mut f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            if let Ok(line) = serde_json::to_string(&entry) {
                let _ = writeln!(f, "{}", line);
            }
        }
    }
}
