use chrono::Utc;
use lusby_common::audit::{AuditEntry, AuditEntryPayload};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// Size cap for the active audit log; when exceeded the log is rotated to
/// `<name>.1` and a fresh chain is started (each file verifies on its own).
const MAX_LOG_BYTES: u64 = 128 * 1024 * 1024;

/// Create the log directory with owner-only permissions when it is missing.
/// Pre-existing directories are left untouched: chmodding an arbitrary parent
/// (for example `/tmp` when tests log there) breaks shared directories.
/// Errors are propagated — audit setup is fail-closed.
fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        match fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {
                // DirBuilder's mode is umask-masked; set it explicitly.
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e),
        }
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

/// Chain head checkpoint next to the log (cheap startup resume + anchor).
fn head_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_os_string();
    p.push(".head");
    PathBuf::from(p)
}

fn read_head_file(path: &Path) -> Option<String> {
    let text = fs::read_to_string(head_path(path)).ok()?;
    let t = text.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn write_head_file(path: &Path, hash: &str) {
    // Best-effort checkpoint: the log itself stays authoritative.
    let _ = fs::write(head_path(path), format!("{}\n", hash));
}

/// Read the entry_hash of the last well-formed line so a restarted daemon
/// continues the hash chain instead of forking it with prev_hash=None.
///
/// Fail closed on corruption: a damaged line in the *middle* of the log is an
/// error (silently starting a fresh chain would fork the log and make every
/// later entry unverifiable). Only a torn *final* line (crash during append)
/// is tolerated.
fn read_last_hash(path: &Path) -> std::io::Result<Option<String>> {
    let f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut reader = BufReader::new(f);
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        lines.push(buf.clone());
    }
    let total = lines.len();
    let mut last: Option<String> = None;
    for (i, line) in lines.iter().enumerate() {
        let is_last = i + 1 == total;
        let text = match std::str::from_utf8(line) {
            Ok(t) => t.trim(),
            Err(_) => {
                if is_last {
                    break; // torn trailing write
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "audit log corrupt: invalid UTF-8 entry",
                ));
            }
        };
        if text.is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEntry>(text) {
            Ok(entry) => last = Some(entry.entry_hash),
            Err(_) => {
                if is_last {
                    break; // torn trailing write
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "audit log corrupt: unparsable entry",
                ));
            }
        }
    }
    Ok(last)
}

pub struct AuditLogger {
    path: PathBuf,
    file: File,
    last_hash: Option<String>,
}

impl AuditLogger {
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            ensure_private_dir(dir)?;
        }
        // Prefer the head checkpoint over a full scan (large logs would slow
        // startup); fall back to a fail-closed scan when it is missing.
        let last_hash = match read_head_file(&path) {
            Some(h) => Some(h),
            None => read_last_hash(&path)?,
        };
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self {
            path,
            file,
            last_hash,
        })
    }

    /// Append one entry to the tamper-evident chain.
    ///
    /// Returns Err when the entry could not be appended or made durable;
    /// callers handling sensitive actions must treat that as a denial
    /// (fail-closed auditing). The chain head only advances after the entry
    /// has been appended, so a failed write cannot fork the chain.
    pub fn log(
        &mut self,
        event_type: &str,
        device_fingerprint: Option<String>,
        action: &str,
        requester_uid: Option<u32>,
    ) -> std::io::Result<()> {
        self.maybe_rotate()?;
        let payload = AuditEntryPayload {
            timestamp: Utc::now(),
            event_type: event_type.into(),
            device_fingerprint,
            action: action.into(),
            requester_uid,
        };
        let prev = self.last_hash.clone();
        let entry = AuditEntry::new(prev, payload);
        let line = serde_json::to_string(&entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        writeln!(self.file, "{}", line)?;
        // The entry is appended now; advance the chain head before syncing so
        // the on-disk chain stays consistent even if the sync reports trouble.
        self.last_hash = Some(entry.entry_hash.clone());
        write_head_file(&self.path, &entry.entry_hash);
        // Durability is the point of the log: surface sync failures instead of
        // pretending the entry is safely recorded.
        self.file.sync_all()?;
        Ok(())
    }

    /// Rotate an oversized log; the archived file keeps its own chain and the
    /// active log starts a new one.
    fn maybe_rotate(&mut self) -> std::io::Result<()> {
        let len = self.file.metadata()?.len();
        if len <= MAX_LOG_BYTES {
            return Ok(());
        }
        let mut archived = self.path.clone().into_os_string();
        archived.push(".1");
        let archived = PathBuf::from(archived);
        let _ = fs::remove_file(&archived);
        // Reopen after the rename: our handle still points at the archived file.
        fs::rename(&self.path, &archived)?;
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        self.file = opts.open(&self.path)?;
        self.last_hash = None;
        write_head_file(&self.path, "");
        Ok(())
    }
}
