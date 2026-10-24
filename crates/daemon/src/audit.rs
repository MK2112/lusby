use chrono::Utc;
use lusby_common::audit::{AuditEntry, AuditEntryPayload};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Size cap for the active audit log; when exceeded the log is rotated to
/// `<name>.1` and a fresh chain is started (each file verifies on its own)
const MAX_LOG_BYTES: u64 = 128 * 1024 * 1024;

/// Create the log directory with owner-only permissions when it is missing.
/// Pre-existing directories are left untouched: chmodding an arbitrary parent
/// (for example `/tmp` when tests log there) breaks shared directories.
/// Errors are propagated — audit setup is fail-closed
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

/// Chain head checkpoint next to the log (cheap startup resume + anchor)
fn head_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_os_string();
    p.push(".head");
    PathBuf::from(p)
}

#[derive(Debug)]
struct HeadCheckpoint {
    len: u64,
    last_offset: u64,
    hash: Option<String>,
}

#[derive(Debug)]
struct ScanResult {
    last_hash: Option<String>,
    last_offset: u64,
    clean_len: u64,
}

fn is_valid_hash(hash: &str) -> bool {
    hash.len() == 71
        && hash.starts_with("sha256:")
        && hash[7..].chars().all(|c| c.is_ascii_hexdigit())
}

fn read_head_file(path: &Path) -> Option<HeadCheckpoint> {
    let text = fs::read_to_string(head_path(path)).ok()?;
    let mut lines = text.lines();
    let len = lines.next()?.trim().parse().ok()?;
    let last_offset = lines.next()?.trim().parse().ok()?;
    let hash = lines.next().unwrap_or("").trim();
    if lines.next().is_some() || last_offset > len {
        return None;
    }
    let hash = if hash.is_empty() {
        None
    } else if is_valid_hash(hash) {
        Some(hash.to_string())
    } else {
        return None;
    };
    Some(HeadCheckpoint {
        len,
        last_offset,
        hash,
    })
}

fn write_head_file(path: &Path, hash: Option<&str>, last_offset: u64, len: u64) {
    let head = head_path(path);
    let mut tmp_os = head.as_os_str().to_os_string();
    tmp_os.push(".tmp");
    let tmp = PathBuf::from(tmp_os);
    let content = format!("{}\n{}\n{}\n", len, last_offset, hash.unwrap_or(""));
    let write = || -> std::io::Result<()> {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, &head)?;
        if let Some(dir) = head.parent() {
            if let Ok(d) = File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    };
    let _ = write();
}

/// A checkpoint is only trusted when it names the actual final log entry at
/// the recorded offset and length
fn head_matches_log(path: &Path, head: &HeadCheckpoint) -> bool {
    let file_len = match fs::metadata(path) {
        Ok(md) => md.len(),
        Err(_) => return head.len == 0 && head.hash.is_none(),
    };
    if head.len != file_len {
        return false;
    }
    if file_len == 0 {
        return head.last_offset == 0 && head.hash.is_none();
    }
    let Some(hash) = head.hash.as_deref() else {
        return false;
    };
    if head.last_offset >= head.len || !is_valid_hash(hash) {
        return false;
    }
    let remaining = head.len - head.last_offset;
    if remaining > 1024 * 1024 {
        return false;
    }
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    if f.seek(SeekFrom::Start(head.last_offset)).is_err() {
        return false;
    }
    let mut buf = vec![0u8; remaining as usize];
    if f.read_exact(&mut buf).is_err() {
        return false;
    }
    match serde_json::from_slice::<AuditEntry>(&buf) {
        Ok(entry) => entry.entry_hash == hash,
        Err(_) => false,
    }
}

/// Read the entry_hash of the last well-formed line so a restarted daemon
/// continues the hash chain instead of forking it with prev_hash=None
fn read_last_hash(path: &Path) -> std::io::Result<ScanResult> {
    let f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ScanResult {
                last_hash: None,
                last_offset: 0,
                clean_len: 0,
            })
        }
        Err(e) => return Err(e),
    };
    let mut reader = BufReader::new(f);
    let mut lines: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut offset = 0u64;
    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        lines.push((offset, buf.clone()));
        offset += n as u64;
    }
    let total = lines.len();
    let mut last_hash: Option<String> = None;
    let mut last_offset = 0u64;
    let mut clean_len = 0u64;
    for (i, (start, line)) in lines.iter().enumerate() {
        let is_last = i + 1 == total;
        let ends_with_newline = line.last() == Some(&b'\n');
        let end = start + line.len() as u64;
        let text = match std::str::from_utf8(line) {
            Ok(t) => t.trim(),
            Err(_) => {
                if is_last && !ends_with_newline {
                    break; // torn trailing write
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "audit log corrupt: invalid UTF-8 entry",
                ));
            }
        };
        if text.is_empty() {
            clean_len = end;
            continue;
        }
        match serde_json::from_str::<AuditEntry>(text) {
            Ok(entry) => {
                last_hash = Some(entry.entry_hash);
                last_offset = *start;
                clean_len = end;
            }
            Err(_) => {
                if is_last && !ends_with_newline {
                    break; // torn trailing write
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "audit log corrupt: unparsable entry",
                ));
            }
        }
    }
    Ok(ScanResult {
        last_hash,
        last_offset,
        clean_len,
    })
}

fn ensure_trailing_newline(path: &Path) -> std::io::Result<u64> {
    let len = match fs::metadata(path) {
        Ok(md) => md.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    if len == 0 {
        return Ok(0);
    }
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(len - 1))?;
    let mut last = [0u8; 1];
    f.read_exact(&mut last)?;
    if last[0] == b'\n' {
        return Ok(len);
    }
    let mut f = OpenOptions::new().append(true).open(path)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    Ok(len + 1)
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
        let last_hash = match read_head_file(&path) {
            Some(head) if head_matches_log(&path, &head) => head.hash,
            _ => {
                let file_len = fs::metadata(&path).map(|md| md.len()).unwrap_or(0);
                let scan = read_last_hash(&path)?;
                if scan.clean_len < file_len {
                    let f = OpenOptions::new().write(true).open(&path)?;
                    f.set_len(scan.clean_len)?;
                    f.sync_all()?;
                }
                let clean_len = ensure_trailing_newline(&path)?;
                write_head_file(
                    &path,
                    scan.last_hash.as_deref(),
                    scan.last_offset,
                    clean_len,
                );
                scan.last_hash
            }
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

    /// Append one entry to the tamper-evident chain
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
        let start = self.file.metadata().map(|md| md.len()).ok();
        writeln!(self.file, "{}", line)?;
        self.last_hash = Some(entry.entry_hash.clone());
        self.file.sync_all()?;
        if let (Some(last_offset), Ok(metadata)) = (start, self.file.metadata()) {
            write_head_file(
                &self.path,
                Some(&entry.entry_hash),
                last_offset,
                metadata.len(),
            );
        }
        Ok(())
    }

    /// Rotate an oversized log; the archived file keeps its own chain and the
    /// active log starts a new one
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
        write_head_file(&self.path, None, 0, 0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lusby_common::audit::verify_stream;
    use std::io::BufReader;

    fn log_two_entries(path: &Path) {
        let mut log = AuditLogger::new(path.to_path_buf()).unwrap();
        log.log("test", None, "one", None).unwrap();
        log.log("test", None, "two", None).unwrap();
    }

    fn entries(path: &Path) -> Vec<AuditEntry> {
        let text = fs::read_to_string(path).unwrap();
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn entry_offsets(path: &Path) -> Vec<(u64, u64)> {
        let text = fs::read_to_string(path).unwrap();
        let mut offset = 0u64;
        text.lines()
            .map(|line| {
                let start = offset;
                offset += line.len() as u64 + 1;
                (start, offset)
            })
            .collect()
    }

    fn assert_chain_len(path: &Path, expected: usize) {
        let f = File::open(path).unwrap();
        assert_eq!(verify_stream(BufReader::new(f)).unwrap(), expected);
    }

    #[test]
    fn stale_head_is_reconciled_from_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        log_two_entries(&path);

        let entries = entries(&path);
        let offsets = entry_offsets(&path);
        write_head_file(
            &path,
            Some(&entries[0].entry_hash),
            offsets[0].0,
            offsets[0].1,
        );

        let mut log = AuditLogger::new(path.clone()).unwrap();
        log.log("test", None, "three", None).unwrap();
        assert_chain_len(&path, 3);
    }

    #[test]
    fn same_length_head_with_wrong_hash_is_reconciled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        log_two_entries(&path);

        let entries = entries(&path);
        let offsets = entry_offsets(&path);
        write_head_file(
            &path,
            Some(&entries[0].entry_hash),
            offsets[1].0,
            offsets[1].1,
        );

        let mut log = AuditLogger::new(path.clone()).unwrap();
        log.log("test", None, "three", None).unwrap();
        assert_chain_len(&path, 3);
    }

    #[test]
    fn torn_trailing_entry_is_truncated_before_append() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        log_two_entries(&path);

        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(br#"{"payload":"torn"#).unwrap();
        f.sync_all().unwrap();
        drop(f);

        let mut log = AuditLogger::new(path.clone()).unwrap();
        log.log("test", None, "three", None).unwrap();
        assert_chain_len(&path, 3);
    }
}
