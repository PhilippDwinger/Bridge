//! Log files with rotation (ADR 0017): every node's output and the app's own log.
//!
//! - One line at a time, control characters removed, at most [`MAX_LINE_CHARS`] characters per line.
//! - When the file would grow past its limit, it becomes `<name>.1` (older ones move up to `.<keep>`, the oldest
//!   goes): the disk use of a log is bounded by `(keep + 1) × max_bytes`.
//! - Nothing secret is ever written here: nodes never see the 24 words, the app never logs request bodies, tokens or
//!   invite links.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Longest line kept (longer lines are cut).
pub const MAX_LINE_CHARS: usize = 4096;
/// Default size of one log file before it rotates.
pub const DEFAULT_MAX_BYTES: u64 = 2 * 1024 * 1024;
/// Default number of rotated files kept.
pub const DEFAULT_KEEP: u32 = 3;
/// Most bytes read from the end of a log for the log view.
pub const MAX_TAIL_BYTES: u64 = 256 * 1024;

/// A log file that rotates by size (cheap to clone; clones share the file).
#[derive(Clone)]
pub struct RotatingLog {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    path: PathBuf,
    max_bytes: u64,
    keep: u32,
    file: Option<File>,
    size: u64,
}

impl RotatingLog {
    /// A log at `path` (folder made if needed), rotating at `max_bytes`, keeping `keep` old files.
    pub fn open(path: &Path, max_bytes: u64, keep: u32) -> Result<Self, String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let mut inner =
            Inner { path: path.to_owned(), max_bytes: max_bytes.max(1024), keep: keep.max(1), file: None, size: 0 };
        inner.reopen()?;
        Ok(Self { inner: Arc::new(Mutex::new(inner)) })
    }

    /// Appends one line (cleaned and bounded). Errors are swallowed: a full disk must not stop a node.
    pub fn line(&self, text: &str) {
        let mut line = clean(text);
        line.push('\n');
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.write(line.as_bytes());
    }

    /// The file being written now.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).path.clone()
    }
}

impl Inner {
    fn reopen(&mut self) -> Result<(), String> {
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(&self.path).map_err(|e| format!("{}: {e}", self.path.display()))?;
        self.size = file.metadata().map(|meta| meta.len()).unwrap_or(0);
        self.file = Some(file);
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) {
        if self.size.saturating_add(bytes.len() as u64) > self.max_bytes && self.size > 0 {
            self.rotate();
        }
        if self.file.is_none() && self.reopen().is_err() {
            return;
        }
        if let Some(file) = self.file.as_mut() {
            if file.write_all(bytes).is_ok() {
                self.size = self.size.saturating_add(bytes.len() as u64);
            }
        }
    }

    fn rotate(&mut self) {
        self.file = None;
        let numbered = |n: u32| {
            let mut name = self.path.clone().into_os_string();
            name.push(format!(".{n}"));
            PathBuf::from(name)
        };
        let _ = std::fs::remove_file(numbered(self.keep));
        for n in (1..self.keep).rev() {
            let _ = std::fs::rename(numbered(n), numbered(n + 1));
        }
        let _ = std::fs::rename(&self.path, numbered(1));
        let _ = self.reopen();
    }
}

/// A line without control characters (tabs become spaces), at most [`MAX_LINE_CHARS`] characters.
#[must_use]
pub fn clean(text: &str) -> String {
    text.trim_end_matches(['\r', '\n'])
        .chars()
        .map(|c| if c == '\t' { ' ' } else { c })
        .filter(|c| !c.is_control())
        .take(MAX_LINE_CHARS)
        .collect()
}

/// The last `lines` lines of the log at `path` (read from at most the last [`MAX_TAIL_BYTES`] bytes; none if the
/// file is missing).
#[must_use]
pub fn tail(path: &Path, lines: usize) -> Vec<String> {
    let Ok(mut file) = File::open(path) else { return Vec::new() };
    let length = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    let start = length.saturating_sub(MAX_TAIL_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut bytes = Vec::new();
    if file.take(MAX_TAIL_BYTES).read_to_end(&mut bytes).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut all: Vec<&str> = text.lines().collect();
    if start > 0 && !all.is_empty() {
        all.remove(0); // probably cut in the middle
    }
    let skip = all.len().saturating_sub(lines);
    all.into_iter().skip(skip).map(clean).collect()
}

/// A [`tracing_subscriber`] writer into a rotating log (the app's own log).
#[derive(Clone)]
pub struct LogWriter(pub RotatingLog);

/// One write of the app log (a whole formatted event; split into lines).
pub struct LogLine {
    log: RotatingLog,
    buffer: Vec<u8>,
}

impl std::io::Write for LogLine {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let room = (64 * 1024usize).saturating_sub(self.buffer.len());
        self.buffer.extend_from_slice(&bytes[..bytes.len().min(room)]);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for LogLine {
    fn drop(&mut self) {
        for line in String::from_utf8_lossy(&self.buffer).lines() {
            self.log.line(line);
        }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogWriter {
    type Writer = LogLine;
    fn make_writer(&'a self) -> Self::Writer {
        LogLine { log: self.0.clone(), buffer: Vec::new() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_and_bounds_disk_use() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let path = dir.path().join("logs").join("node.log");
        let log = RotatingLog::open(&path, 2048, 2)?;
        for n in 0..400 {
            log.line(&format!("line {n:04} {}", "x".repeat(40)));
        }
        let names: Vec<String> = std::fs::read_dir(dir.path().join("logs"))
            .map_err(|e| e.to_string())?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(names.len(), 3, "current + 2 kept: {names:?}");
        for name in &names {
            let size = std::fs::metadata(dir.path().join("logs").join(name)).map_err(|e| e.to_string())?.len();
            assert!(size <= 2048, "{name}: {size}");
        }
        let last = tail(&path, 2);
        assert_eq!(last.len(), 2);
        assert!(last[1].starts_with("line 0399"), "{last:?}");
        Ok(())
    }

    #[test]
    fn lines_are_cleaned_and_bounded() -> Result<(), String> {
        assert_eq!(clean("a\u{1b}[31mb\tc\r\n"), "a[31mb c");
        assert_eq!(clean(&"y".repeat(10_000)).len(), MAX_LINE_CHARS);
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let path = dir.path().join("a.log");
        let log = RotatingLog::open(&path, DEFAULT_MAX_BYTES, DEFAULT_KEEP)?;
        log.line("eins\nzwei");
        assert_eq!(tail(&path, 10), vec!["einszwei".to_owned()], "a line stays one line");
        assert!(tail(&dir.path().join("missing.log"), 10).is_empty());
        Ok(())
    }
}
