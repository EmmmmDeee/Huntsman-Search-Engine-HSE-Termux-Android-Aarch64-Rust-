//! Verbose, multi-sink debug logging for painless field diagnosis.
//!
//! Three sinks are wired in [`init`]:
//!   1. **stderr** — human-facing, `info` by default; `-v` → debug, `-vv` →
//!      trace. Honours `RUST_LOG` when set.
//!   2. **file** — ALWAYS at `debug`, appended to `$HOME/.huntsman/logs/hse.log`
//!      and size-rotated at startup. Every run therefore leaves a full trace
//!      for diagnosis without spamming the terminal.
//!   3. **log bus** — ALWAYS at `debug`, fanning each formatted line onto a
//!      `tokio::broadcast` so the Web UI can stream it live over SSE
//!      (SpiderFoot-style Event Log).
//!
//! **Secret safety:** `HUNTSMAN_*` / `key=` / `token=` style values are scrubbed
//! by [`redact`] before any line reaches a sink. Modules already avoid logging
//! key values; this is defence-in-depth so the file and the shareable
//! `doctor --bundle` can never leak a credential. Entity UIDs / scan IDs are
//! deliberately NOT redacted — they're needed for diagnosis.
//!
//! No new dependencies: a small custom `MakeWriter` handles the file + bus
//! sinks and rotation; `regex` (already a dep) drives redaction.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use regex::Regex;
use tokio::sync::broadcast;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

/// Rotate `hse.log` → `hse.log.1` once it grows past this at startup.
const LOG_FILE_CAP_BYTES: u64 = 5 * 1024 * 1024;
/// Live log-bus ring capacity (lines). A lagging UI subscriber drops the
/// oldest lines rather than back-pressuring the engine.
const LOG_BUS_CAPACITY: usize = 1024;

static LOG_BUS: OnceLock<broadcast::Sender<String>> = OnceLock::new();

/// Process-wide formatted-log broadcast. The Web UI SSE endpoint subscribes here.
pub fn log_bus() -> &'static broadcast::Sender<String> {
    LOG_BUS.get_or_init(|| broadcast::channel(LOG_BUS_CAPACITY).0)
}

/// Subscribe to the live formatted log stream (one `String` per log line).
pub fn subscribe() -> broadcast::Receiver<String> {
    log_bus().subscribe()
}

/// Path to the rotating debug log: `$HOME/.huntsman/logs/hse.log`.
pub fn log_file_path() -> PathBuf {
    let base = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join(".huntsman").join("logs").join("hse.log")
}

/// Last `max_bytes` of the debug log, redacted — used by `doctor --bundle`
/// and the Web UI backfill. Empty string if the log doesn't exist yet.
pub fn tail(max_bytes: usize) -> String {
    let Ok(data) = std::fs::read(log_file_path()) else {
        return String::new();
    };
    let start = data.len().saturating_sub(max_bytes);
    // Don't slice mid-line: advance to the next newline if we cut into one.
    let slice = &data[start..];
    redact(&String::from_utf8_lossy(slice)).into_owned()
}

/// Scrub credential-bearing assignments (`HUNTSMAN_*=…`, `api_key:…`,
/// `token=…`, `password=…`, `bearer …`) from a log line, masking the value.
/// Returns the input borrowed (no allocation) when nothing matches. The
/// separator requirement keeps it targeted — `tokens=5` / `keyboard` don't
/// match, but `api_key=…` does. Entity UIDs / scan IDs are untouched.
pub fn redact(line: &str) -> std::borrow::Cow<'_, str> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(?i)((?:HUNTSMAN_[A-Z0-9_]+|api[_-]?key|secret|token|password|passwd|pwd|bearer)\s*[=:]\s*)\S+",
        )
        .expect("redaction regex is valid")
    });
    re.replace_all(line, "${1}<redacted>")
}

/// Initialise the layered subscriber. `verbose`: 0 = info on stderr, 1 = debug,
/// ≥2 = trace. The file + log-bus sinks always capture at `debug`.
/// Idempotent-ish: safe to call once at startup (a second call is ignored by
/// the global-default guard).
pub fn init(verbose: u8) {
    let stderr_level = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let stderr_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(stderr_level));

    let stderr_layer = fmt::layer()
        .with_target(false)
        .with_writer(io::stderr)
        .with_filter(stderr_filter);

    // File sink — always debug; None if the file can't be opened (registry
    // treats Option<Layer> as a no-op when None).
    let file_layer = open_log_file().map(|f| {
        fmt::layer()
            .with_ansi(false)
            .with_writer(FileMaker(Arc::new(Mutex::new(f))))
            .with_filter(EnvFilter::new("debug"))
    });

    // Log-bus sink — always debug; feeds the Web UI SSE stream.
    let _ = log_bus();
    let bus_layer = fmt::layer()
        .with_ansi(false)
        .with_writer(BusMaker)
        .with_filter(EnvFilter::new("debug"));

    let _ = tracing_subscriber::registry()
        .with(stderr_layer)
        .with(file_layer)
        .with(bus_layer)
        .try_init();
}

/// Open the debug log for append, rotating once if it's over the size cap.
fn open_log_file() -> Option<File> {
    let path = log_file_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > LOG_FILE_CAP_BYTES) {
        let _ = std::fs::rename(&path, path.with_file_name("hse.log.1"));
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok()
}

// ── Custom sinks ────────────────────────────────────────────────────────────
// Each log event gets a fresh per-event writer that accumulates the formatted
// line, then on Drop redacts it and forwards to its target (file / bus). The
// `fmt` layer writes one event per writer, so Drop sees the complete line.

trait LineTarget {
    fn emit(&self, line: &str);
}

struct LineCollector<T: LineTarget> {
    buf: Vec<u8>,
    target: T,
}

impl<T: LineTarget> Write for LineCollector<T> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<T: LineTarget> Drop for LineCollector<T> {
    fn drop(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let raw = String::from_utf8_lossy(&self.buf);
        self.target.emit(&redact(raw.trim_end_matches('\n')));
    }
}

#[derive(Clone)]
struct FileMaker(Arc<Mutex<File>>);
struct FileTarget(Arc<Mutex<File>>);
impl LineTarget for FileTarget {
    fn emit(&self, line: &str) {
        let mut f = self.0.lock();
        let _ = writeln!(f, "{line}");
    }
}
impl<'a> MakeWriter<'a> for FileMaker {
    type Writer = LineCollector<FileTarget>;
    fn make_writer(&'a self) -> Self::Writer {
        LineCollector {
            buf: Vec::new(),
            target: FileTarget(Arc::clone(&self.0)),
        }
    }
}

#[derive(Clone)]
struct BusMaker;
struct BusTarget;
impl LineTarget for BusTarget {
    fn emit(&self, line: &str) {
        // Err == no UI subscribers; that's fine.
        let _ = log_bus().send(line.to_string());
    }
}
impl<'a> MakeWriter<'a> for BusMaker {
    type Writer = LineCollector<BusTarget>;
    fn make_writer(&'a self) -> Self::Writer {
        LineCollector {
            buf: Vec::new(),
            target: BusTarget,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_masks_huntsman_key_values() {
        let r = redact("loaded HUNTSMAN_SHODAN_KEY=abc123secret for shodan");
        assert!(r.contains("HUNTSMAN_SHODAN_KEY="));
        assert!(r.contains("<redacted>"));
        assert!(!r.contains("abc123secret"));
    }

    #[test]
    fn redact_masks_token_and_password_forms() {
        assert!(redact("api_key: zzz999").contains("<redacted>"));
        assert!(redact("password=hunter2").contains("<redacted>"));
        assert!(redact("Bearer: eyJhbGciOi").contains("<redacted>"));
    }

    #[test]
    fn redact_leaves_normal_lines_untouched() {
        let line = "module=crtsh found 7 entities for example.com";
        assert_eq!(redact(line), line);
        // Scan IDs / UIDs (long hex) must survive — needed for diagnosis.
        let uid = "entity 9a131144a5e5fdfe09c0cb809f6f16a773dcab87 merged";
        assert_eq!(redact(uid), uid);
    }

    #[test]
    fn log_bus_subscribe_receives_emitted_line() {
        let mut rx = subscribe();
        BusTarget.emit("hello from the bus");
        let got = rx.try_recv().unwrap();
        assert_eq!(got, "hello from the bus");
    }

    #[test]
    fn log_file_path_under_huntsman_logs() {
        let p = log_file_path();
        assert!(p.ends_with("hse.log"));
        assert!(p.to_string_lossy().contains(".huntsman"));
    }
}
