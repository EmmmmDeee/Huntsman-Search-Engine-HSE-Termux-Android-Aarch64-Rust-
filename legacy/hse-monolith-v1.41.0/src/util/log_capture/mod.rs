//! In-memory ring buffer of recent verbose log lines, for download via the UI.
//!
//! A `tracing_subscriber` fmt layer (installed in [`crate::cli::run`]) tees
//! every formatted log line — at the project's default TRACE verbosity — into
//! this bounded ring, in addition to stderr. `GET /api/v1/logs` and the
//! Settings page's "Download debug log" button serialise the ring to a text
//! file on demand. Bounded so a long-running session on a low-RAM Termux device
//! can never grow logs without limit (the "bound everything" invariant).

use std::collections::VecDeque;
use std::io;
use std::sync::{LazyLock, Mutex, MutexGuard};

use tracing_subscriber::fmt::MakeWriter;

/// Default retained-line cap. ~20k × ~160 B ≈ 3 MB — generous for a debug dump,
/// trivially bounded for the device. Override with `HUNTSMAN_LOG_BUFFER_LINES`.
const DEFAULT_CAP: usize = 20_000;

fn configured_cap() -> usize {
    std::env::var("HUNTSMAN_LOG_BUFFER_LINES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_CAP)
}

struct Ring {
    lines: VecDeque<String>,
    /// Bytes written since the last newline — fmt may emit an event across more
    /// than one `write` call, so a line is only committed when its `\n` lands.
    partial: String,
    cap: usize,
    /// Lines evicted because the ring was full — surfaced in the dump header so
    /// a downloaded log is honest about truncation.
    dropped: u64,
}

static RING: LazyLock<Mutex<Ring>> = LazyLock::new(|| {
    Mutex::new(Ring {
        lines: VecDeque::new(),
        partial: String::new(),
        cap: configured_cap(),
        dropped: 0,
    })
});

/// Lock the ring, recovering from a poisoned mutex (a panic mid-log must never
/// take logging down with it).
fn lock() -> MutexGuard<'static, Ring> {
    RING.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Append raw formatted bytes from the fmt layer, committing whole lines on
/// each embedded newline and holding any trailing partial line.
fn push_bytes(buf: &[u8]) {
    let text = String::from_utf8_lossy(buf);
    let mut r = lock();
    r.partial.push_str(&text);
    while let Some(nl) = r.partial.find('\n') {
        // `nl` indexes an ASCII '\n', so `..=nl` is a valid char boundary.
        let mut line: String = r.partial.drain(..=nl).collect();
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        r.lines.push_back(line);
        if r.lines.len() > r.cap {
            r.lines.pop_front();
            r.dropped += 1;
        }
    }
}

/// Number of complete lines currently buffered.
#[must_use]
pub fn line_count() -> usize {
    lock().lines.len()
}

/// Serialise the buffered log (oldest → newest) into a single string with a
/// small honest header. Suitable as a downloadable `.log` body.
#[must_use]
pub fn dump() -> String {
    dump_with_count().0
}

/// Like [`dump`] but returns the serialised body AND its line count from a
/// SINGLE lock acquisition, so a caller that shows both (e.g. a bundle header
/// "N lines" printed next to the body) can't observe a torn read where the
/// count and the body disagree because a line landed between two separate
/// `dump()` / [`line_count`] locks.
#[must_use]
pub fn dump_with_count() -> (String, usize) {
    let r = lock();
    let n = r.lines.len();
    let mut out = String::with_capacity(r.lines.iter().map(|l| l.len() + 1).sum::<usize>() + 160);
    out.push_str(&format!(
        "# Huntsman Search Engine v{} — verbose debug log\n# lines={n} dropped={} cap={}\n\n",
        crate::VERSION,
        r.dropped,
        r.cap
    ));
    for l in &r.lines {
        out.push_str(l);
        out.push('\n');
    }
    (out, n)
}

/// A window of buffered lines newer than a caller-held cursor, plus the cursor
/// to resume from — the read primitive behind a *live* log view (as opposed to
/// [`dump`], which returns the whole ring for a one-shot download).
///
/// The ring assigns every committed line an implicit monotonic sequence: the
/// line at `lines[i]` has sequence `dropped + i`, so `dropped + lines.len()` is
/// the sequence the next line will take. A caller polls with the `cursor` from
/// its previous [`tail`] and receives only lines committed since — no full
/// re-serialise, no per-line id stored.
pub struct Tail {
    /// Lines with sequence `>= after`, oldest first. Empty when the caller is
    /// already current.
    pub lines: Vec<String>,
    /// The sequence to pass as `after` on the next call to receive only newer
    /// lines. Equals the total number of lines ever committed.
    pub cursor: u64,
    /// Lines that existed at or after the caller's `after` but were evicted by
    /// the ring's bound before this read could return them — a real gap in what
    /// the caller will ever see. `0` in the steady state; non-zero only when a
    /// burst outran the poll (or on a first read against an already-wrapped
    /// ring). Surfaced so a live view can show an honest "N lines lost" marker
    /// rather than silently skipping, mirroring the `dropped=` dump header.
    pub missed: u64,
    /// The ring's all-time eviction count (the same figure the download
    /// header's `dropped=` shows), read under the same lock as `lines`. Distinct
    /// from `missed`, which is only the gap relative to *this caller's* `after`.
    pub dropped: u64,
}

/// Read every buffered line with sequence `>= after` (see [`Tail`]). Pass
/// `after = 0` for a first read (returns the whole current ring, with `missed`
/// reporting how many earlier lines were already evicted); thereafter pass the
/// previous [`Tail::cursor`].
#[must_use]
pub fn tail(after: u64) -> Tail {
    let r = lock();
    let oldest = r.dropped; // sequence of lines[0]
    let end = r.dropped + r.lines.len() as u64; // one past the newest
    let (start_idx, missed) = if after <= oldest {
        // Caller wants from at/before the oldest retained line: everything we
        // still hold, and anything between `after` and `oldest` is lost.
        (0usize, oldest - after)
    } else if after >= end {
        // Caller is already current (or ahead, after a clear() reset the ring).
        (r.lines.len(), 0)
    } else {
        ((after - oldest) as usize, 0)
    };
    let lines = r.lines.iter().skip(start_idx).cloned().collect();
    Tail {
        lines,
        cursor: end,
        missed,
        dropped: r.dropped,
    }
}

/// Drop all buffered lines (the Settings "clear" action / tests).
pub fn clear() {
    let mut r = lock();
    r.lines.clear();
    r.partial.clear();
    r.dropped = 0;
}

/// `MakeWriter` that tees fmt-layer output into the ring buffer. Install via
/// `fmt::layer().with_writer(RingMakeWriter)`.
#[derive(Clone, Copy, Default)]
pub struct RingMakeWriter;

/// The per-event writer handed out by [`RingMakeWriter`].
pub struct RingWriter;

impl io::Write for RingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        push_bytes(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for RingMakeWriter {
    type Writer = RingWriter;
    fn make_writer(&self) -> Self::Writer {
        RingWriter
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
