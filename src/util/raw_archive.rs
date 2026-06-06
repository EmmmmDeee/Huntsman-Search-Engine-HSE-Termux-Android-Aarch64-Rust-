//! Per-query raw-response archive for **paid** intelligence providers.
//!
//! Operator policy, verbatim: *"Data that is paid for must be kept in absolute
//! completeness. These legitimate services cost money per query and should
//! never ever be wasted or discarded, and must always be retained in their raw
//! form until manually deleted."*
//!
//! Every byte a paid provider (SeekNow, OathNet) returns is saved here —
//! verbatim, before any parsing, extraction, deduplication, or budget/quota
//! filtering — so the complete purchased corpus survives even the parts the
//! entity extractor doesn't (yet) recognise.
//!
//! ## One self-describing file per query (intuitive, individual names)
//!
//! Each response is its own file under `$HOME/.huntsman/raw/`, named so a human
//! can tell at a glance **who** was queried, on **which provider/endpoint**, and
//! **when** — without opening it:
//!
//! ```text
//! see-know__stealer__matthewdiegmann_at_gmail.com__20260606T061409Z__0001.json
//! see-know__search-email__vanamill_at_hotmail.com__20260606T061410Z__0002.json
//! oathnet__breach-search__MattDieg__20260606T061411Z__0003.json
//! ```
//!
//! `<provider>__<endpoint>__<query>__<UTC-timestamp>__<seq>.json`. The trailing
//! sequence number disambiguates retries / identical re-queries so no response
//! is ever overwritten. Inside, a small `_meta` header documents the request and
//! `raw` holds the response as structured JSON when it parses (pretty-printed,
//! fully readable) or the exact response string otherwise — lossless either way,
//! never encrypted, hashed, or redacted.
//!
//! ## Why one file per query, append-only, never evicted
//!
//! The rest of HSE follows a "bound everything" invariant for a 4 GB Termux
//! device. This archive is the deliberate exception: the operator paid for these
//! bytes, so they are retained until *manually* deleted, never auto-evicted, and
//! kept individually addressable so a single query's purchased data can be found,
//! cited, or deleted on its own.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

/// Process-local monotonic sequence, zero-padded into every filename so two
/// responses archived in the same second (e.g. a retry) never collide or
/// overwrite — each paid response keeps its own file.
static SEQ: AtomicU64 = AtomicU64::new(1);

/// Env toggle. ON by default (the operator's standing directive is total
/// retention of paid data); set `HUNTSMAN_RAW_ARCHIVE=0` (or `off`/`false`) to
/// disable it for a session that must leave no on-disk trace.
fn enabled() -> bool {
    enabled_from(std::env::var("HUNTSMAN_RAW_ARCHIVE").ok().as_deref())
}

/// Pure disable-switch policy (no env read) so it is unit-testable: ON unless
/// the value is explicitly `0`/`off`/`false`.
fn enabled_from(val: Option<&str>) -> bool {
    match val {
        Some(v) => {
            let v = v.trim();
            !(v == "0" || v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("false"))
        }
        None => true,
    }
}

/// Archive directory: `$HUNTSMAN_RAW_ARCHIVE_DIR` if set, else
/// `$HOME/.huntsman/raw`. Mirrors the `$HOME/.huntsman/` convention used by the
/// module ledger and key pool.
fn archive_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("HUNTSMAN_RAW_ARCHIVE_DIR")
        && !dir.trim().is_empty()
    {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".huntsman").join("raw")
}

/// Filesystem-safe, human-legible slug: keep alphanumerics and a few obvious
/// separators, render `@` as the readable `_at_`, collapse everything else to
/// `_`, and cap the length so a pathological query can't blow the filename
/// limit. Empty input becomes `unknown` so a filename component is never blank.
fn slug(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' => out.push(ch),
            '@' => out.push_str("_at_"),
            _ => out.push('_'),
        }
    }
    // Collapse runs of '_' for readability and trim leading/trailing separators.
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    let trimmed = out.trim_matches(['_', '.', '-']).to_string();
    let trimmed = if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed
    };
    trimmed.chars().take(max).collect()
}

/// `YYYYMMDDThhmmssZ` (UTC) for `unix_secs`, computed with Hinnant's
/// civil-from-days algorithm so no date crate is needed. Sorts lexicographically
/// in chronological order — a directory listing is a timeline.
fn format_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let (hh, mi, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil_from_days, epoch 1970-01-01 (see Howard Hinnant, "chrono-Compatible
    // Low-Level Date Algorithms").
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}{m:02}{d:02}T{hh:02}{mi:02}{ss:02}Z")
}

/// The full, self-describing filename for one archived response.
fn build_filename(provider: &str, endpoint: &str, query: &str, unix_secs: u64, seq: u64) -> String {
    format!(
        "{}__{}__{}__{}__{:04}.json",
        slug(provider, 24),
        slug(endpoint, 32),
        slug(query, 80),
        format_utc(unix_secs),
        seq
    )
}

/// The pretty-printed, self-describing file body: a `_meta` header naming the
/// request, plus the response under `raw` (structured when it parses, the exact
/// string otherwise). Pure (no I/O) so the shape is unit-testable.
fn build_body(provider: &str, endpoint: &str, query: &str, unix_secs: u64, raw: &str) -> String {
    let raw_val: Value =
        serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string()));
    let doc = serde_json::json!({
        "_meta": {
            "provider": provider,
            "endpoint": endpoint,
            "query": query,
            "archived_at_utc": format_utc(unix_secs),
            "unix": unix_secs,
        },
        "raw": raw_val,
    });
    // Pretty-printed: an individual file is meant to be opened and read by a
    // human, so optimise for legibility over compactness.
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| doc.to_string())
}

/// Persist one paid-provider response to its own file, verbatim. Best-effort and
/// infallible from the caller's view: any I/O error is logged at debug and
/// swallowed so archiving can never fail a scan or drop the in-flight result.
///
/// `endpoint` is the human label for the queried surface (e.g. `stealer`,
/// `search-email`, `breach-search`); `query` is the actual value looked up
/// (email / username / name). Call with the *raw response body*, before parsing.
pub fn record(provider: &str, endpoint: &str, query: &str, raw: &str) {
    if !enabled() || raw.is_empty() {
        return;
    }
    let unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let filename = build_filename(provider, endpoint, query, unix_secs, seq);
    let body = build_body(provider, endpoint, query, unix_secs, raw);
    let dir = archive_dir();
    let path = dir.join(filename);
    if let Err(e) = write_file(&path, &body) {
        tracing::debug!(provider, endpoint, error = %e, "raw archive write failed");
    }
}

/// Write one complete archive file (mode 0600 on unix), creating the archive
/// directory if missing. Each file is written once and never appended to, so no
/// cross-writer locking is needed — the unique `seq` in the name guarantees a
/// distinct path per call.
fn write_file(path: &std::path::Path, body: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    f.write_all(body.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disable_switch_is_opt_out_only() {
        assert!(enabled_from(None), "default must be ON");
        assert!(enabled_from(Some("1")));
        assert!(enabled_from(Some("anything")));
        assert!(!enabled_from(Some("0")));
        assert!(!enabled_from(Some("off")));
        assert!(!enabled_from(Some("False")));
        assert!(!enabled_from(Some("  off  ")));
    }

    #[test]
    fn slug_is_human_legible_and_filesystem_safe() {
        assert_eq!(slug("matthewdiegmann@gmail.com", 80), "matthewdiegmann_at_gmail.com");
        assert_eq!(slug("Matthew Diegmann", 80), "Matthew_Diegmann");
        assert_eq!(slug("mattdieg123", 80), "mattdieg123");
        // No path traversal, no slashes survive.
        assert_eq!(slug("../../etc/passwd", 80), "etc_passwd");
        // Blank / separator-only input never yields an empty component.
        assert_eq!(slug("", 80), "unknown");
        assert_eq!(slug("///", 80), "unknown");
        // Length is capped.
        assert_eq!(slug(&"a".repeat(200), 10).len(), 10);
    }

    #[test]
    fn format_utc_matches_known_epoch_instants() {
        assert_eq!(format_utc(0), "19700101T000000Z");
        // 2026-06-06T06:14:09Z (the live test instant) — exact round value.
        assert_eq!(format_utc(1_780_726_449), "20260606T061409Z");
    }

    #[test]
    fn build_filename_is_blatantly_self_describing() {
        let name = build_filename("see_know", "stealer", "matthewdiegmann@gmail.com", 1_780_726_449, 7);
        assert_eq!(
            name,
            "see_know__stealer__matthewdiegmann_at_gmail.com__20260606T061409Z__0007.json"
        );
        // A human (and the OS sort) can read who/what/when straight off the name.
        assert!(name.starts_with("see_know__stealer__"));
        assert!(name.contains("matthewdiegmann_at_gmail.com"));
        assert!(name.ends_with("__0007.json"));
    }

    #[test]
    fn build_body_keeps_paid_secret_in_full_with_meta_header() {
        let body = build_body(
            "see_know",
            "stealer",
            "seed@x.com",
            1_780_726_449,
            r#"{"results":[{"password":"PLAINTEXT-kept"}]}"#,
        );
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["_meta"]["provider"], "see_know");
        assert_eq!(v["_meta"]["endpoint"], "stealer");
        assert_eq!(v["_meta"]["query"], "seed@x.com");
        assert_eq!(v["_meta"]["archived_at_utc"], "20260606T061409Z");
        // The cleartext paid secret is retained, in full, structurally.
        assert_eq!(v["raw"]["results"][0]["password"], "PLAINTEXT-kept");
    }

    #[test]
    fn build_body_falls_back_to_verbatim_string_for_non_json() {
        let body = build_body("oathnet", "breach-search", "x", 0, "503 Service Unavailable");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["raw"], "503 Service Unavailable");
    }

    #[test]
    fn write_file_persists_individual_named_response_on_disk() {
        // End-to-end on a temp dir (no process-env mutation): an individually
        // named file is written and reads back to the structured paid response.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("hse_raw_{}_{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let name = build_filename("see_know", "search-email", "vanamill@hotmail.com", 1_780_726_449, 3);
        let path = dir.join(&name);
        let body = build_body("see_know", "search-email", "vanamill@hotmail.com", 1_780_726_449, r#"{"x":1}"#);
        write_file(&path, &body).expect("write succeeds");

        assert!(path.exists());
        assert_eq!(
            path.file_name().unwrap().to_str().unwrap(),
            "see_know__search-email__vanamill_at_hotmail.com__20260606T061409Z__0003.json"
        );
        let read = std::fs::read_to_string(&path).unwrap();
        let v: Value = serde_json::from_str(&read).unwrap();
        assert_eq!(v["raw"]["x"], 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
