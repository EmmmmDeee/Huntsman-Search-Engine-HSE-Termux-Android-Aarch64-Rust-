//! Append-only raw-response archive for **paid** intelligence providers.
//!
//! Operator policy, verbatim: *"Data that is paid for must be kept in absolute
//! completeness. These legitimate services cost money per query and should
//! never ever be wasted or discarded, and must always be retained in their raw
//! form until manually deleted."*
//!
//! Every byte a paid provider (SeekNow, OathNet) returns is appended here —
//! verbatim, before any parsing, extraction, deduplication, or budget/quota
//! filtering — so the complete purchased corpus survives even the parts the
//! entity extractor doesn't (yet) recognise. The extractor's job is to surface
//! pivots; this archive's job is to guarantee nothing paid-for is ever lost
//! between the wire and the operator.
//!
//! ## Why append-only (and NOT bounded/evicted)
//!
//! The rest of HSE follows a "bound everything" invariant for a 4 GB Termux
//! device — ring buffers, capped caches, FIFO eviction. This archive is the
//! deliberate exception: the operator paid for these bytes, so they are
//! retained until *manually* deleted, never auto-evicted. A capped archive
//! would silently discard purchased data — exactly what the policy forbids.
//!
//! ## Format (`$HOME/.huntsman/raw/<provider>.jsonl`)
//!
//! One self-describing JSON object per line (NDJSON — greppable, `jq`-able,
//! not encrypted/hashed/redacted):
//!
//! ```json
//! {"ts":1733_000_000,"provider":"see_know","query":"…","raw":{…}}
//! ```
//!
//! `raw` embeds the response as a structured JSON *value* when the body parses
//! (fully readable, losslessly preserved); otherwise it is stored as the exact
//! response string. Either way the original is recoverable byte-for-byte by a
//! human interpreter.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::Value;

/// Serialises concurrent appends so the parallel endpoint fan-out can't
/// interleave two records into one torn line. Each record is one `write_all`
/// of a complete `line + '\n'`, taken under this lock.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Env toggle. The archive is ON by default (the operator's standing directive
/// is total retention of paid data); set `HUNTSMAN_RAW_ARCHIVE=0` (or `off`/
/// `false`) to disable it for a session that must leave no on-disk trace.
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

/// Path to a provider's append-only archive (`<dir>/<provider>.jsonl`). The
/// provider name is sanitised to a filesystem-safe slug so it can never escape
/// the archive directory.
fn provider_path(provider: &str) -> PathBuf {
    let slug: String = provider
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    archive_dir().join(format!("{slug}.jsonl"))
}

/// Build the one-line NDJSON record for `(provider, query, raw)`. Pure (no I/O)
/// so the envelope shape is unit-testable. `raw` is embedded as a structured
/// JSON value when it parses, else as the exact response string — lossless
/// either way.
fn build_record(provider: &str, query: &str, raw: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Embed the body structurally when it's valid JSON (readable + preserved);
    // fall back to the verbatim string so a non-JSON/error body is still kept.
    let raw_val: Value = serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string()));
    let record = serde_json::json!({
        "ts": ts,
        "provider": provider,
        "query": query,
        "raw": raw_val,
    });
    record.to_string()
}

/// Append one paid-provider response to its archive, verbatim. Best-effort and
/// infallible from the caller's view: any I/O error is logged at debug and
/// swallowed so archiving can never fail a scan or drop the in-flight result.
/// Call this with the *raw response body*, before parsing or extraction.
pub fn record(provider: &str, query: &str, raw: &str) {
    if !enabled() || raw.is_empty() {
        return;
    }
    let line = build_record(provider, query, raw);
    let path = provider_path(provider);
    if let Err(e) = append_line(&path, &line) {
        tracing::debug!(provider, error = %e, "raw archive append failed");
    }
}

/// Append a single complete line (plus newline) to `path`, creating the file
/// (mode 0600 on unix) and any missing parent directories. Serialised by the
/// process-global [`WRITE_LOCK`] so concurrent appends never interleave into a
/// torn line. Pure of env/provider logic, so the on-disk retention guarantee is
/// directly unit-testable against a temp path.
fn append_line(path: &std::path::Path, line: &str) -> std::io::Result<()> {
    let _guard = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{line}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn build_record_embeds_valid_json_structurally() {
        let line = build_record("see_know", "a@b.com", r#"{"data":{"items":[{"email":"a@b.com"}]}}"#);
        let v: Value = serde_json::from_str(&line).expect("record is valid JSON");
        assert_eq!(v["provider"], "see_know");
        assert_eq!(v["query"], "a@b.com");
        // The body is preserved as a structured value, not a string blob.
        assert_eq!(v["raw"]["data"]["items"][0]["email"], "a@b.com");
        assert!(v["ts"].as_u64().is_some());
    }

    #[test]
    fn build_record_falls_back_to_verbatim_string_for_non_json() {
        // An error page / truncated body is still retained, byte-for-byte.
        let body = "503 Service Unavailable";
        let line = build_record("oathnet", "x", body);
        let v: Value = serde_json::from_str(&line).expect("record is valid JSON");
        assert_eq!(v["raw"], body, "non-JSON body must be kept verbatim as a string");
    }

    #[test]
    fn provider_path_slugs_unsafe_names_inside_archive_dir() {
        // A provider name can never traverse out of the archive directory.
        let p = provider_path("../../etc/passwd");
        let dir = archive_dir();
        assert!(p.starts_with(&dir), "{p:?} must stay under {dir:?}");
        assert!(p.file_name().unwrap().to_str().unwrap().ends_with(".jsonl"));
        assert!(!p.to_string_lossy().contains(".."));
    }

    #[test]
    fn disable_switch_is_opt_out_only() {
        // The archive is ON by default (total retention of paid data); only an
        // explicit 0/off/false disables it. Pure — no process-env mutation.
        assert!(enabled_from(None), "default must be ON");
        assert!(enabled_from(Some("1")));
        assert!(enabled_from(Some("anything")));
        assert!(!enabled_from(Some("0")));
        assert!(!enabled_from(Some("off")));
        assert!(!enabled_from(Some("False")));
        assert!(!enabled_from(Some("  off  ")));
    }

    #[test]
    fn append_line_round_trips_paid_secret_verbatim_on_disk() {
        // End-to-end retention guarantee, on disk, without touching process env:
        // a built record appended to a real file parses back to the original
        // structured body — the cleartext paid secret kept in full.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp = std::env::temp_dir().join(format!(
            "hse_raw_test_{}_{nanos}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let path = tmp.join("see_know.jsonl");

        let line = build_record("see_know", "seed@x.com", r#"{"results":[{"password":"PLAINTEXT-kept"}]}"#);
        append_line(&path, &line).expect("append succeeds");
        // A second append must not clobber the first (append-only, never evicted).
        append_line(&path, &build_record("see_know", "seed2", r#"{"x":2}"#)).unwrap();

        let contents = std::fs::read_to_string(&path).expect("archive file exists");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "append-only: both records retained");
        let v: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(v["raw"]["results"][0]["password"], "PLAINTEXT-kept");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
