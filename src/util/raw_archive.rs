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

/// Archive an HTTP JSON response keyed off its URL — the universal entry point
/// for the shared transport layer, so EVERY module's API response is retained,
/// not just the two breach pools. `provider` is the module/source name; the
/// endpoint label and query value are derived from `url` (path tail + first
/// query parameter, falling back to the last path segment), so the saved file
/// still names what was looked up. Best-effort; non-JSON/HTML bodies are fine
/// (stored verbatim as a string).
pub fn record_http(provider: &str, url: &str, body: &str) {
    let (endpoint, query) = describe_url(url);
    record(provider, &endpoint, &query, body);
}

/// Derive `(endpoint, query)` labels from a request URL: the endpoint is the
/// last one or two non-empty path segments (e.g. `…/v3/breachedaccount/x` →
/// `breachedaccount`), and the query is the first query-string value, else the
/// last path segment, else the host. Pure, so it is unit-testable.
fn describe_url(url: &str) -> (String, String) {
    let after_scheme = url.splitn(2, "://").last().unwrap_or(url);
    let (host_path, query_str) = match after_scheme.split_once('?') {
        Some((hp, q)) => (hp, q),
        None => (after_scheme, ""),
    };
    let (host, path) = match host_path.split_once('/') {
        Some((h, p)) => (h, p),
        None => (host_path, ""),
    };
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let urldecode = crate::util::http::urldecode;
    // First NON-credential query value. Picking the first value blindly would
    // write our OWN auth key into the filename + `_meta.query` for endpoints that
    // put credentials first (`?api_key=…&q=…`) — archiving is on by default, so
    // that would leak the operator's key onto disk. Credential-named params are
    // skipped; the value we surface is the actual lookup term.
    const CRED_PARAMS: &[&str] = &[
        "key",
        "api_key",
        "apikey",
        "api-key",
        "token",
        "access_token",
        "auth",
        "auth_token",
        "secret",
        "password",
        "pass",
        "apptoken",
        "app_token",
        "x-api-key",
    ];
    let first_qval = query_str.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        if v.is_empty() || CRED_PARAMS.contains(&k.trim().to_lowercase().as_str()) {
            return None;
        }
        Some(v)
    });

    if let Some(qv) = first_qval {
        // Query-string API (`…/search?q=value`): endpoint is the last path
        // segment (or host), the looked-up value is the first query parameter.
        let endpoint = segs
            .last()
            .map(|s| (*s).to_string())
            .unwrap_or_else(|| host.to_string());
        (endpoint, urldecode(qv))
    } else if segs.len() >= 2 {
        // Path-style API (`…/breachedaccount/<value>`): the last segment is the
        // value, the one before names the endpoint.
        (
            segs[segs.len() - 2].to_string(),
            urldecode(segs[segs.len() - 1]),
        )
    } else if let Some(last) = segs.last() {
        (host.to_string(), urldecode(last))
    } else {
        (host.to_string(), host.to_string())
    }
}

/// Persist one paid-provider response to its own file, verbatim. Best-effort and
/// infallible from the caller's view: any I/O error is logged at debug and
/// swallowed so archiving can never fail a scan or drop the in-flight result.
///
/// `endpoint` is the human label for the queried surface (e.g. `stealer`,
/// `search-email`, `breach-search`); `query` is the actual value looked up
/// (email / username / name). Call with the *raw response body*, before parsing.
pub fn record(provider: &str, endpoint: &str, query: &str, raw: &str) {
    if raw.is_empty() {
        return;
    }
    // Identify any FOREIGN API keys leaked in this response (every body flows
    // through here, so this is the universal detection point). Runs regardless
    // of whether on-disk archiving is enabled — key identification is a finding,
    // not an archive feature. Our own auth keys are excluded inside the sink.
    crate::util::found_keys::scan_body(provider, query, raw);

    if !enabled() {
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

/// One archived response, parsed back from disk for inclusion in a dossier.
/// `raw` is the verbatim provider body (structured JSON, or a string for a
/// non-JSON body) exactly as it was stored.
#[derive(Debug, Clone)]
pub struct ArchivedResponse {
    pub provider: String,
    pub endpoint: String,
    pub query: String,
    pub unix: u64,
    pub filename: String,
    pub raw: Value,
}

/// Every archived response whose capture time falls within `[start_unix,
/// end_unix]` — i.e. every paid API response a single scan fetched, recovered
/// verbatim from the on-disk archive so a dossier can embed the COMPLETE raw
/// corpus (including thin records that produced no entity). Returns them in
/// chronological order. Best-effort: unreadable / malformed files are skipped,
/// never fatal. The archive files themselves are left in place (the raw dumps
/// stay saved separately).
#[must_use]
pub fn records_in_window(start_unix: u64, end_unix: u64) -> Vec<ArchivedResponse> {
    records_filtered_dir(&archive_dir(), start_unix, end_unix, None)
}

/// Every archived response captured within `[start_unix, end_unix]` **whose
/// query is one of `queries`** (lower-cased). This is how a dossier ties raw
/// responses to a specific scan precisely: the time window excludes earlier runs
/// of the same target, and the query-set excludes a neighbouring back-to-back
/// scan whose window touches this one at the shared second boundary (unix
/// timestamps are second-granular). `queries` should be the scan's target value
/// plus every entity value it produced — covering the seed and every expansion
/// pivot that was re-queried.
#[must_use]
pub fn records_for_queries(
    queries: &std::collections::HashSet<String>,
    start_unix: u64,
    end_unix: u64,
) -> Vec<ArchivedResponse> {
    records_filtered_dir(&archive_dir(), start_unix, end_unix, Some(queries))
}

/// Env-free core for [`records_in_window`] / [`records_for_queries`] — the
/// window filter, optional query-set filter, and parse, so all three are
/// unit-testable against a temp archive.
///
/// The archive is append-only and never evicted, so it grows without bound and
/// the auto-dossier reads it on every scan. To keep that O(matching files) and
/// not O(total archived files), each filename — which embeds the UTC timestamp
/// and the query slug (`<provider>__<endpoint>__<queryslug>__<UTC>__<seq>.json`)
/// — is pre-filtered *before* the file is opened. Only files that survive the
/// cheap filename checks are read and parsed; the exact `_meta.unix` / query
/// checks below stay as the authoritative guard.
fn records_filtered_dir(
    dir: &std::path::Path,
    start_unix: u64,
    end_unix: u64,
    queries: Option<&std::collections::HashSet<String>>,
) -> Vec<ArchivedResponse> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    // Fixed-width UTC stamps sort lexicographically in chronological order, so a
    // string compare against the window bounds is exact. `u64::MAX` (an open
    // upper bound from a still-running scan) disables the upper filename check.
    let utc_lo = format_utc(start_unix);
    let utc_hi = (end_unix != u64::MAX).then(|| format_utc(end_unix));
    // Pre-slug the wanted queries once so the per-file check is a set lookup.
    let want_slugs: Option<std::collections::HashSet<String>> =
        queries.map(|set| set.iter().map(|q| slug(q, 80)).collect());

    for entry in rd.flatten() {
        let filename = entry.file_name().to_string_lossy().into_owned();
        if !filename.ends_with(".json") {
            continue;
        }
        // Cheap filename pre-filter (no I/O). Skip only when the name parses to
        // the known 5-field shape; anything else falls through to a full read so
        // a legacy/odd filename is never silently dropped.
        let parts: Vec<&str> = filename.split("__").collect();
        if parts.len() == 5 {
            let (fq_slug, futc) = (parts[2], parts[3]);
            if futc < utc_lo.as_str() {
                continue;
            }
            if let Some(hi) = &utc_hi
                && futc > hi.as_str()
            {
                continue;
            }
            if let Some(want) = &want_slugs
                && !want.contains(fq_slug)
            {
                continue;
            }
        }

        let path = entry.path();
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(doc) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let unix = doc
            .pointer("/_meta/unix")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if unix < start_unix || unix > end_unix {
            continue;
        }
        let meta_str = |k: &str| {
            doc.pointer(&format!("/_meta/{k}"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        let query = meta_str("query");
        if let Some(set) = queries
            && !set.contains(&query.to_lowercase())
        {
            continue;
        }
        out.push(ArchivedResponse {
            provider: meta_str("provider"),
            endpoint: meta_str("endpoint"),
            query,
            unix,
            filename: entry.file_name().to_string_lossy().into_owned(),
            raw: doc.get("raw").cloned().unwrap_or(Value::Null),
        });
    }
    out.sort_by(|a, b| {
        a.unix
            .cmp(&b.unix)
            .then_with(|| a.filename.cmp(&b.filename))
    });
    out
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
        assert_eq!(
            slug("matthewdiegmann@gmail.com", 80),
            "matthewdiegmann_at_gmail.com"
        );
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
        let name = build_filename(
            "see_know",
            "stealer",
            "matthewdiegmann@gmail.com",
            1_780_726_449,
            7,
        );
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
        let body = build_body(
            "oathnet",
            "breach-search",
            "x",
            0,
            "503 Service Unavailable",
        );
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["raw"], "503 Service Unavailable");
    }

    #[test]
    fn describe_url_derives_endpoint_and_query() {
        // Query param → query value (URL-decoded); path tail → endpoint.
        assert_eq!(
            describe_url("https://haveibeenpwned.com/api/v3/breachedaccount/a%40b.com"),
            ("breachedaccount".to_string(), "a@b.com".to_string())
        );
        assert_eq!(
            describe_url("https://crt.sh/?q=example.com&output=json"),
            ("crt.sh".to_string(), "example.com".to_string())
        );
        // No path, no query → host is both.
        assert_eq!(
            describe_url("https://api.example.org"),
            ("api.example.org".to_string(), "api.example.org".to_string())
        );
        // Credential-named params are SKIPPED so our own auth key never lands in
        // a filename / `_meta.query`; the real lookup term is used instead.
        assert_eq!(
            describe_url("https://api.example.org/v1/lookup?api_key=SECRET123456&q=target%40x.com"),
            ("lookup".to_string(), "target@x.com".to_string())
        );
        // When EVERY query param is a credential, fall back to the path/host —
        // never the secret.
        let (_, q) = describe_url("https://api.example.org/v1/ping?token=DEADBEEFSECRET");
        assert_ne!(
            q, "DEADBEEFSECRET",
            "an auth token must never become the query label"
        );
    }

    #[test]
    fn records_in_window_recovers_full_responses_and_filters_by_time() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("hse_win_{}_{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Two in-window responses (one structured, one thin/no-entity) + one out.
        write_file(
            &dir.join(build_filename(
                "see-know",
                "search-email",
                "v@x.com",
                1000,
                1,
            )),
            &build_body(
                "see-know",
                "search-email",
                "v@x.com",
                1000,
                r#"{"results":[{"source":"INF0SEC Leaks"}]}"#,
            ),
        )
        .unwrap();
        write_file(
            &dir.join(build_filename(
                "oathnet",
                "breach-search",
                "v@x.com",
                1005,
                2,
            )),
            &build_body(
                "oathnet",
                "breach-search",
                "v@x.com",
                1005,
                r#"{"data":{"items":[{"password":"PLAINTEXT"}]}}"#,
            ),
        )
        .unwrap();
        write_file(
            &dir.join(build_filename("see-know", "search-email", "old", 50, 3)),
            &build_body("see-know", "search-email", "old", 50, r#"{"x":1}"#),
        )
        .unwrap();

        let got = records_filtered_dir(&dir, 900, 1100, None);
        assert_eq!(got.len(), 2, "only the two in-window responses");
        // Chronological order, provenance recovered, raw body intact verbatim.
        assert_eq!(got[0].provider, "see-know");
        assert_eq!(got[0].query, "v@x.com");
        assert_eq!(got[0].raw["results"][0]["source"], "INF0SEC Leaks");
        assert_eq!(got[1].raw["data"]["items"][0]["password"], "PLAINTEXT");
        // The out-of-window record is excluded.
        assert!(!got.iter().any(|r| r.query == "old"));

        // Query-set filter: same window, but restrict to a different value —
        // both in-window responses are for "v@x.com", so an unrelated query set
        // excludes them (this is what stops a neighbouring scan bleeding in).
        let mut other: std::collections::HashSet<String> = std::collections::HashSet::new();
        other.insert("someone-else@x.com".to_string());
        assert!(records_filtered_dir(&dir, 900, 1100, Some(&other)).is_empty());
        // Matching query-set keeps them.
        let mut mine: std::collections::HashSet<String> = std::collections::HashSet::new();
        mine.insert("v@x.com".to_string());
        assert_eq!(records_filtered_dir(&dir, 900, 1100, Some(&mine)).len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
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
        let name = build_filename(
            "see_know",
            "search-email",
            "vanamill@hotmail.com",
            1_780_726_449,
            3,
        );
        let path = dir.join(&name);
        let body = build_body(
            "see_know",
            "search-email",
            "vanamill@hotmail.com",
            1_780_726_449,
            r#"{"x":1}"#,
        );
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
