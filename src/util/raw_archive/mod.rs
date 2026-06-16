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
//! see-know__stealer__jordanavery_at_gmail.com__20260606T061409Z__0001.json
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

use std::sync::atomic::Ordering;

mod config;
mod format;
mod io;
mod query;
mod url;

pub use query::ArchivedResponse;

/// Archive an HTTP JSON response keyed off its URL — the universal entry point
/// for the shared transport layer, so EVERY module's API response is retained,
/// not just the two breach pools. `provider` is the module/source name; the
/// endpoint label and query value are derived from `url` (path tail + first
/// query parameter, falling back to the last path segment), so the saved file
/// still names what was looked up. Best-effort; non-JSON/HTML bodies are fine
/// (stored verbatim as a string).
pub fn record_http(provider: &str, url: &str, body: &str) {
    let (endpoint, query) = url::describe_url(url);
    record(provider, &endpoint, &query, body);
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

    if !config::enabled() {
        return;
    }
    let unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let seq = config::SEQ.fetch_add(1, Ordering::Relaxed);
    let filename = format::build_filename(provider, endpoint, query, unix_secs, seq);
    let body = format::build_body(provider, endpoint, query, unix_secs, raw);
    let dir = config::archive_dir();
    let path = dir.join(filename);
    if let Err(e) = io::write_file(&path, &body) {
        tracing::debug!(provider, endpoint, error = %e, "raw archive write failed");
    }
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
    query::records_filtered_dir(&config::archive_dir(), start_unix, end_unix, None)
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
    query::records_filtered_dir(&config::archive_dir(), start_unix, end_unix, Some(queries))
}

#[cfg(test)]
mod tests;
