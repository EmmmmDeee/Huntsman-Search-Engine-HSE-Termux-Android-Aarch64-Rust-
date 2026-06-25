//! Foreign API keys discovered **inside endpoint response data** — third-party
//! credentials leaked in breach/stealer records, scraped pages, JSON payloads,
//! etc. — as distinct from the keys HSE uses to authenticate its OWN queries.
//!
//! Operator directive: *"I don't need the API keys already being utilised to
//! query, I need every other API key retrieved during endpoint queries to be
//! identified."* So this sink:
//!
//!   1. is fed every response body at the single archive chokepoint
//!      (`raw_archive::record`), covering EVERY module — reqwest, curl, and the
//!      breach pools alike;
//!   2. runs each token through `key_harvest::identify_vendor_api_key` —
//!      recognised vendor prefixes (80+), PEM blocks, and crypto addresses — so
//!      a hit is a genuine, service-identified key. It deliberately skips the
//!      generic-hex heuristic: this scans EVERY body, and entropy-testing every
//!      32/64-char hex token (which breach corpora carry by the thousand) is
//!      both slow (~2.8 → 20 MB/s once skipped; reproduce the current figure via
//!      the `bench_scan_body_throughput` baseline) and noisy — those are password
//!      hashes already captured as `Password` entities by the breach modules;
//!   3. **excludes our own auth credentials** ([`crate::util::keys::own_api_keys`])
//!      so the report contains only foreign keys;
//!   4. retains full provenance (which provider/endpoint, which query) per key.
//!
//! The engine [`reset`]s it at scan start and [`drain`]s it at finalisation into
//! first-class `ApiKey` entities (tagged `foreign-key`), so every leaked key
//! lands in the graph, the dossier, and correlations — regardless of which
//! module surfaced the data.

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex, MutexGuard};

tokio::task_local! {
    /// The `scan_id` of the scan whose modules are executing on this task. Set by
    /// the engine around each scan (`run_with_ledger`) **and** re-set inside each
    /// spawned dispatch task, so [`scan_body`] — reached deep in the shared
    /// `raw_archive` HTTP chokepoint, which carries no `scan_id` of its own — can
    /// attribute a discovered key to the right scan under `hse serve`'s concurrent
    /// scans, **without** threading `scan_id` through the whole util HTTP layer.
    /// Unset outside a scan (e.g. unit tests) ⇒ the default `""` bucket.
    static SCAN: String;
}

/// Run `f` with the current-scan ambient set to `scan_id`, so any [`scan_body`]
/// reached inside `f` keys into that scan's bucket. The engine wraps each scan and
/// each spawned dispatch task in this. Pure (sets a task-local, no I/O) — hence an
/// allow-listed `core → util` leaf in `tests/architecture.rs`, the one exception to
/// "found_keys is driven through the module hook": reset/drain bridge to
/// `core::entity` (so they stay in the hook), but the scan-scope ambient does not.
pub async fn with_scan<F: std::future::Future>(scan_id: String, f: F) -> F::Output {
    SCAN.scope(scan_id, f).await
}

/// The scan currently executing on this task, or `""` when unscoped.
fn current_scan() -> String {
    SCAN.try_with(String::clone).unwrap_or_default()
}

/// Test-only synchronous scope: run `f` with the scan ambient set (mirrors
/// [`with_scan`] for the sync test bodies, which can't `.await` while holding the
/// `SINK`-serialising lock). The production path uses the async [`with_scan`].
#[cfg(test)]
fn with_scan_sync<R>(scan_id: &str, f: impl FnOnce() -> R) -> R {
    SCAN.sync_scope(scan_id.to_string(), f)
}

/// A foreign API key found in response data, with provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundKey {
    /// Identified service (e.g. `stripe_live`, `aws_access_key`, `generic_hex`).
    pub service: String,
    /// The key value, verbatim (operator policy: never redacted).
    pub key: String,
    /// The module/host whose response carried it.
    pub provider: String,
    /// The value that was queried when it was retrieved.
    pub query: String,
    /// How many times this exact key was seen this scan.
    pub count: u32,
}

#[derive(Default)]
struct Sink {
    /// Discovered foreign keys **per `scan_id`** (keyed by [`SCAN`]), each inner
    /// map deduped by key value. Per-scan so concurrent `serve` scans can't wipe or
    /// harvest each other's keys (PROBLEM_TREE T2.11). The `""` bucket is used by
    /// unscoped callers (unit tests).
    per_scan: HashMap<String, HashMap<String, FoundKey>>,
    /// Our own auth credentials, to exclude. **Shared** across scans — the process
    /// owns the same auth keys regardless of which scan is running. Refreshed at
    /// [`reset`].
    own: HashSet<String>,
}

static SINK: LazyLock<Mutex<Sink>> = LazyLock::new(|| Mutex::new(Sink::default()));

fn lock() -> MutexGuard<'static, Sink> {
    SINK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Token-length window: below 16 chars almost nothing real matches; above 512
/// is past every known vendor key (GitLab's ~256 is the longest) and into
/// base64-blob DoS territory.
pub(crate) const MIN_TOKEN: usize = 16;
pub(crate) const MAX_TOKEN: usize = 512;

/// Token boundary for key-candidate extraction: whitespace plus the structural
/// punctuation that brackets values in JSON, query strings, and env files.
/// Shared by every body scanner so the two call sites cannot drift — the
/// config-leak probe previously used a narrower set (no `, & { } [ ]`), missing
/// keys followed by a query/array separator.
///
/// `?` is included because upstream endpoints frequently echo query parameters
/// in response bodies (e.g. `{"url":"…?api_key=AKIA…&b=2"}`); without it the
/// whole suffix `AKIA…&b=2` is one token, which fails the vendor-prefix check
/// after the first `&`.
pub(crate) fn is_key_delimiter(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '"' | '\'' | '`' | '>' | '<' | '=' | ';' | ',' | '&' | '?' | '{' | '}' | '[' | ']'
        )
}

/// Candidate key tokens of `body`: maximal non-delimiter runs, trimmed, within
/// `[MIN_TOKEN, max_len]`. Zero-copy (`&str` slices of `body`); the caller
/// applies its own classifier (vendor-only on every body, generic-inclusive on
/// high-signal config leaks). The single source of truth for how a response
/// body is split into key candidates.
pub(crate) fn key_tokens(body: &str, max_len: usize) -> impl Iterator<Item = &str> {
    body.split(is_key_delimiter)
        .map(str::trim)
        .filter(move |t| t.len() >= MIN_TOKEN && t.len() <= max_len)
}

/// Clear `scan_id`'s bucket and refresh the (shared) own-key exclusion set. Called
/// by the engine at the start of every scan so each scan reports only the keys IT
/// retrieved, and a freshly-rotated auth key is excluded immediately.
pub fn reset(scan_id: &str) {
    let mut g = lock();
    g.per_scan.remove(scan_id);
    g.own = crate::util::keys::own_api_keys();
}

/// Test-only: register an additional own-credential to exclude. The embedded
/// auth keys aren't vendor-prefixed (so the vendor-only scan never detects
/// them), so exercising the exclusion path needs a vendor-shaped own key.
#[cfg(test)]
fn insert_own_for_test(key: &str) {
    lock().own.insert(key.to_string());
}

/// Scan one response `body` for foreign API keys, recording each (deduped by
/// value, provenance kept) — excluding our own auth credentials. Best-effort and
/// infallible: safe to call on every response, JSON or not.
///
/// Identification uses [`crate::modules::oathnet_pro::key_harvest::identify_vendor_api_key`]
/// (recognised vendor prefixes /
/// PEM / crypto), NOT the generic-hex heuristic. That is deliberate: this runs
/// on EVERY response body, and entropy-scanning every 32/64-char hex token (of
/// which breach corpora have thousands) was measured at ~2.8 MB/s and produced
/// password-hash false positives. The hashes are already captured as `Password`
/// entities by the breach modules; here we want only genuine third-party keys.
pub fn scan_body(provider: &str, query: &str, body: &str) {
    use crate::modules::oathnet_pro::key_harvest::identify_vendor_api_key;
    if body.is_empty() {
        return;
    }
    // Identify candidates WITHOUT holding the global lock. Under concurrent
    // module dispatch many bodies are scanned at once; holding the lock only for
    // the O(hits) merge — not the O(body) scan — keeps the sink from serialising
    // the whole scan. Hits are rare, so this Vec is almost always empty.
    let mut hits: Vec<(&'static str, String)> = Vec::new();
    for t in key_tokens(body, MAX_TOKEN) {
        if let Some((service, key_val)) = identify_vendor_api_key(t) {
            hits.push((service, key_val.to_string()));
        }
    }
    if hits.is_empty() {
        return;
    }
    // Attribute to the scan currently executing on this task (the `SCAN` ambient
    // the engine set around this dispatch); `""` when unscoped.
    let scan = current_scan();
    let mut g = lock();
    // Split the borrow so the shared `own` set and the per-scan bucket can be
    // touched at once.
    let Sink { per_scan, own } = &mut *g;
    let bucket = per_scan.entry(scan).or_default();
    for (service, key) in hits {
        // Exclude our own auth credentials — the operator already has those.
        if own.contains(&key) {
            continue;
        }
        bucket
            .entry(key.clone())
            .and_modify(|f| f.count = f.count.saturating_add(1))
            .or_insert_with(|| FoundKey {
                service: service.to_string(),
                key,
                provider: provider.to_string(),
                query: query.to_string(),
                count: 1,
            });
    }
}

/// Deterministic ordering for reporting: by service, then by value.
fn report_order(a: &FoundKey, b: &FoundKey) -> std::cmp::Ordering {
    a.service.cmp(&b.service).then_with(|| a.key.cmp(&b.key))
}

/// A stable snapshot of `scan_id`'s keys found so far — non-destructive, for
/// diagnostics.
#[must_use]
pub fn snapshot(scan_id: &str) -> Vec<FoundKey> {
    let g = lock();
    let mut v: Vec<FoundKey> = g
        .per_scan
        .get(scan_id)
        .map(|m| m.values().cloned().collect())
        .unwrap_or_default();
    v.sort_by(report_order);
    v
}

/// Take every key found for `scan_id`, clearing that scan's bucket. Called by the
/// engine at scan finalisation to mint `ApiKey` entities from the discoveries.
#[must_use]
pub fn drain(scan_id: &str) -> Vec<FoundKey> {
    let mut g = lock();
    let mut v: Vec<FoundKey> = g
        .per_scan
        .remove(scan_id)
        .map(|m| m.into_values().collect())
        .unwrap_or_default();
    v.sort_by(report_order);
    v
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
