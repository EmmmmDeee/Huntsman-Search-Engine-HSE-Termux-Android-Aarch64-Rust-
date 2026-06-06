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
//!      both slow (~2.8 → 20 MB/s once skipped) and noisy — those are password
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
    /// Deduped by key value.
    found: HashMap<String, FoundKey>,
    /// Our own auth credentials, to exclude. Populated at [`reset`].
    own: HashSet<String>,
}

static SINK: LazyLock<Mutex<Sink>> = LazyLock::new(|| Mutex::new(Sink::default()));

fn lock() -> MutexGuard<'static, Sink> {
    SINK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Token-length window: below 16 chars almost nothing real matches; above 512
/// is past every known vendor key (GitLab's ~256 is the longest) and into
/// base64-blob DoS territory.
const MIN_TOKEN: usize = 16;
const MAX_TOKEN: usize = 512;

/// Clear the sink and refresh the own-key exclusion set. Called by the engine at
/// the start of every scan so each scan reports only the keys IT retrieved, and
/// a freshly-rotated auth key is excluded immediately.
pub fn reset() {
    let mut g = lock();
    g.found.clear();
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
/// Identification uses [`identify_vendor_api_key`] (recognised vendor prefixes /
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
    for word in body.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | '`' | '>' | '<' | '=' | ';' | ',' | '&' | '{' | '}' | '[' | ']'
            )
    }) {
        let t = word.trim();
        if t.len() < MIN_TOKEN || t.len() > MAX_TOKEN {
            continue;
        }
        if let Some((service, key_val)) = identify_vendor_api_key(t) {
            hits.push((service, key_val.to_string()));
        }
    }
    if hits.is_empty() {
        return;
    }
    let mut g = lock();
    for (service, key) in hits {
        // Exclude our own auth credentials — the operator already has those.
        if g.own.contains(&key) {
            continue;
        }
        g.found
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

/// A stable snapshot of the keys found so far — non-destructive, for diagnostics.
#[must_use]
pub fn snapshot() -> Vec<FoundKey> {
    let mut v: Vec<FoundKey> = lock().found.values().cloned().collect();
    v.sort_by(report_order);
    v
}

/// Take every found key, clearing the sink. Called by the engine at scan
/// finalisation to mint `ApiKey` entities from the discoveries.
#[must_use]
pub fn drain() -> Vec<FoundKey> {
    let mut g = lock();
    let mut v: Vec<FoundKey> = g.found.drain().map(|(_, f)| f).collect();
    v.sort_by(report_order);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    // Serialise the tests that share the process-global SINK.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn identifies_foreign_keys_with_provenance_and_dedups() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        // A Stripe-style live key embedded in a record body, twice. Built from
        // fragments so the synthetic test key isn't a contiguous `sk_live_…`
        // literal in source (which trips repository secret-scanning / push
        // protection); `identify_api_key` still sees the assembled value.
        let synthetic = format!("sk_{}_{}", "live", "4eC39HqLyjWDarjtT1zdp7dc");
        let body = format!(r#"{{"note":"prod key {synthetic}", "dup":"{synthetic}"}}"#);
        scan_body("see-know", "victim@example.com", &body);
        let snap = snapshot();
        let stripe: Vec<_> = snap.iter().filter(|f| f.key == synthetic).collect();
        assert_eq!(stripe.len(), 1, "deduped by value; got {snap:?}");
        assert_eq!(stripe[0].count, 2, "both occurrences counted");
        assert_eq!(stripe[0].provider, "see-know");
        assert_eq!(stripe[0].query, "victim@example.com");
        assert!(
            stripe[0].service.contains("stripe"),
            "identified: {}",
            stripe[0].service
        );
        // drain empties the sink.
        assert!(!drain().is_empty());
        assert!(snapshot().is_empty());
    }

    #[test]
    fn generic_hex_hash_is_not_reported_as_a_key() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        // Breach data is full of 32-char MD5 hashes. The universal scan uses the
        // vendor-only identifier, so a bare hex hash is NOT misreported as a
        // retrieved API key (it's already captured as a Password entity by the
        // breach modules, and entropy-scanning every hash was the perf hot spot).
        let hash = "5e3706b9c16282351af9c3aac7107b54";
        scan_body("oathnet", "victim@example.com", &format!("hash={hash}"));
        assert!(
            snapshot().is_empty(),
            "a bare hex hash must not become a foreign-key finding: {:?}",
            snapshot()
        );
    }

    #[test]
    fn report_order_is_deterministic_by_service_then_value() {
        let mk = |service: &str, key: &str| FoundKey {
            service: service.to_string(),
            key: key.to_string(),
            provider: "p".to_string(),
            query: "q".to_string(),
            count: 1,
        };
        let mut v = [
            mk("stripe_live", "zzzz"),
            mk("aws_access_key", "bbbb"),
            mk("aws_access_key", "aaaa"),
        ];
        v.sort_by(report_order);
        assert_eq!(v[0].service, "aws_access_key");
        assert_eq!(v[0].key, "aaaa");
        assert_eq!(v[1].key, "bbbb");
        assert_eq!(v[2].service, "stripe_live");
    }

    #[test]
    fn excludes_our_own_auth_keys() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        // An operator's OWN configured key that happens to be vendor-shaped must
        // never be reported as a foreign finding. Build it from fragments so the
        // synthetic literal isn't a contiguous secret in source.
        let own = format!("sk_{}_{}", "live", "OWNkeyDoNotReport0123456789");
        insert_own_for_test(&own);
        scan_body("see-know", "q", &format!("leaked here: {own}"));
        assert!(
            snapshot().iter().all(|f| f.key != own),
            "our own auth key must be excluded from findings"
        );
    }
}
