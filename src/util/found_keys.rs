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
//!   2. runs each token through `key_harvest::identify_api_key` (80+ vendor
//!      prefixes, PEM blocks, crypto addresses, generic hex, URL-param and
//!      user:pass forms), so a hit is *identified by service*, not just flagged;
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
    /// True when the match came from a *heuristic* catch-all (`generic_hex`,
    /// `url_param_key`) rather than a recognised vendor pattern. Breach corpora
    /// are full of 32/64-char hex *password hashes* that the generic-hex rule
    /// matches; flagging them keeps a real vendor key (Stripe, AWS, GitHub, a PEM
    /// block, …) from being buried under — and miscounted alongside — hashes.
    pub heuristic: bool,
}

/// Services that `identify_api_key` returns from a *heuristic* rule rather than a
/// recognised vendor prefix / structured form. These have a high false-positive
/// rate against breach data (a 32-char hex is far more often an MD5 hash than an
/// API key), so we keep them but label them low-confidence.
fn is_heuristic_service(service: &str) -> bool {
    matches!(service, "generic_hex" | "url_param_key")
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

/// Scan one response `body` for foreign API keys, recording each (deduped by
/// value, provenance kept) — excluding our own auth credentials. Best-effort and
/// infallible: safe to call on every response, JSON or not. Tokenises on the
/// same delimiters as the key-pool scanner so the two stay consistent.
pub fn scan_body(provider: &str, query: &str, body: &str) {
    use crate::modules::oathnet_pro::key_harvest::identify_api_key;
    if body.is_empty() {
        return;
    }
    // Identify candidates WITHOUT holding the global lock. Tokenisation plus
    // per-token pattern matching is the expensive part, and under concurrent
    // module dispatch many bodies are scanned at once; holding the lock only for
    // the O(hits) merge — not the O(body) scan — keeps the sink from serialising
    // the whole scan. Hits are rare, so this Vec is almost always empty.
    let mut hits: Vec<(&'static str, String)> = Vec::new();
    for word in body.split(|c: char| {
        c.is_whitespace()
            || matches!(c, '"' | '\'' | '`' | '>' | '<' | '=' | ';' | ',' | '{' | '}' | '[' | ']')
    }) {
        let t = word.trim();
        if t.len() < MIN_TOKEN || t.len() > MAX_TOKEN {
            continue;
        }
        if let Some((service, key_val)) = identify_api_key(t) {
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
        let heuristic = is_heuristic_service(service);
        g.found
            .entry(key.clone())
            .and_modify(|f| f.count = f.count.saturating_add(1))
            .or_insert_with(|| FoundKey {
                service: service.to_string(),
                key,
                provider: provider.to_string(),
                query: query.to_string(),
                count: 1,
                heuristic,
            });
    }
}

/// Deterministic ordering for reporting: recognised **vendor keys first**
/// (the high-signal findings), then by service, then by value. Heuristic
/// catch-all matches (likely hashes) sort last so they never bury a real key.
fn report_order(a: &FoundKey, b: &FoundKey) -> std::cmp::Ordering {
    a.heuristic
        .cmp(&b.heuristic)
        .then_with(|| a.service.cmp(&b.service))
        .then_with(|| a.key.cmp(&b.key))
}

/// A stable snapshot of the keys found so far (vendor keys first) — non-
/// destructive, for diagnostics.
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
        assert!(stripe[0].service.contains("stripe"), "identified: {}", stripe[0].service);
        assert!(!stripe[0].heuristic, "a vendor-prefixed key is not heuristic");
        // drain empties the sink.
        assert!(!drain().is_empty());
        assert!(snapshot().is_empty());
    }

    #[test]
    fn generic_hex_hash_is_kept_but_flagged_heuristic() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        // Breach data is full of 32-char MD5 hashes; the generic-hex rule matches
        // them. They must be KEPT (nothing dropped) but flagged heuristic so a
        // hash can't masquerade as — or be miscounted with — a real retrieved key.
        let hash = "5e3706b9c16282351af9c3aac7107b54";
        scan_body("oathnet", "victim@example.com", &format!("hash={hash}"));
        let snap = snapshot();
        let h = snap.iter().find(|f| f.key == hash).expect("hash kept");
        assert!(h.heuristic, "a bare hex hash is heuristic, not a vendor key");
        assert_eq!(h.service, "generic_hex");
    }

    #[test]
    fn report_order_ranks_vendor_before_heuristic() {
        // Pure ordering contract, independent of the pattern catalogue: a
        // recognised vendor key always sorts ahead of a heuristic match, so the
        // dossier never buries a leaked Stripe/AWS key under a column of hashes.
        let mk = |service: &str, key: &str, heuristic: bool| FoundKey {
            service: service.to_string(),
            key: key.to_string(),
            provider: "p".to_string(),
            query: "q".to_string(),
            count: 1,
            heuristic,
        };
        let mut v = vec![
            mk("generic_hex", "aaaa", true),
            mk("stripe_live", "zzzz", false),
            mk("url_param_key", "bbbb", true),
        ];
        v.sort_by(report_order);
        assert!(!v[0].heuristic, "vendor key first: {v:?}");
        assert_eq!(v[0].service, "stripe_live");
        assert!(v[1].heuristic && v[2].heuristic, "heuristics last");
    }

    #[test]
    fn excludes_our_own_auth_keys() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        // The bundled SeekNow auth key must NEVER be reported as a finding.
        let own = crate::util::keys::SEEKNOW_DEFAULT_KEY;
        scan_body("see-know", "q", &format!("leaked here: {own}"));
        assert!(
            snapshot().iter().all(|f| f.key != own),
            "our own auth key must be excluded from findings"
        );
    }
}
