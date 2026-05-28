//! Bounded per-process response cache.
//!
//! Both `util::see_know` and `util::oathnet` previously hand-rolled
//! the same shape:
//!
//! ```text
//! static RESPONSE_CACHE: LazyLock<Mutex<HashMap<String, Vec<Value>>>>
//!     = LazyLock::new(|| Mutex::new(HashMap::with_capacity(256)));
//!
//! fn cache_get(key: &str) -> Option<Vec<Value>> { ... }
//! fn cache_put(key: String, items: Vec<Value>) { ... }   // cap at 1024
//! ```
//!
//! Encapsulated here so the cache cap, eviction policy, and lock
//! discipline live in one place. The cache itself is `Mutex` over
//! `HashMap` — fine for the OSINT modules' query rate (handful of
//! cached values per scan, never on a hot path).
//!
//! Eviction is intentionally simple: once `cap` entries are present
//! `put()` silently no-ops. The trade-off favours predictability
//! (cap is a true ceiling) over hit rate (a real LRU would evict
//! cold entries). For the API-quota use case the cache is sized to
//! comfortably hold every distinct (path, query) tuple a single
//! scan generates, so the no-op branch is rarely hit in practice.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Generic bounded response cache.
///
/// Construct as a `static` via `const fn new(cap)`. The underlying
/// `HashMap` is allocated lazily on first access via `OnceLock`, so
/// processes that never touch the API pay zero startup cost.
pub struct ResponseCache<T: Clone + Send + 'static> {
    inner: OnceLock<Mutex<HashMap<String, T>>>,
    /// Hard ceiling on the number of entries. `put()` no-ops once
    /// the map reaches `cap` items.
    cap: usize,
}

impl<T: Clone + Send + 'static> ResponseCache<T> {
    /// `const fn` constructor so callers can declare
    /// `static CACHE: ResponseCache<Vec<Value>> = ResponseCache::new(1024)`.
    pub const fn new(cap: usize) -> Self {
        Self {
            inner: OnceLock::new(),
            cap,
        }
    }

    /// Lazy-initialise the underlying `Mutex<HashMap>` on first
    /// access. Subsequent calls return the same handle.
    fn lock(&self) -> &Mutex<HashMap<String, T>> {
        self.inner.get_or_init(|| {
            let initial = 256.min(self.cap);
            Mutex::new(HashMap::with_capacity(initial))
        })
    }

    /// Look up a key. Returns `Some(value.clone())` on hit, `None`
    /// on miss or lock poisoning.
    pub fn get(&self, key: &str) -> Option<T> {
        self.lock().lock().ok().and_then(|c| c.get(key).cloned())
    }

    /// Insert a value. No-ops if the map has reached `cap` or the
    /// lock is poisoned.
    pub fn put(&self, key: String, value: T) {
        if let Ok(mut c) = self.lock().lock()
            && c.len() < self.cap
        {
            c.insert(key, value);
        }
    }

    /// Number of entries currently cached. Useful for tests; the
    /// production module layer doesn't care about live size.
    pub fn len(&self) -> usize {
        self.lock().lock().map(|c| c.len()).unwrap_or(0)
    }

    /// True if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Effective ceiling. Used by tests to validate the cap was
    /// installed as declared.
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Drop every entry. Intended for tests and operator-initiated
    /// flushes (e.g. after detecting API contract drift); the
    /// production code path doesn't call this.
    pub fn clear(&self) {
        if let Ok(mut c) = self.lock().lock() {
            c.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_then_get_round_trips() {
        let c: ResponseCache<Vec<i32>> = ResponseCache::new(10);
        c.put("k".into(), vec![1, 2, 3]);
        assert_eq!(c.get("k"), Some(vec![1, 2, 3]));
    }

    #[test]
    fn get_returns_none_for_missing_key() {
        let c: ResponseCache<String> = ResponseCache::new(10);
        assert_eq!(c.get("absent"), None);
    }

    #[test]
    fn put_noops_once_cap_reached() {
        let c: ResponseCache<u32> = ResponseCache::new(2);
        c.put("a".into(), 1);
        c.put("b".into(), 2);
        // Third insert MUST be silently dropped — cap is a hard
        // ceiling, not a soft hint.
        c.put("c".into(), 3);
        assert_eq!(c.len(), 2);
        assert_eq!(c.get("c"), None);
    }

    #[test]
    fn capacity_reports_declared_cap() {
        let c: ResponseCache<u32> = ResponseCache::new(42);
        assert_eq!(c.capacity(), 42);
    }

    #[test]
    fn put_updates_existing_value() {
        let c: ResponseCache<u32> = ResponseCache::new(10);
        c.put("k".into(), 1);
        c.put("k".into(), 2);
        assert_eq!(c.get("k"), Some(2));
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn clear_drops_every_entry() {
        let c: ResponseCache<u32> = ResponseCache::new(10);
        c.put("a".into(), 1);
        c.put("b".into(), 2);
        assert_eq!(c.len(), 2);
        c.clear();
        assert_eq!(c.len(), 0);
        assert!(c.is_empty());
    }

    #[test]
    fn is_empty_tracks_population() {
        let c: ResponseCache<u32> = ResponseCache::new(10);
        assert!(c.is_empty());
        c.put("x".into(), 7);
        assert!(!c.is_empty());
    }

    #[test]
    fn lazy_init_happens_on_first_access() {
        // Build a cache but never touch it; OnceLock should report
        // un-initialised. We can't observe that directly without
        // exposing internals, but `len()` going from 0 to 1 after
        // a single put proves the lazy alloc works.
        let c: ResponseCache<u32> = ResponseCache::new(10);
        assert_eq!(c.len(), 0);
        c.put("k".into(), 1);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn cap_of_one_admits_only_first_entry() {
        let c: ResponseCache<u32> = ResponseCache::new(1);
        c.put("a".into(), 1);
        c.put("b".into(), 2);
        assert_eq!(c.len(), 1);
        assert_eq!(c.get("a"), Some(1));
        assert_eq!(c.get("b"), None);
    }

    #[test]
    fn cap_of_zero_admits_nothing() {
        // Pathological but well-defined: cap = 0 → put always
        // no-ops. The cache reports empty forever.
        let c: ResponseCache<u32> = ResponseCache::new(0);
        c.put("a".into(), 1);
        assert!(c.is_empty());
    }

    #[test]
    fn initial_alloc_caps_at_256_even_for_large_cap() {
        // The lazy-init capacity is `min(256, cap)` to avoid burning
        // memory for a cache that's nominally huge but never
        // populated. Can't observe `HashMap::capacity()` directly
        // through the API, but inserting < 256 entries must succeed
        // without re-alloc churn — the property here is just that
        // construction doesn't panic.
        let c: ResponseCache<u32> = ResponseCache::new(10_000);
        for i in 0..50 {
            c.put(format!("k{i}"), i);
        }
        assert_eq!(c.len(), 50);
    }

    #[test]
    fn supports_vec_value_type_for_paid_apis() {
        // Exercise the actual use case: a Vec<serde_json::Value>
        // payload as both producers (see_know, oathnet) use.
        use serde_json::Value;
        let c: ResponseCache<Vec<Value>> = ResponseCache::new(8);
        let payload = vec![Value::String("hit".into()), Value::Bool(true)];
        c.put("search:alice".into(), payload.clone());
        assert_eq!(c.get("search:alice"), Some(payload));
    }
}
