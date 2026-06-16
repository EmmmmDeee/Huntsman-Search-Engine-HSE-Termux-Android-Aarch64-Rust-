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
        self.lock().lock().map_or(0, |c| c.len())
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
    include!("tests.rs");
}
