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
//! # Eviction policy: true LRU with a hard ceiling
//!
//! `cap` is a hard ceiling on live entries. When a `put()` of a **new**
//! key would exceed `cap`, the least-recently-used entry is evicted to
//! make room — so the cap holds AND hot entries survive. Recency is
//! tracked by a monotonic per-cache access tick stamped on every `get()`
//! (move-to-front) and `put()`; the entry with the smallest tick is the
//! LRU victim. An in-place refresh of an already-present key never grows
//! the map, so it is always admitted regardless of fill level.
//!
//! Evictions are counted (see [`ResponseCache::evictions`]) and traced at
//! `debug` level, so a saturating cache is observable rather than
//! silently degrading to zero hit rate. For the API-quota use case the
//! cache is still sized to comfortably hold every distinct (path, query)
//! tuple a single scan generates, so eviction is rare in practice — the
//! LRU policy is a safety net, not the steady state.
//!
//! # No TTL
//!
//! Entries have **no time-to-live**: a cached value is served until it is
//! either evicted (LRU, under cap pressure) or overwritten by a fresh
//! `put()` for the same key. There is no background expiry. Callers that
//! must invalidate on API contract drift (or any other staleness signal)
//! are responsible for calling [`ResponseCache::clear`] explicitly.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

/// Generic bounded response cache.
///
/// Construct as a `static` via `const fn new(cap)`. The underlying
/// `HashMap` is allocated lazily on first access via `OnceLock`, so
/// processes that never touch the API pay zero startup cost.
///
/// Eviction is true LRU bounded by `cap` (see the [module docs](self)).
pub struct ResponseCache<T: Clone + Send + 'static> {
    /// Each entry stores its value alongside the access tick at which it
    /// was last touched (read or written). The smallest tick identifies
    /// the least-recently-used entry — the eviction victim under cap
    /// pressure.
    inner: OnceLock<Mutex<HashMap<String, Entry<T>>>>,
    /// Hard ceiling on the number of entries. A `put()` of a new key that
    /// would exceed `cap` evicts the least-recently-used entry first.
    cap: usize,
    /// Monotonic access clock. Incremented on every `get()` hit and every
    /// `put()`; the current value is stamped onto the touched entry so the
    /// minimum stamp is always the LRU entry. Wrap-around is not a concern
    /// (`u64` at any realistic OSINT query rate outlives the process).
    clock: AtomicU64,
    /// Count of entries evicted to honour `cap`. Surfaced via
    /// [`ResponseCache::evictions`] so a saturating cache is observable
    /// instead of silently degrading hit rate to zero.
    evictions: AtomicU64,
}

/// A cached value plus the access tick at which it was last touched.
///
/// `tick` is the LRU key: lower means staler. Kept as a sibling of the
/// value (rather than a separate ordering structure) so the whole entry
/// moves atomically under the single `Mutex`.
struct Entry<T> {
    value: T,
    tick: u64,
}

impl<T: Clone + Send + 'static> ResponseCache<T> {
    /// `const fn` constructor so callers can declare
    /// `static CACHE: ResponseCache<Vec<Value>> = ResponseCache::new(1024)`.
    pub const fn new(cap: usize) -> Self {
        Self {
            inner: OnceLock::new(),
            cap,
            clock: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    /// Lazy-initialise the underlying `Mutex<HashMap>` on first
    /// access. Subsequent calls return the same handle.
    fn lock(&self) -> &Mutex<HashMap<String, Entry<T>>> {
        self.inner.get_or_init(|| {
            let initial = 256.min(self.cap);
            Mutex::new(HashMap::with_capacity(initial))
        })
    }

    /// Next value of the monotonic access clock. Each call yields a
    /// strictly larger tick than the previous one, giving a total order
    /// over accesses for LRU victim selection.
    fn next_tick(&self) -> u64 {
        // `fetch_add` returns the prior value; add one so the first tick
        // handed out is 1 (0 is reserved as "never touched", though no
        // live entry ever carries it).
        self.clock.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
    }

    /// Look up a key. Returns `Some(value.clone())` on hit, `None`
    /// on miss or lock poisoning.
    ///
    /// A hit moves the entry to the front of the LRU order (it stamps the
    /// entry with a fresh access tick), so frequently-read keys resist
    /// eviction under cap pressure.
    pub fn get(&self, key: &str) -> Option<T> {
        let tick = self.next_tick();
        let mut guard = self.lock().lock().ok()?;
        let entry = guard.get_mut(key)?;
        entry.tick = tick;
        Some(entry.value.clone())
    }

    /// Insert a value. No-ops only if the lock is poisoned (or if `cap`
    /// is zero, which admits nothing by construction).
    ///
    /// An in-place refresh of an existing key is always allowed — it
    /// can't grow the map — so a full cache never gets stuck serving a
    /// stale value for a key it already holds (PROBLEM_TREE T2.12). A new
    /// key that would exceed `cap` evicts the least-recently-used entry
    /// first, keeping `cap` a hard ceiling while preserving hot entries
    /// (true LRU, not a no-op-on-full drop).
    pub fn put(&self, key: String, value: T) {
        let tick = self.next_tick();
        let Ok(mut c) = self.lock().lock() else {
            return;
        };

        // In-place refresh: never grows the map, always admitted.
        if let Some(entry) = c.get_mut(&key) {
            entry.value = value;
            entry.tick = tick;
            return;
        }

        // New key. A zero cap admits nothing; bail before evicting so we
        // never thrash an always-empty cache.
        if self.cap == 0 {
            return;
        }

        // New key at (or somehow over) cap: evict the LRU entry to make
        // room. `>=` rather than `==` is defensive — the map can never
        // exceed `cap` under this code path, but the guard costs nothing
        // and makes the ceiling unconditional. The `let`-chain keeps the
        // ceiling check and victim lookup in one condition (matches the
        // edition-2024 idiom used elsewhere in this module).
        if c.len() >= self.cap
            && let Some(victim) = c.iter().min_by_key(|(_, e)| e.tick).map(|(k, _)| k.clone())
        {
            c.remove(&victim);
            let total = self
                .evictions
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            tracing::debug!(
                evicted_key = %victim,
                cap = self.cap,
                total_evictions = total,
                "response_cache: evicted least-recently-used entry to honour cap"
            );
        }

        c.insert(key, Entry { value, tick });
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

    /// Total number of entries evicted to honour `cap` over the lifetime
    /// of this cache.
    ///
    /// A non-zero (and growing) count means the cache is saturating: new
    /// keys are displacing old ones rather than all fitting under `cap`.
    /// Surfaced so operators and tests can detect a cache that has
    /// silently outgrown its sizing instead of discovering it as a
    /// mysterious hit-rate collapse.
    pub fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// Drop every entry. Intended for tests and operator-initiated
    /// flushes (e.g. after detecting API contract drift, since entries
    /// carry no TTL and never expire on their own); the production code
    /// path doesn't call this.
    ///
    /// The eviction counter is left intact — it is a lifetime metric, not
    /// a snapshot of live state.
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
