//! Simple in-memory response caching for expensive API queries.
//!
//! Caches SeekNow responses by (target_value, query_type) to avoid redundant
//! queries for identical searches across multiple scans. Dramatically improves
//! budget efficiency, especially for high-volume scans of overlapping entities.
//!
//! Cache is session-scoped (cleared between runs) and never persisted, ensuring
//! freshness while maximizing within-session reuse.

use parking_lot::RwLock;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Global session-scoped response cache accessor.
fn response_cache() -> &'static RwLock<ResponseCache> {
    static CACHE: OnceLock<RwLock<ResponseCache>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(ResponseCache::new()))
}

/// Cache key: (target_value, query_type) — uniquely identifies a SeekNow query.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct CacheKey {
    target: String,
    query_type: String,
}

/// In-memory cache of SeekNow API responses, indexed by (target, query_type).
#[derive(Debug)]
struct ResponseCache {
    entries: HashMap<CacheKey, Value>,
}

impl ResponseCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Attempt to retrieve a cached response for this (target, query_type) pair.
    fn get(&self, target: &str, query_type: &str) -> Option<Value> {
        let key = CacheKey {
            target: target.to_lowercase(),
            query_type: query_type.to_string(),
        };
        self.entries.get(&key).cloned()
    }

    /// Store a response in the cache.
    fn set(&mut self, target: &str, query_type: &str, response: Value) {
        let key = CacheKey {
            target: target.to_lowercase(),
            query_type: query_type.to_string(),
        };
        self.entries.insert(key, response);
    }

    /// Clear all cached entries (called at scan boundaries).
    fn clear(&mut self) {
        self.entries.clear();
    }

    /// Return cache hit count (for metrics/debugging).
    fn size(&self) -> usize {
        self.entries.len()
    }
}

/// Check cache for a SeekNow response by (target_value, query_type).
pub fn get_cached_response(target: &str, query_type: &str) -> Option<Value> {
    response_cache().read().get(target, query_type)
}

/// Store a SeekNow response in the cache.
pub fn cache_response(target: &str, query_type: &str, response: Value) {
    response_cache().write().set(target, query_type, response);
}

/// Clear the session cache (called between scans).
pub fn clear_session_cache() {
    response_cache().write().clear();
}

/// Return the current cache size (for metrics/debugging).
pub fn cache_size() -> usize {
    response_cache().read().size()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_stores_and_retrieves_responses() {
        clear_session_cache();
        let target = "test@example.com";
        let query_type = "email";
        let response = serde_json::json!({"status": "found", "records": 5});

        assert_eq!(get_cached_response(target, query_type), None);
        cache_response(target, query_type, response.clone());
        assert_eq!(get_cached_response(target, query_type), Some(response));
    }

    #[test]
    fn cache_is_case_insensitive_for_targets() {
        clear_session_cache();
        let response = serde_json::json!({"status": "found"});
        cache_response("Test@Example.COM", "email", response.clone());
        assert_eq!(get_cached_response("test@example.com", "email"), Some(response));
    }

    #[test]
    fn cache_distinguishes_by_query_type() {
        clear_session_cache();
        let r1 = serde_json::json!({"type": "email_search"});
        let r2 = serde_json::json!({"type": "domain_search"});
        let target = "example.com";

        cache_response(target, "email", r1.clone());
        cache_response(target, "domain", r2.clone());

        assert_eq!(get_cached_response(target, "email"), Some(r1));
        assert_eq!(get_cached_response(target, "domain"), Some(r2));
    }

    #[test]
    fn clear_empties_cache() {
        cache_response("test", "query", serde_json::json!({}));
        assert!(cache_size() > 0);
        clear_session_cache();
        assert_eq!(cache_size(), 0);
    }
}
