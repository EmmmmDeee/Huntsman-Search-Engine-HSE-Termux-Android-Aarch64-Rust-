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

    #[test]
    fn full_cache_still_refreshes_an_existing_key() {
        // T2.12: at cap, a NEW key is rejected (the ceiling holds), but an in-place
        // refresh of a key already present must still apply — a full cache must
        // never get stuck serving a stale value for a key it already holds.
        let c: ResponseCache<u32> = ResponseCache::new(2);
        c.put("a".into(), 1);
        c.put("b".into(), 2); // now at cap
        c.put("c".into(), 3); // new key: rejected (ceiling holds)
        assert_eq!(c.get("c"), None, "new key must be rejected at cap");
        assert_eq!(c.len(), 2);
        c.put("a".into(), 99); // existing key: must refresh despite being full
        assert_eq!(c.get("a"), Some(99), "existing key must refresh when full");
        assert_eq!(c.len(), 2, "refresh must not grow the map past cap");
    }
