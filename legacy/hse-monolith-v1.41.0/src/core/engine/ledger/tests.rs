use super::*;

    fn key(v: &str) -> DispatchKey {
        ("hibp", TargetKind::Email, v.to_string())
    }

    #[test]
    fn evicts_oldest_when_capped() {
        // Small cap to exercise FIFO eviction without inserting 100k keys
        // (same-module test, so the private fields are reachable).
        let mut log = DispatchLog {
            seen: HashSet::new(),
            order: VecDeque::new(),
            cap: 3,
        };
        assert!(log.insert(key("a")));
        assert!(log.insert(key("b")));
        assert!(log.insert(key("c")));
        assert!(log.insert(key("d"))); // over cap → evicts the oldest ("a")
        assert!(
            log.len() <= 3,
            "ledger ({}) must stay within the cap",
            log.len()
        );
        // Recently-seen keys are still deduped (retained — never re-queried)...
        assert!(!log.insert(key("d")));
        assert!(!log.insert(key("c")));
        // ...but the long-evicted oldest seed legitimately dispatches again.
        assert!(log.insert(key("a")), "evicted key must be treated as new");
    }

    /// `remove` must release a key for legitimate re-dispatch (the MissingKey
    /// opt-out path) AND keep the FIFO eviction order exact: a stale order
    /// entry left behind by remove would, at eviction time, delete a
    /// re-inserted LIVE key from the seen-set.
    #[test]
    fn remove_releases_key_and_keeps_eviction_exact() {
        let mut log = DispatchLog {
            seen: HashSet::new(),
            order: VecDeque::new(),
            cap: 2,
        };
        assert!(log.insert(key("a")));
        log.remove(&key("a"));
        assert!(log.is_empty());
        // Released key re-dispatches.
        assert!(log.insert(key("a")), "removed key must be insertable again");

        // Eviction exactness: after remove + re-insert, filling past the cap
        // must evict in true insertion order — "a" (the oldest live key) goes
        // first, not a phantom left by the earlier remove.
        assert!(log.insert(key("b")));
        assert!(log.insert(key("c"))); // cap 2 → evicts "a"
        assert_eq!(log.len(), 2);
        assert!(
            log.insert(key("a")),
            "evicted key legitimately re-dispatches"
        );
        assert!(!log.insert(key("c")), "recent key still deduped");
    }
