use super::*;

    // Serialise the tests that share the process-global SINK.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn identifies_foreign_keys_with_provenance_and_dedups() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        reset(""); // unscoped tests use the default bucket
        // A Stripe-style live key embedded in a record body, twice. Built from
        // fragments so the synthetic test key isn't a contiguous `sk_live_…`
        // literal in source (which trips repository secret-scanning / push
        // protection); `identify_api_key` still sees the assembled value.
        let synthetic = format!("sk_{}_{}", "live", "4eC39HqLyjWDarjtT1zdp7dc");
        let body = format!(r#"{{"note":"prod key {synthetic}", "dup":"{synthetic}"}}"#);
        scan_body("see-know", "victim@example.com", &body);
        let snap = snapshot("");
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
        assert!(!drain("").is_empty());
        assert!(snapshot("").is_empty());
    }

    #[test]
    fn generic_hex_hash_is_not_reported_as_a_key() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        reset(""); // unscoped tests use the default bucket
        // Breach data is full of 32-char MD5 hashes. The universal scan uses the
        // vendor-only identifier, so a bare hex hash is NOT misreported as a
        // retrieved API key (it's already captured as a Password entity by the
        // breach modules, and entropy-scanning every hash was the perf hot spot).
        let hash = "5e3706b9c16282351af9c3aac7107b54";
        scan_body("oathnet", "victim@example.com", &format!("hash={hash}"));
        assert!(
            snapshot("").is_empty(),
            "a bare hex hash must not become a foreign-key finding: {:?}",
            snapshot("")
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
        let _guard = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        reset(""); // unscoped tests use the default bucket
        // An operator's OWN configured key that happens to be vendor-shaped must
        // never be reported as a foreign finding. Build it from fragments so the
        // synthetic literal isn't a contiguous secret in source.
        let own = format!("sk_{}_{}", "live", "OWNkeyDoNotReport0123456789");
        insert_own_for_test(&own);
        scan_body("see-know", "q", &format!("leaked here: {own}"));
        assert!(
            snapshot("").iter().all(|f| f.key != own),
            "our own auth key must be excluded from findings"
        );
    }

    // ── Adversarial-input invariants (scan_body runs on hostile response bodies) ──

    #[test]
    fn scan_body_survives_multibyte_and_adversarial_input() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        reset(""); // unscoped tests use the default bucket
        let key = format!("sk_{}_{}", "live", "4eC39HqLyjWDarjtT1zdp7dc");
        // Multibyte UTF-8 tokens, NUL/control bytes, and a 200 KB delimiter-free
        // blob (a DoS attempt) all surround two delimited copies of a real key.
        // Invariant: no panic (tokens may be non-ASCII), the genuine key is still
        // recovered, and none of the noise fabricates a finding.
        let giant = "A".repeat(200_000);
        let body = format!("café résumé 日本語 \u{0}\u{1}\u{7f} {key} token={key} {giant}");
        scan_body("see-know", "café@example.com", &body); // must not panic
        let snap = snapshot("");
        assert!(
            snap.iter().any(|f| f.key == key),
            "real key must survive amid adversarial/multibyte noise"
        );
        assert_eq!(
            snap.len(),
            1,
            "adversarial noise must not fabricate keys: {snap:?}"
        );
    }

    #[test]
    fn scan_body_enforces_token_length_bounds() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        reset(""); // unscoped tests use the default bucket
        // A vendor-prefixed token longer than MAX_TOKEN is the DoS shape: it must
        // be rejected by the cheap length gate, never handed to the identifier.
        let oversized = format!("sk_{}_{}", "live", "x".repeat(MAX_TOKEN));
        // And a token shorter than MIN_TOKEN is below the floor.
        let undersized = "sk_live_x"; // 9 < 16
        scan_body("p", "q", &format!("{oversized} {undersized}"));
        assert!(
            snapshot("").is_empty(),
            "out-of-bounds tokens must yield no findings"
        );
    }

    #[test]
    fn key_tokens_uses_full_delimiter_set_and_length_window() {
        // `&`, `,`, and `[ ] "` are delimiters (the set the config-leak probe
        // used to omit), so a token followed by a query/array separator is
        // isolated rather than glued to the next field.
        let body = "a=ABCDEFGHIJKLMNOP&b=QRSTUVWXYZ012345,[\"deadbeefdeadbeef\"]";
        let toks: Vec<&str> = key_tokens(body, MAX_TOKEN).collect();
        assert!(
            toks.contains(&"ABCDEFGHIJKLMNOP"),
            "isolated by '&': {toks:?}"
        );
        assert!(
            toks.contains(&"QRSTUVWXYZ012345"),
            "isolated by ',': {toks:?}"
        );
        assert!(
            toks.contains(&"deadbeefdeadbeef"),
            "isolated by '[]\"': {toks:?}"
        );

        // Length window: sub-MIN and over-max tokens are dropped; exactly max kept.
        let short = "x".repeat(MIN_TOKEN - 1);
        let over = "y".repeat(MAX_TOKEN + 1);
        assert_eq!(key_tokens(&format!("{short} {over}"), MAX_TOKEN).count(), 0);
        let at_max = "z".repeat(MAX_TOKEN);
        assert_eq!(
            key_tokens(&at_max, MAX_TOKEN).collect::<Vec<_>>(),
            vec![at_max.as_str()]
        );
    }

    #[test]
    fn scan_body_is_quiet_on_empty_and_whitespace_bodies() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        reset(""); // unscoped tests use the default bucket
        scan_body("p", "q", "");
        scan_body("p", "q", "   \n\t  \r\n ");
        assert!(snapshot("").is_empty());
    }

    #[test]
    fn concurrent_scans_do_not_contaminate_each_others_found_keys() {
        // PROBLEM_TREE T2.11: with the process-global sink keyed by `scan_id` (via
        // the `SCAN` ambient the engine sets per scan + per spawned dispatch task),
        // two scans running at once each drain ONLY the keys IT found. Before the
        // fix the sink was unkeyed, so scan B's `reset` wiped A's in-progress keys
        // or B's `drain` harvested them (silent loss / mis-attribution). Two real
        // scopes, distinct keys, asserted no crossover.
        let _guard = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        reset("scan-a");
        reset("scan-b");
        // High-entropy values (the identifier has a 3.5 bits/char Shannon gate that
        // rejects low-diversity tokens); built from fragments so no contiguous
        // `sk_live_…` literal trips repository secret-scanning.
        let key_a = format!("sk_{}_{}", "live", "4eC39HqLyjWDarjtT1zdp7dc");
        let key_b = format!("sk_{}_{}", "live", "8fK2mPqR7nX3wZ9bV5cT1yJ6");
        with_scan_sync("scan-a", || {
            scan_body("provider-a", "victim-a", &format!("leak {key_a}"));
        });
        with_scan_sync("scan-b", || {
            scan_body("provider-b", "victim-b", &format!("leak {key_b}"));
        });
        let a = drain("scan-a");
        let b = drain("scan-b");
        assert_eq!(a.len(), 1, "scan-a must drain exactly its own key: {a:?}");
        assert_eq!(b.len(), 1, "scan-b must drain exactly its own key: {b:?}");
        assert_eq!(a[0].key, key_a, "scan-a got the wrong key");
        assert_eq!(a[0].provider, "provider-a");
        assert_eq!(b[0].key, key_b, "scan-b got the wrong key");
        assert_eq!(b[0].provider, "provider-b");
        // Buckets are independent: each was emptied by its own drain, no crossover.
        assert!(drain("scan-a").is_empty());
        assert!(drain("scan-b").is_empty());
    }

    /// Throughput baseline for the hot path (`scan_body` runs on EVERY response
    /// body). Reproducible evidence for the module's "skip generic-hex → faster"
    /// claim, and a regression tripwire for the tokeniser.
    ///
    /// Method: scan a deterministic ~256 KB body resembling a breach/stealer JSON
    /// record (emails, 32-hex hashes the vendor-only scan must skip cheaply, the
    /// odd real key) `iters` times; report MB/s = `bytes / min_wall`. Min-of-runs
    /// is the most stable single-machine estimator. Context: a debug build is
    /// ~10x slower than `--release`; treat the absolute number as a debug floor.
    /// Run: `cargo test -p huntsman-search-engine --lib \
    /// util::found_keys::tests::bench_scan_body_throughput -- --ignored --nocapture`.
    #[test]
    #[ignore = "throughput baseline; run with --ignored --nocapture"]
    fn bench_scan_body_throughput() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        reset(""); // unscoped tests use the default bucket
        let key = format!("sk_{}_{}", "live", "4eC39HqLyjWDarjtT1zdp7dc");
        let unit = format!(
            r#"{{"email":"victim@example.com","hash":"5e3706b9c16282351af9c3aac7107b54","ua":"Mozilla/5.0 (X11)","note":"{key}"}}"#
        );
        let body = unit.repeat(256 * 1024 / unit.len() + 1);
        let bytes = body.len();

        // Warm up, then take the min wall-time over several runs.
        for _ in 0..3 {
            scan_body("bench", "q", &body);
        }
        let mut best = std::time::Duration::MAX;
        for _ in 0..20 {
            let start = std::time::Instant::now();
            scan_body("bench", "q", &body);
            best = best.min(start.elapsed());
        }
        let mbps = bytes as f64 / best.as_secs_f64() / 1e6;
        eprintln!(
            "scan_body: {} KB body, {mbps:.1} MB/s (debug build)",
            bytes / 1024
        );
        assert!(best > std::time::Duration::ZERO);
    }
