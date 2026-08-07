use super::*;
    use serde_json::json;

    /// Serialises the tests that touch the process-global [`BUDGET`] and
    /// [`RESPONSE_CACHE`].
    ///
    /// Both are `static`, and `cargo test` runs this module's tests in
    /// parallel, so without this the cache tests were racing the budget tests
    /// for real: `reset_budget()` clears `RESPONSE_CACHE`, so one test firing it
    /// between another's `cache_put` and `cache_get` fails the second on a
    /// condition it never created. Every test that resets the budget, exhausts
    /// the cap, latches the quota, or asserts on the cache takes this first.
    ///
    /// `lock()` is unwrapped through the poison, not `expect`ed: a panicking
    /// test would otherwise poison the mutex and cascade into unrelated
    /// failures that hide the one real failure.
    static BUDGET_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn budget_test_guard() -> std::sync::MutexGuard<'static, ()> {
        BUDGET_TEST_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn resolve_key_uses_provided_when_non_empty() {
        assert_eq!(resolve_key(Some("my-key")), "my-key");
    }

    #[test]
    fn resolve_key_falls_back_to_hardcoded_when_none() {
        assert_eq!(resolve_key(None), HARDCODED_KEY);
    }

    #[test]
    fn resolve_key_falls_back_to_hardcoded_when_empty() {
        assert_eq!(resolve_key(Some("")), HARDCODED_KEY);
    }

    #[test]
    fn build_search_url_appends_search_id_only_when_a_session_is_supplied() {
        // The session id is threaded in explicitly (T2.11: it used to be read
        // from a single-slot process-global a concurrent scan could clobber). No
        // session ⇒ no `search_id`; a session ⇒ exactly that id, url-encoded.
        let no_sess =
            build_search_url("https://api", "/breach/search", "email", "a@b.com", 100, None);
        assert_eq!(
            no_sess,
            "https://api/breach/search?email%5B%5D=a%40b.com&page_size=100&sort=indexed_at:desc"
        );
        assert!(
            !no_sess.contains("search_id"),
            "no session ⇒ no search_id param, got {no_sess}"
        );

        let with_sess = build_search_url(
            "https://api",
            "/breach/search",
            "email",
            "a@b.com",
            100,
            Some("sess/42"),
        );
        // Same base query, plus the session id appended and url-encoded (the `/`
        // becomes %2F) so a raw session id can never break the query string.
        assert_eq!(
            with_sess,
            "https://api/breach/search?email%5B%5D=a%40b.com&page_size=100&sort=indexed_at:desc&search_id=sess%2F42"
        );
    }

    #[test]
    fn enrich_with_breach_dates_stamps_from_the_rows_own_dbname_only() {
        let items = vec![
            json!({"dbname": "poshmark.com", "email": "a@x.com"}),
            // A dbname with no dbname_info entry — untouched.
            json!({"dbname": "unknown-db.com", "email": "b@x.com"}),
            // Already carries its own breach_date — never overridden.
            json!({"dbname": "poshmark.com", "email": "c@x.com", "breach_date": "1999-01-01"}),
            // Not an object — passed through unchanged, no panic.
            json!("not-an-object"),
        ];
        let mut dbname_info = std::collections::HashMap::new();
        dbname_info.insert(
            "poshmark.com".to_string(),
            DbMeta {
                breach_date: Some("2018-05-16".to_string()),
            },
        );
        // wattpad.com has no BreachDate on this response — items from it must
        // stay unenriched, not stamped with an empty/garbage value.
        dbname_info.insert("wattpad.com".to_string(), DbMeta { breach_date: None });

        let out = enrich_with_breach_dates(items, &dbname_info);

        assert_eq!(
            out[0].get("breach_date").and_then(Value::as_str),
            Some("2018-05-16"),
            "a row whose dbname has a BreachDate must be stamped"
        );
        assert!(
            out[1].get("breach_date").is_none(),
            "a row whose dbname has no dbname_info entry must stay unstamped"
        );
        assert_eq!(
            out[2].get("breach_date").and_then(Value::as_str),
            Some("1999-01-01"),
            "a row's own pre-existing breach_date must never be overridden"
        );
        assert_eq!(out[3], json!("not-an-object"), "non-object rows pass through");
    }

    #[test]
    fn enrich_with_breach_dates_is_a_no_op_when_dbname_info_is_empty() {
        // The common case for non-breach-search endpoints (e.g. stealer search,
        // which has no dbname_info block at all): items must be returned exactly
        // as given, not merely "not stamped" but structurally untouched.
        let items = vec![json!({"dbname": "x.com", "email": "a@x.com"})];
        let out = enrich_with_breach_dates(items.clone(), &std::collections::HashMap::new());
        assert_eq!(out, items);
    }

    #[test]
    fn budget_try_increment_enforces_a_finite_scan_cap() {
        // PROBLEM_TREE T2.11: oathnet's quota gate must be the atomic reserve
        // (`try_increment`/CAS), not the racy `remaining()`-then-`increment()` that
        // two concurrent `serve` scans could both pass — overspending the
        // operator's PAID cap. Pin that the gate enforces a finite per-scan cap and
        // stays refused once reached (the CAS correctness itself is covered by the
        // `util::budget` unit tests; this asserts oathnet routes through it).
        let _guard = budget_test_guard();
        reset_budget();
        let mut ok = 0u32;
        while budget_try_increment() {
            ok += 1;
            assert!(ok < 10_000, "gate never refuses — the per-scan cap is unenforced");
        }
        assert!(ok >= 1, "gate refused from the very first reserve");
        assert!(!budget_try_increment(), "must stay refused once the cap is hit");
        reset_budget();
    }

    #[test]
    fn reset_budget_clears_the_cross_module_response_cache() {
        // Regression: RESPONSE_CACHE dedups identical queries WITHIN one scan
        // (its own doc comment), but reset_budget() previously only reset the
        // quota counters -- a long-lived `hse serve`/`hse live` process would
        // silently keep serving the FIRST scan's cached breach records for
        // every later re-scan of the same value, forever, with no live
        // re-check. reset_budget() must also clear the cache.
        let _guard = budget_test_guard();
        let key = "reset_budget_clears_cache_test_key";
        cache_put(
            key.to_string(),
            vec![json!({"stale": true})],
            Completeness::Complete,
        );
        assert!(
            cache_get(key).is_some(),
            "sanity: the cache must actually hold the value before reset"
        );
        reset_budget();
        assert!(
            cache_get(key).is_none(),
            "reset_budget() must clear RESPONSE_CACHE so a new scan re-queries live"
        );
    }

    #[test]
    fn val_str_extracts_string_field() {
        let v = json!({"name": "alice", "age": 30});
        assert_eq!(val_str(&v, "name"), Some("alice".to_string()));
    }

    #[test]
    fn val_str_returns_none_for_missing_field() {
        let v = json!({"name": "alice"});
        assert_eq!(val_str(&v, "missing"), None);
    }

    #[test]
    fn val_str_returns_none_for_empty_string() {
        let v = json!({"name": ""});
        assert_eq!(val_str(&v, "name"), None);
    }

    #[test]
    fn val_str_returns_none_for_non_string() {
        let v = json!({"count": 42});
        assert_eq!(val_str(&v, "count"), None);
    }

    #[test]
    fn val_str_or_returns_first_match() {
        let v = json!({"email": "a@b.com", "login": "alice"});
        assert_eq!(
            val_str_or(&v, &["missing", "email", "login"]),
            Some("a@b.com".to_string())
        );
    }

    #[test]
    fn val_str_or_returns_none_when_all_missing() {
        let v = json!({"x": 1});
        assert_eq!(val_str_or(&v, &["a", "b", "c"]), None);
    }

    #[test]
    fn top_dbnames_ranks_by_frequency() {
        let items = vec![
            json!({"dbname": "linkedin"}),
            json!({"dbname": "adobe"}),
            json!({"dbname": "linkedin"}),
            json!({"dbname": "adobe"}),
            json!({"dbname": "adobe"}),
            json!({"dbname": "myspace"}),
        ];
        let top = top_dbnames(&items, 2);
        assert_eq!(top[0], "adobe");
        assert_eq!(top[1], "linkedin");
        assert_eq!(top.len(), 2);
    }

    #[test]
    fn top_dbnames_empty_input() {
        assert!(top_dbnames(&[], 5).is_empty());
    }

    #[test]
    fn top_dbnames_is_deterministic_on_count_ties() {
        // Equal-count db names must resolve by name ascending — not by the source
        // HashMap's randomised iteration order — so the persisted `top_dbnames`
        // attribute is byte-reproducible and `take(n)` on a boundary tie is stable.
        // `top` appears twice; `alpha`/`mid`/`zeta` once each. Re-seed repeatedly.
        let mk = || {
            vec![
                json!({"dbname": "zeta"}),
                json!({"dbname": "top"}),
                json!({"dbname": "alpha"}),
                json!({"dbname": "top"}),
                json!({"dbname": "mid"}),
            ]
        };
        for _ in 0..16 {
            // `top` (2) first, then the count-1 tie in name order → boundary is exact.
            assert_eq!(top_dbnames(&mk(), 3), vec!["top", "alpha", "mid"]);
        }
    }

    #[test]
    fn session_init_body_escapes_every_value_via_serde() {
        // The hand-rolled quote-only escaping produced INVALID JSON for a value
        // with a backslash and mis-decoded literal `\n`/`\t`; serde escapes
        // correctly, so the body always parses back to the exact query value.
        for value in [
            "plain",
            r#"has"quote"#,
            r#"back\slash"#,
            "tab\tand\nnewline",
            "a\\\"b",
        ] {
            let body = session_init_body(value);
            let parsed: serde_json::Value =
                serde_json::from_str(&body).expect("session-init body must be valid JSON");
            assert_eq!(parsed["query"], value, "query round-trips exactly for {value:?}");
        }
    }

    #[test]
    fn top_dbnames_skips_items_without_dbname() {
        let items = vec![json!({"other": "val"}), json!({"dbname": "x"})];
        let top = top_dbnames(&items, 10);
        assert_eq!(top, vec!["x"]);
    }

    #[test]
    fn top_dbnames_ties_break_alphabetically_not_by_hashmap_order() {
        // 10 distinct dbnames, each appearing exactly once — a full tie at
        // every rank. Without a deterministic tie-break, which 5 of the 10
        // land in the top-5 cutoff (and in what order) depends on the
        // process-random `HashMap` iteration order the counts are collected
        // through, so two identical scans could report a different set of
        // "top" breach databases for the same subject. With the fix, the
        // result is always the alphabetically-first 5 — the same every call.
        let items = vec![
            json!({"dbname": "zebra"}),
            json!({"dbname": "yankee"}),
            json!({"dbname": "xray"}),
            json!({"dbname": "whiskey"}),
            json!({"dbname": "victor"}),
            json!({"dbname": "uniform"}),
            json!({"dbname": "tango"}),
            json!({"dbname": "sierra"}),
            json!({"dbname": "romeo"}),
            json!({"dbname": "quebec"}),
        ];
        let top = top_dbnames(&items, 5);
        assert_eq!(
            top,
            vec!["quebec", "romeo", "sierra", "tango", "uniform"],
            "a full tie must resolve deterministically (alphabetically), not by HashMap iteration order"
        );
    }

    #[test]
    fn distinct_field_aggregates_every_record_additively() {
        // Regression guard: a last-write-wins overwrite would keep only "GB" and
        // only the final name. The additive aggregator retains ALL distinct
        // values across records, in first-seen order.
        let items = vec![
            json!({"country": "AU", "full_name": "Haigen Bamford"}),
            json!({"country": "GB", "full_name": "H Bamford"}),
            json!({"country": "AU", "full_name": "Haigen Bamford"}),
            json!({"full_name": "Haigen R Bamford"}),
        ];
        assert_eq!(distinct_field(&items, "country"), vec!["AU", "GB"]);
        assert_eq!(
            distinct_field(&items, "full_name"),
            vec!["Haigen Bamford", "H Bamford", "Haigen R Bamford"]
        );
    }

    #[test]
    fn distinct_field_skips_empty_and_absent_values() {
        let items = vec![
            json!({"country": ""}),
            json!({"other": "x"}),
            json!({"country": "AU"}),
        ];
        assert_eq!(distinct_field(&items, "country"), vec!["AU"]);
        assert!(distinct_field(&[], "country").is_empty());
    }

    #[test]
    fn paths_are_non_empty() {
        assert!(!paths::BREACH.is_empty());
        assert!(!paths::STEALER.is_empty());
    }

    #[test]
    fn surface_maps_to_its_path_and_label() {
        assert_eq!(Surface::Breach.path(), paths::BREACH);
        assert_eq!(Surface::Stealer.path(), paths::STEALER);
        assert_eq!(Surface::Breach.label(), "breach");
        assert_eq!(Surface::Stealer.label(), "stealer");
    }

    #[test]
    fn surface_max_page_size_matches_the_documented_per_endpoint_ceiling() {
        // docs/OATHNET_API_GUIDE.txt §11: Breach Search max 1000, V2 Stealer
        // max 100 — they differ, so a shared batch page_size must be clamped
        // per surface, not passed through uncapped.
        assert_eq!(Surface::Breach.max_page_size(), 1000);
        assert_eq!(Surface::Stealer.max_page_size(), 100);
    }

    #[test]
    fn continuation_cursor_requires_both_has_more_and_a_real_cursor() {
        assert_eq!(
            continuation_cursor(true, Some("abc123".to_string())),
            Some("abc123".to_string()),
            "has_more + a cursor: continue"
        );
        assert_eq!(
            continuation_cursor(true, None),
            None,
            "has_more but no cursor supplied: nothing to continue with"
        );
        assert_eq!(
            continuation_cursor(false, Some("abc123".to_string())),
            None,
            "no more pages: a stray cursor must not force another fetch"
        );
        assert_eq!(continuation_cursor(false, None), None);
    }

    #[test]
    fn search_data_deserialises_the_real_live_confirmed_envelope_shape() {
        // Live-confirmed 2026-07-15 against the REAL
        // `GET /service/v2/breach/search`: the pagination block is keyed
        // "meta" (no underscore) and next_cursor is a SIBLING of it, not
        // nested inside — NOT the shape `docs/OATHNET_API_GUIDE.txt` §3.1's
        // illustrative example shows (data._meta with next_cursor nested
        // inside it). This exact shape (trimmed to the pagination-relevant
        // fields; the real response also carries dbname_info and a
        // top-level, sibling-of-data `_meta.lookups.left_today` quota
        // block) reproduces a real captured response, not a guess at the
        // documented contract.
        // Before this test existed, `search_data_deserialises_the_real_
        // documented_envelope_shape` pinned the WRONG (doc-derived) shape
        // and passed regardless — it validated the code against the same
        // wrong reference the code itself was wrong against, so it could
        // never have caught this bug.
        let raw = json!({
            "items": [{"email": "a@example.com"}, {"email": "b@example.com"}],
            "meta": {
                "count": 2,
                "total": 1234,
                "took_ms": 42,
                "has_more": true,
                "total_pages": 83,
                "filter_id": "de0f31fbf94f7ad2c5916d06"
            },
            "next_cursor": "Wzc2NzYwOF0="
        });
        let sd: SearchData = serde_json::from_value(raw).expect("must deserialise");
        assert_eq!(sd.items.len(), 2);
        let meta = sd.meta.expect("meta must parse");
        assert!(meta.has_more);
        assert_eq!(
            sd.next_cursor.as_deref(),
            Some("Wzc2NzYwOF0="),
            "next_cursor lives at the data level, a sibling of meta, not nested inside it"
        );
    }

    #[test]
    fn search_data_still_accepts_the_documented_underscore_meta_shape() {
        // Defense-in-depth: `docs/OATHNET_API_GUIDE.txt` §3.1's illustrative
        // `_meta`-nested shape was proven wrong for breach search (see the
        // test above), but the alias is kept in case another surface
        // (stealer, victims) or a future response variant genuinely uses
        // it — this pins that the fallback path still works.
        let raw = json!({
            "items": [{"email": "a@example.com"}],
            "_meta": {
                "has_more": true,
                "next_cursor": "sess_cursor_abc"
            }
        });
        let sd: SearchData = serde_json::from_value(raw).expect("must deserialise");
        let meta = sd.meta.expect("_meta alias must parse");
        assert!(meta.has_more);
        assert_eq!(
            sd.next_cursor, None,
            "no top-level next_cursor in this shape"
        );
        assert_eq!(
            meta.next_cursor.as_deref(),
            Some("sess_cursor_abc"),
            "falls back to the nested location when no top-level cursor is present"
        );
    }

    #[test]
    fn search_data_defaults_meta_when_absent() {
        // A final page (has_more: false) may omit meta's continuation
        // fields entirely, or the whole block — must not fail to parse.
        let raw = json!({"items": []});
        let sd: SearchData = serde_json::from_value(raw).expect("must deserialise");
        assert!(sd.items.is_empty());
        assert!(sd.meta.is_none());
        assert!(sd.next_cursor.is_none());
    }

    #[test]
    fn real_quota_from_envelope_parses_the_real_live_confirmed_shape() {
        // Verbatim (trimmed to the quota-relevant fields) from a real
        // `GET /service/v2/breach/search` response captured live
        // 2026-07-15 — a genuine top-level `_meta.lookups` block, not a
        // guess at the documented contract.
        let raw = json!({
            "success": true,
            "message": "V2-Breach-Search completed successfully",
            "data": {"items": []},
            "_meta": {
                "user": {"plan": "Pro", "plan_type": "pro", "is_plan_active": true, "is_authenticated": true},
                "lookups": {"used_today": 3, "left_today": 497, "daily_limit": 500, "is_unlimited": false},
                "service": {"name": "V2 Breach Search"},
                "performance": {"duration_ms": 25.14}
            }
        });
        let env: Envelope = serde_json::from_value(raw).expect("must deserialise");
        let q = real_quota_from_envelope(&env).expect("real quota must parse");
        assert_eq!(q.used_today, 3);
        assert_eq!(q.left_today, 497);
        assert_eq!(q.daily_limit, Some(500));
        assert!(!q.is_unlimited);
    }

    #[test]
    fn real_quota_from_envelope_is_none_without_a_meta_block() {
        let raw = json!({"success": true, "data": {"items": []}});
        let env: Envelope = serde_json::from_value(raw).expect("must deserialise");
        assert!(real_quota_from_envelope(&env).is_none());
    }

    #[test]
    fn real_quota_updates_in_place_and_is_readable_via_the_public_getter() {
        let q1 = RealQuota {
            used_today: 3,
            left_today: 497,
            daily_limit: Some(500),
            is_unlimited: false,
        };
        record_real_quota(q1);
        assert_eq!(real_quota(), Some(q1));
        // A later observation overwrites — the newest response is always
        // the most accurate, never averaged/merged with a stale one.
        let q2 = RealQuota {
            used_today: 4,
            left_today: 496,
            daily_limit: Some(500),
            is_unlimited: false,
        };
        record_real_quota(q2);
        assert_eq!(real_quota(), Some(q2));
    }

    #[test]
    fn selector_field_covers_every_indexed_kind_and_only_those() {
        use crate::core::scan::TargetKind;
        assert_eq!(selector_field(TargetKind::Email), Some("email"));
        assert_eq!(selector_field(TargetKind::Username), Some("username"));
        assert_eq!(selector_field(TargetKind::Phone), Some("phone"));
        assert_eq!(selector_field(TargetKind::FullName), Some("q"));
        assert_eq!(selector_field(TargetKind::IpAddress), Some("ip"));
        assert_eq!(selector_field(TargetKind::Domain), Some("domain"));
        // A kind OathNet does not index.
        assert_eq!(selector_field(TargetKind::Url), None);
    }

    #[test]
    fn stealer_indexable_only_for_login_fields() {
        assert!(stealer_indexable("email"));
        assert!(stealer_indexable("username"));
        for f in ["phone", "q", "ip", "domain"] {
            assert!(!stealer_indexable(f), "{f} is breach-only");
        }
        // Every login-indexable field must itself be a real selector field.
        use crate::core::scan::TargetKind;
        for kind in [TargetKind::Email, TargetKind::Username] {
            let f = selector_field(kind).expect("should succeed");
            assert!(stealer_indexable(f));
        }
    }

    // ── cache_key ─────────────────────────────────────────────────────────────

    #[test]
    fn cache_key_lays_out_path_field_value() {
        assert_eq!(
            cache_key("search", "email", "user@example.com"),
            "search:email:user@example.com"
        );
    }

    #[test]
    fn cache_key_lowercases_only_the_value() {
        // The value is folded to lowercase so case-variant lookups hit one entry;
        // path and field are passed through verbatim.
        assert_eq!(
            cache_key("Search", "Email", "USER@Example.COM"),
            "Search:Email:user@example.com"
        );
    }

    #[test]
    fn cache_key_collapses_case_variant_values_to_one_key() {
        assert_eq!(
            cache_key("p", "f", "AzBy"),
            cache_key("p", "f", "azby"),
            "values differing only in case must share a cache key"
        );
    }

    // ── key_fingerprint ───────────────────────────────────────────────────────

    #[test]
    fn key_fingerprint_empty_key_is_labelled_no_key() {
        assert_eq!(key_fingerprint(""), "oathnet.org:(no key)");
        assert_eq!(key_fingerprint("   "), "oathnet.org:(no key)");
    }

    #[test]
    fn key_fingerprint_short_key_shown_in_full() {
        // ≤12 chars: no elision, the (already short) key is shown verbatim.
        assert_eq!(key_fingerprint("abc123"), "oathnet.org:abc123");
        assert_eq!(key_fingerprint("twelvechars0"), "oathnet.org:twelvechars0");
    }

    #[test]
    fn key_fingerprint_long_key_elides_middle() {
        // >12 chars: head8…tail4 with a real ellipsis codepoint.
        assert_eq!(
            key_fingerprint("0123456789abcdef"),
            "oathnet.org:01234567\u{2026}cdef"
        );
    }

    #[test]
    fn key_fingerprint_trims_surrounding_whitespace() {
        assert_eq!(key_fingerprint("  abc123  "), "oathnet.org:abc123");
    }

    #[test]
    fn effective_error_status_prefers_the_bodys_reported_status_when_present() {
        assert_eq!(effective_error_status(Some(404), 200), 404);
    }

    #[test]
    fn effective_error_status_falls_back_to_the_real_http_status_when_the_body_omits_it() {
        // A 404/429/5xx response whose body doesn't conform to the
        // documented `errors.status_code` shape (a proxy/gateway error page,
        // a differently-shaped error schema) must still be classified
        // correctly from the REAL transport-layer status `search()` now
        // gets from `CurlClient::get_with_status` — not silently fall
        // through to a generic error that discards already-paginated
        // results.
        assert_eq!(effective_error_status(None, 404), 404);
        assert_eq!(effective_error_status(None, 429), 429);
        assert_eq!(effective_error_status(None, 503), 503);
    }

    #[test]
    fn effective_error_status_treats_a_body_reported_zero_as_absent() {
        // `status_code: 0` in the body is not a real HTTP status — it must
        // not shadow a genuine transport-layer status.
        assert_eq!(effective_error_status(Some(0), 500), 500);
    }

    // ─── An incomplete enumeration must keep saying so ──────────────────────

    /// A truncated page-set is real data that is NOT the whole answer, and the
    /// distinction has to survive the cache.
    ///
    /// `cache_put` runs on every exit from `search`, including the five that
    /// stop pagination short. Before completeness was cached alongside the
    /// items, the SECOND caller for the same `(path, field, value)` — a
    /// different module in the same scan, which is the whole point of this
    /// cache — got the truncated set with no marker at all, not even the log
    /// line the first call emitted.
    #[test]
    fn truncation_survives_the_response_cache() {
        let _guard = budget_test_guard();
        let key = "truncation_survives_cache_test_key";
        let partial = cache_put(
            key.to_string(),
            vec![json!({"row": 1})],
            Completeness::BudgetExhausted,
        );
        assert!(partial.completeness.is_partial());

        let hit = cache_get(key).expect("the value must be cached");
        assert_eq!(
            hit.completeness,
            Completeness::BudgetExhausted,
            "a cache hit must report the same completeness the original call did, \
             or the second module in a scan is told a partial set is complete"
        );
        assert!(hit.completeness.is_partial());
        reset_budget();
    }

    /// A query refused before any request is made must record WHICH door
    /// closed, and must not be cached.
    ///
    /// Both refusals used to return `Completeness::Complete` — the same
    /// conflation this type exists to remove, made at the worst place in the
    /// module: neither exit performs a request, so not even the `debug!` line
    /// the mid-pagination stops emit would have appeared. An operator reading a
    /// dossier saw "nothing found" for a query that was never asked.
    ///
    /// Hermetic and offline: the guard returns before the first HTTP call, so
    /// the key is never used and no network is touched. `example.com` is
    /// reserved (RFC 2606) and would be a dead lookup even if one escaped.
    ///
    /// Deliberately a plain `#[test]` driving its own current-thread runtime
    /// rather than `#[tokio::test]`. [`search`] is async, but the shared-state
    /// guard above is a `std::sync::MutexGuard`, and holding one across an
    /// `.await` is exactly the defect `clippy::await_holding_lock` exists to
    /// catch — it fired here. `block_on` blocks this thread instead, so the
    /// guard is never held across a yield point, and a single future on a
    /// private runtime has nothing to interleave with anyway.
    #[test]
    fn a_query_refused_at_the_door_records_which_one_closed() {
        let _guard = budget_test_guard();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime must build");

        let door = |key: &'static str| {
            rt.block_on(search(
                key,
                paths::BREACH,
                "email",
                "door-guard@example.com",
                10,
                None,
            ))
            .expect("the door returns Ok carrying a reason, never an Err")
        };

        // 1. The operator's own scan/session cap, with the provider latch clear.
        reset_budget();
        while budget_try_increment() {}
        let refused = door("unused-the-guard-returns-first");
        assert!(refused.items.is_empty(), "no request was made");
        assert_eq!(
            refused.completeness,
            Completeness::BudgetExhausted,
            "the operator's own cap biting is not the provider's daily quota — \
             raising the cap spends money, waiting out a quota does not"
        );
        assert!(refused.completeness.is_partial());

        // A refusal says nothing about (path, field, value) — only about budget
        // state right now. Caching it would pin a transient refusal onto this
        // target for the life of the process, and the next scan's reset_budget()
        // would no longer be enough to let it re-query live.
        assert!(
            cache_get(&cache_key(paths::BREACH, "email", "door-guard@example.com")).is_none(),
            "a query that never ran must not be cached as its own answer"
        );

        // 2. The provider's daily quota, on a budget with room to spare.
        reset_budget();
        mark_quota_exhausted();
        let refused = door("unused-the-guard-returns-first");
        assert!(refused.items.is_empty());
        assert_eq!(
            refused.completeness,
            Completeness::QuotaExhausted,
            "an already-latched provider quota must not read as the operator's cap"
        );

        // 3. A persistent 429 latches BOTH — the quota latch to stop the scan
        // re-firing, the rate-limit latch to record why. The door must report
        // the why. Reading the quota latch first would tell the operator to
        // wait hours for a daily reset when a short retry was the answer.
        reset_budget();
        mark_quota_exhausted();
        mark_rate_limited();
        let refused = door("unused-the-guard-returns-first");
        assert!(refused.items.is_empty());
        assert_eq!(
            refused.completeness,
            Completeness::RateLimited,
            "a stop caused by a persistent 429 must not be reported as a spent daily quota — \
             the two need opposite operator responses"
        );

        // The latch is per-scan: a rate limit one scan hit must not bench the
        // provider for every later scan in a long-lived `serve`/`live` process.
        reset_budget();
        assert!(
            !is_rate_limited(),
            "reset_budget() must clear the rate-limit latch at the scan boundary"
        );
    }

    /// Each stop reason is distinct and carries an operator-actionable message.
    /// They are deliberately not collapsed into one `truncated: bool`: raising
    /// the scan cap spends money, a daily quota needs waiting out, a rate limit
    /// needs a retry, and a missing cursor is a provider bug worth reporting.
    #[test]
    fn every_partial_reason_is_distinct_and_actionable() {
        assert_eq!(Completeness::Complete.reason(), None);
        assert!(!Completeness::Complete.is_partial());

        let partial = [
            Completeness::BudgetExhausted,
            Completeness::QuotaExhausted,
            Completeness::RateLimited,
            Completeness::CursorMissing,
            Completeness::PageVanished,
        ];
        let mut seen = std::collections::HashSet::new();
        for c in partial {
            assert!(c.is_partial(), "{c:?} must count as partial");
            let r = c.reason().expect("a partial result must explain itself");
            assert!(!r.is_empty());
            assert!(seen.insert(r), "{c:?} reuses another variant's reason: {r}");
        }
        assert_eq!(seen.len(), 5, "all five partial reasons must be distinct");
    }

    #[test]
    fn quota_config_provides_runtime_defaults() {
        let config = crate::util::quota_config::oathnet_quota();
        assert_eq!(config.per_scan_limit, 4, "default per-scan limit should be 4");
        assert_eq!(
            config.daily_limit, 10000,
            "default daily limit should be 10000"
        );

        let snapshot = budget_snapshot();
        assert!(
            snapshot.scan_cap >= config.per_scan_limit,
            "configured per-scan limit should influence the budget cap"
        );
    }
