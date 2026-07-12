use super::*;
    use serde_json::json;

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
    fn budget_try_increment_enforces_a_finite_scan_cap() {
        // PROBLEM_TREE T2.11: oathnet's quota gate must be the atomic reserve
        // (`try_increment`/CAS), not the racy `remaining()`-then-`increment()` that
        // two concurrent `serve` scans could both pass — overspending the
        // operator's PAID cap. Pin that the gate enforces a finite per-scan cap and
        // stays refused once reached (the CAS correctness itself is covered by the
        // `util::budget` unit tests; this asserts oathnet routes through it).
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
        let key = "reset_budget_clears_cache_test_key";
        cache_put(key.to_string(), &[json!({"stale": true})]);
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
            let f = selector_field(kind).unwrap();
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
