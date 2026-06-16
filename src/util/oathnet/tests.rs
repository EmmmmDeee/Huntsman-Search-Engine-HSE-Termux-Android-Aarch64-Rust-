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
