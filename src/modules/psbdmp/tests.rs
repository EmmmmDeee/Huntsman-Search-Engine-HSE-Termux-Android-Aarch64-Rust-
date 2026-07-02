use super::*;

    #[test]
    fn extract_emits_a_url_per_paste_with_provenance() {
        let resp = SearchResp {
            count: 2,
            data: vec![
                Paste {
                    id: "abc123".into(),
                    date: "2021-05-01 10:00:00".into(),
                    tags: "email".into(),
                },
                Paste {
                    id: "def456".into(),
                    date: String::new(),
                    tags: String::new(),
                },
                // Duplicate id must be deduped.
                Paste {
                    id: "abc123".into(),
                    date: String::new(),
                    tags: String::new(),
                },
            ],
        };
        let mut r = ModuleResult::new();
        extract(&resp, "victim@example.com", TargetKind::Email, "scan", &mut r);
        // 2 deduped paste URLs + 1 seed-identity (Email) entity.
        assert_eq!(r.entities.len(), 3, "deduped urls + seed; got {:?}", r.entities);
        let urls: Vec<&str> = r
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Url)
            .map(|e| e.value.as_str())
            .collect();
        assert!(urls.contains(&"https://pastebin.com/abc123"));
        assert!(urls.contains(&"https://pastebin.com/def456"));
        // Paste exposure tagged on every emitted entity (URLs and the seed).
        assert!(r.entities.iter().all(|e| e.has_tag("paste-exposed")));
        let first = r
            .entities
            .iter()
            .find(|e| e.value.ends_with("abc123"))
            .unwrap();
        assert_eq!(
            first.evidence[0].attributes.get("date").unwrap(),
            "2021-05-01 10:00:00"
        );
    }

    #[test]
    fn extract_is_quiet_on_no_pastes() {
        let mut r = ModuleResult::new();
        extract(&SearchResp::default(), "x", TargetKind::Email, "scan", &mut r);
        assert!(r.entities.is_empty());
    }

    #[test]
    fn extract_marks_seed_identity_paste_exposed_with_temporal_signal() {
        // The seed identity itself (not just the orphan paste URLs) must carry the
        // exposure, the paste count, and the EARLIEST paste date — so the subject's
        // own record shows the leak and identity-level breach correlation can see it.
        let resp = SearchResp {
            count: 2,
            data: vec![
                Paste {
                    id: "p2".into(),
                    date: "2022-08-09 12:00:00".into(),
                    tags: String::new(),
                },
                Paste {
                    id: "p1".into(),
                    // Lexically (and chronologically) earlier than p2's date.
                    date: "2020-01-02 00:00:00".into(),
                    tags: "email".into(),
                },
            ],
        };
        for (kind, want) in [
            (TargetKind::Email, EntityKind::Email),
            (TargetKind::Username, EntityKind::Username),
            (TargetKind::Domain, EntityKind::Domain),
        ] {
            let mut r = ModuleResult::new();
            extract(&resp, "subject", kind, "scan", &mut r);
            let seed = r
                .entities
                .iter()
                .find(|e| e.kind == want && e.value == "subject")
                .unwrap_or_else(|| panic!("seed {want:?} entity must be emitted for {kind:?}"));
            assert!(seed.has_tag("paste-exposed"), "seed must be paste-exposed");
            assert!(seed.has_tag("breach"), "seed must be breach-tagged");
            let ev = &seed.evidence[0];
            assert_eq!(ev.attributes.get("paste_count").map(String::as_str), Some("2"));
            // Earliest of the two dates, independent of input order.
            assert_eq!(
                ev.attributes.get("earliest_paste").map(String::as_str),
                Some("2020-01-02 00:00:00")
            );
            // Same earliest date is ALSO stamped under the canonical `breach_date`
            // key AU-019's temporal breach-cluster rule reads, so paste exposure
            // can date-cluster with other breach sources. `.get(..10)` inside
            // AU-019 slices this to the ISO day (`2020-01-02`).
            assert_eq!(
                ev.attributes.get("breach_date").map(String::as_str),
                Some("2020-01-02 00:00:00")
            );
        }
    }

    #[test]
    fn module_metadata() {
        let m = Psbdmp;
        assert_eq!(m.name(), "psbdmp");
        assert!(!m.description().is_empty());
        assert_eq!(m.cost(), crate::core::module::ModuleCost::Free);
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(m.accepts(&Target::new(TargetKind::Username, "alice")));
        assert!(m.accepts(&Target::new(TargetKind::Domain, "y.com")));
        assert!(!m.attack_techniques().is_empty());
    }

    #[test]
    fn extract_url_carries_search_term_evidence() {
        let resp = SearchResp {
            count: 1,
            data: vec![Paste {
                id: "xyz789".into(),
                date: "2023-12-01 00:00:00".into(),
                tags: "password".into(),
            }],
        };
        let mut r = ModuleResult::new();
        extract(&resp, "alice@example.com", TargetKind::Email, "scan-1", &mut r);
        // 1 paste URL + 1 seed-identity entity; the URL is pushed first.
        assert_eq!(r.entities.len(), 2);
        let e = &r.entities[0];
        assert_eq!(e.kind, EntityKind::Url);
        assert!(e.value.contains("xyz789"));
        assert!(e.has_tag("paste-exposed"));
        // Evidence carries the search term.
        let attr = e.evidence[0].attributes.get("search_term").map(String::as_str);
        assert_eq!(attr, Some("alice@example.com"));
    }
