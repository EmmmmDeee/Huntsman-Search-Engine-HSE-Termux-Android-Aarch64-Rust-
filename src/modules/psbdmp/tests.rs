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
        extract(&resp, "victim@example.com", "scan", &mut r);
        assert_eq!(r.entities.len(), 2, "deduped; got {:?}", r.entities);
        let urls: Vec<&str> = r.entities.iter().map(|e| e.value.as_str()).collect();
        assert!(urls.contains(&"https://pastebin.com/abc123"));
        assert!(urls.contains(&"https://pastebin.com/def456"));
        // Paste exposure tagged + provenance kept.
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
        extract(&SearchResp::default(), "x", "scan", &mut r);
        assert!(r.entities.is_empty());
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
        extract(&resp, "alice@example.com", "scan-1", &mut r);
        assert_eq!(r.entities.len(), 1);
        let e = &r.entities[0];
        assert_eq!(e.kind, EntityKind::Url);
        assert!(e.value.contains("xyz789"));
        assert!(e.has_tag("paste-exposed"));
        // Evidence carries the search term.
        let attr = e.evidence[0].attributes.get("search_term").map(String::as_str);
        assert_eq!(attr, Some("alice@example.com"));
    }
