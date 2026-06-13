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
