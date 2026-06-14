use super::*;

    #[test]
    fn split_uid_variants() {
        assert_eq!(
            split_uid("Jordan Avery <matt@example.com>"),
            (Some("Jordan Avery"), Some("matt@example.com"))
        );
        assert_eq!(
            split_uid("<only@example.com>"),
            (None, Some("only@example.com"))
        );
        assert_eq!(
            split_uid("bare@example.com"),
            (None, Some("bare@example.com"))
        );
        assert_eq!(
            split_uid("No Address Here"),
            (Some("No Address Here"), None)
        );
    }

    #[test]
    fn extract_pulls_name_and_alternate_emails() {
        // Realistic HKP machine-readable index: one key, two UIDs (the queried
        // address + an alternate), URL-encoded as keyservers return them.
        let body = "info:1:1\n\
            pub:ABCDEF0123456789ABCDEF0123456789ABCDEF01:1:4096:1500000000::\n\
            uid:Jordan%20Avery%20%3Cmatt%40example.com%3E:1500000000::\n\
            uid:Jordan%20Avery%20%3Cm.avery%40work.com%3E:1500000000::\n";
        let mut r = ModuleResult::new();
        extract(body, "matt@example.com", "scan", &mut r);

        let has = |k: EntityKind, v: &str| r.entities.iter().any(|e| e.kind == k && e.value == v);
        // Owner name surfaced once (deduped across both UIDs).
        assert!(has(EntityKind::Person, "Jordan Avery"));
        assert_eq!(
            r.entities
                .iter()
                .filter(|e| e.kind == EntityKind::Person)
                .count(),
            1
        );
        // The ALTERNATE email is surfaced; the queried one is not re-emitted.
        assert!(has(EntityKind::Email, "m.avery@work.com"));
        assert!(!has(EntityKind::Email, "matt@example.com"));
        // Evidence carries the key fingerprint.
        assert!(r.entities.iter().all(|e| {
            e.evidence
                .iter()
                .any(|ev| ev.attributes.contains_key("key_fingerprint"))
        }));
    }

    #[test]
    fn extract_is_quiet_on_no_keys() {
        let mut r = ModuleResult::new();
        extract("info:1:0\n", "x@y.com", "scan", &mut r);
        assert!(r.entities.is_empty());
    }
