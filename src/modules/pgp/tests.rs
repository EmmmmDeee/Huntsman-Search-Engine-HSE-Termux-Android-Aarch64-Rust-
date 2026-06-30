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
    fn extract_mints_correlatable_pgp_key_credential() {
        // The key fingerprint becomes a Credential `pgp:<fp>` tagged `pgp-key`,
        // its evidence naming every bound email — the artifact AU-048 links
        // across accounts (the PGP analogue of github_user's ssh-key).
        let body = "info:1:1\n\
            pub:ABCDEF0123456789ABCDEF0123456789ABCDEF01:1:4096:1500000000::\n\
            uid:Jordan%20Avery%20%3Cmatt%40example.com%3E:1500000000::\n\
            uid:Jordan%20Avery%20%3Cm.avery%40work.com%3E:1500000000::\n";
        let mut r = ModuleResult::new();
        extract(body, "matt@example.com", "scan", &mut r);

        let cred = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Credential)
            .expect("PGP key minted as a Credential");
        // Stable, lowercased value so the same key dedups across scans.
        assert_eq!(cred.value, "pgp:abcdef0123456789abcdef0123456789abcdef01");
        assert!(cred.has_tag("pgp-key") && cred.has_tag("public-key") && cred.has_tag("pgp"));
        // Both bound controllers (queried + alternate) are named via the `email`
        // attr AU-048 reads, so a key shared by two identities links them.
        let emails: std::collections::BTreeSet<&str> = cred
            .evidence
            .iter()
            .filter_map(|ev| ev.attributes.get("email").map(String::as_str))
            .collect();
        assert!(emails.contains("matt@example.com"));
        assert!(emails.contains("m.avery@work.com"));
    }

    #[test]
    fn extract_is_quiet_on_no_keys() {
        let mut r = ModuleResult::new();
        extract("info:1:0\n", "x@y.com", "scan", &mut r);
        assert!(r.entities.is_empty());
    }

    #[test]
    fn module_metadata() {
        let m = Pgp;
        assert_eq!(m.name(), "pgp");
        assert!(!m.description().is_empty());
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "y.com")));
        assert!(!m.attack_techniques().is_empty());
    }

    #[test]
    fn extract_deduplicates_person_across_uids() {
        // Two UIDs carry the same name — Person must be emitted exactly once.
        let body = "info:1:1\n\
            pub:ABCDEF0123456789ABCDEF0123456789ABCDEF01:1:4096:1500000000::\n\
            uid:Jordan%20Avery%20%3Ca%40example.com%3E:1500000000::\n\
            uid:Jordan%20Avery%20%3Cb%40example.com%3E:1500000000::\n";
        let mut r = ModuleResult::new();
        extract(body, "a@example.com", "scan", &mut r);
        assert_eq!(
            r.entities.iter().filter(|e| e.kind == EntityKind::Person).count(),
            1,
            "duplicate name across UIDs must be emitted once"
        );
    }
