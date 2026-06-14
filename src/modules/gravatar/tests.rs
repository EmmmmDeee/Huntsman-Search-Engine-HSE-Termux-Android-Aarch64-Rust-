use super::*;

    #[test]
    fn gravatar_hash_is_md5_of_lowercased_trimmed_email() {
        // Documented Gravatar example: MD5("MyEmailAddress@example.com " trimmed
        // + lowercased) — the canonical hash for that address.
        assert_eq!(
            gravatar_hash("  MyEmailAddress@example.com "),
            "0bc83cb571cd1c50ba6f3e8a78ef1346"
        );
        // Case/space insensitivity.
        assert_eq!(
            gravatar_hash("matt@example.com"),
            gravatar_hash("  MATT@Example.COM  ")
        );
    }

    #[test]
    fn extract_entry_emits_the_full_identity_graph() {
        let json = serde_json::json!({
            "hash": "abc",
            "profileUrl": "https://gravatar.com/matt",
            "preferredUsername": "matt",
            "thumbnailUrl": "https://gravatar.com/avatar/abc",
            "displayName": "Matt D",
            "name": { "formatted": "Jordan Avery", "givenName": "Jordan", "familyName": "Avery" },
            "currentLocation": "Brisbane, QLD",
            "accounts": [
                { "shortname": "github", "username": "javery", "url": "https://github.com/javery", "verified": "true" },
                { "shortname": "twitter", "username": "mattd", "url": "https://twitter.com/mattd", "verified": "false" }
            ],
            "urls": [ { "value": "https://javery.dev", "title": "Blog" } ]
        });
        let entry: Entry = serde_json::from_value(json).unwrap();
        let mut r = ModuleResult::new();
        extract_entry(&entry, "abc", "scan", &mut r);

        let has = |k: EntityKind, v: &str| r.entities.iter().any(|e| e.kind == k && e.value == v);
        assert!(has(EntityKind::Person, "Jordan Avery"));
        assert!(has(EntityKind::Username, "matt"));
        assert!(has(EntityKind::Address, "Brisbane, QLD"));
        assert!(has(EntityKind::Url, "https://gravatar.com/matt"));
        assert!(has(EntityKind::Url, "https://javery.dev"));
        // Platform-prefixed account usernames + their URLs.
        assert!(has(EntityKind::Username, "github:javery"));
        assert!(has(EntityKind::Username, "twitter:mattd"));
        assert!(has(EntityKind::Url, "https://github.com/javery"));
        // Verified flag carried as a tag.
        assert!(
            r.entities
                .iter()
                .any(|e| e.value == "github:javery" && e.has_tag("verified"))
        );
        assert!(
            !r.entities
                .iter()
                .any(|e| e.value == "twitter:mattd" && e.has_tag("verified"))
        );
        // Every entity carries the gravatar source tag + the profile evidence.
        assert!(r.entities.iter().all(|e| e.has_tag("gravatar")));
    }

    #[test]
    fn extract_entry_is_quiet_on_an_empty_profile() {
        let entry = Entry::default();
        let mut r = ModuleResult::new();
        extract_entry(&entry, "h", "scan", &mut r);
        assert!(r.entities.is_empty(), "no fields ⇒ no entities");
    }
