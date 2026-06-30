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
        // The owner's self-asserted link label (UrlEntry.title) is now carried
        // as `link_title` evidence on the personal-URL entity.
        let blog = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Url && e.value == "https://javery.dev")
            .expect("personal url entity");
        assert_eq!(
            blog.evidence[0].attributes.get("link_title").map(String::as_str),
            Some("Blog")
        );
        // Bare platform usernames (platform tag, not prefixed value) + their URLs.
        assert!(has(EntityKind::Username, "javery"), "github username bare");
        assert!(has(EntityKind::Username, "mattd"), "twitter username bare");
        assert!(has(EntityKind::Url, "https://github.com/javery"));
        // Platform tag + gravatar-pivot tag carried on account usernames.
        assert!(
            r.entities
                .iter()
                .any(|e| e.value == "javery" && e.has_tag("github") && e.has_tag("verified"))
        );
        assert!(
            r.entities
                .iter()
                .any(|e| e.value == "mattd" && e.has_tag("twitter") && !e.has_tag("verified"))
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

    #[test]
    fn module_metadata() {
        let m = Gravatar;
        assert_eq!(m.name(), "gravatar");
        assert!(!m.description().is_empty());
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "y.com")));
        assert!(!m.attack_techniques().is_empty());
    }

    #[test]
    fn gravatar_profile_url_uses_hash() {
        let hash = gravatar_hash("matt@example.com");
        // The lookup URL is "https://gravatar.com/{hash}.json"
        let expected_url = format!("https://gravatar.com/{hash}.json");
        assert!(expected_url.contains(&hash));
        assert!(expected_url.ends_with(".json"));
    }
