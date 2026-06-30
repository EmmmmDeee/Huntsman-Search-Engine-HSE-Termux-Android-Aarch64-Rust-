use super::*;

    #[test]
    fn accepts_only_username() {
        let m = CratesIo;
        assert!(m.accepts(&Target::new(TargetKind::Username, "dtolnay")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }

    #[test]
    fn metadata() {
        let m = CratesIo;
        assert_eq!(m.name(), "crates_io");
        assert!(m.produces().contains(&EntityKind::Person));
    }

    #[test]
    fn deserializes_user_and_missing() {
        let json = r#"{"user":{"id":1,"login":"alice","name":"Alice Smith",
            "avatar":"https://x/a","url":"https://github.com/alice"}}"#;
        let r: UserResp = serde_json::from_str(json).unwrap();
        let u = r.user.unwrap();
        assert_eq!(u.login, "alice");
        assert_eq!(u.name.as_deref(), Some("Alice Smith"));
        assert_eq!(u.url.as_deref(), Some("https://github.com/alice"));
        // A no-user body deserializes to None.
        let empty: UserResp = serde_json::from_str(r#"{}"#).unwrap();
        assert!(empty.user.is_none());
    }

    #[test]
    fn handle_validation() {
        let valid = |s: &str| -> bool {
            !s.is_empty()
                && s.len() <= 39
                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        };
        assert!(valid("dtolnay"));
        assert!(valid("kylo4kylo"));
        assert!(!valid("has space"));
        assert!(!valid("under_score"));
    }

    // ── build_entities (pure) ───────────────────────────────────────────

    fn user_resp(json: &str) -> UserResp {
        serde_json::from_str(json).expect("valid UserResp fixture")
    }
    fn of_kind(ents: &[Entity], kind: EntityKind) -> Option<&Entity> {
        ents.iter().find(|e| e.kind == kind)
    }

    #[test]
    fn full_record_yields_username_person_and_url() {
        let body = user_resp(
            r#"{"user":{"id":1,"login":"alice","name":"Alice Smith",
                "avatar":"https://x/a","url":"https://github.com/alice"}}"#,
        );
        let ents = build_entities(&body, "s");
        // Username (crates) + GitHub Username pivot + Person + Url
        assert_eq!(ents.len(), 4);

        let u = ents.iter().find(|e| e.kind == EntityKind::Username && e.value == "alice")
            .expect("crates username entity");
        assert!(u.has_tag("crates-io") && u.has_tag("code"));
        let attr = |k: &str| u.evidence[0].attributes.get(k).map(String::as_str);
        assert_eq!(attr("profile_url"), Some("https://crates.io/users/alice"));
        assert_eq!(attr("name"), Some("Alice Smith"));
        // The avatar URL (embeds the stable numeric GitHub id) is now surfaced.
        assert_eq!(attr("avatar_url"), Some("https://x/a"));

        // GitHub username pivot extracted from the profile URL.
        let gh = ents.iter().find(|e| e.kind == EntityKind::Username && e.value == "alice"
            && e.has_tag("github"));
        assert!(gh.is_some(), "must emit GitHub username pivot");
        assert!(gh.unwrap().has_tag("crates-io-pivot"));

        let p = of_kind(&ents, EntityKind::Person).expect("person entity");
        assert_eq!(p.value, "Alice Smith");
        assert!(p.has_tag("crates-io") && p.has_tag("derived"));
        assert_eq!(
            p.evidence[0].attributes.get("crates_login").map(String::as_str),
            Some("alice")
        );

        let url = of_kind(&ents, EntityKind::Url).expect("url entity");
        assert_eq!(url.value, "https://github.com/alice");
        assert!(url.has_tag("linked-profile"));
    }

    #[test]
    fn no_user_yields_nothing() {
        assert!(build_entities(&user_resp(r#"{}"#), "s").is_empty());
    }

    #[test]
    fn single_word_name_yields_no_person_but_still_attrs_username() {
        // crates.io often carries just a mononym / handle as `name`; a Person
        // pivot needs ≥ 2 whitespace tokens, but the name is still evidence.
        let body = user_resp(r#"{"user":{"login":"bob","name":"bob"}}"#);
        let ents = build_entities(&body, "s");
        assert!(of_kind(&ents, EntityKind::Person).is_none());
        let u = of_kind(&ents, EntityKind::Username).unwrap();
        assert_eq!(
            u.evidence[0].attributes.get("name").map(String::as_str),
            Some("bob")
        );
    }

    #[test]
    fn blank_name_adds_no_name_attr_and_no_person() {
        let body = user_resp(r#"{"user":{"login":"carol","name":""}}"#);
        let ents = build_entities(&body, "s");
        assert!(of_kind(&ents, EntityKind::Person).is_none());
        let u = of_kind(&ents, EntityKind::Username).unwrap();
        assert!(
            !u.evidence[0].attributes.contains_key("name"),
            "a blank name must not become a `name` attribute"
        );
    }

    #[test]
    fn missing_optional_fields_yield_username_only() {
        let body = user_resp(r#"{"user":{"login":"dave"}}"#);
        let ents = build_entities(&body, "s");
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].kind, EntityKind::Username);
        assert!(!ents[0].evidence[0].attributes.contains_key("name"));
    }

    #[test]
    fn non_http_url_yields_no_url_entity() {
        // A non-http(s) `url` (or a bare handle) must not become a Url pivot.
        let body = user_resp(r#"{"user":{"login":"eve","url":"ftp://x/eve"}}"#);
        let ents = build_entities(&body, "s");
        assert!(of_kind(&ents, EntityKind::Url).is_none());
    }

    #[test]
    fn placeholder_name_is_not_promoted_to_person() {
        // A template/placeholder full name must never be promoted to a Person
        // (the name is still recorded as a `name` attr on the username).
        let body = user_resp(r#"{"user":{"login":"jdoe","name":"John Doe"}}"#);
        let ents = build_entities(&body, "s");
        assert!(
            of_kind(&ents, EntityKind::Person).is_none(),
            "a placeholder full name must not yield a Person entity"
        );
        let u = of_kind(&ents, EntityKind::Username).unwrap();
        assert_eq!(
            u.evidence[0].attributes.get("name").map(String::as_str),
            Some("John Doe")
        );
    }
