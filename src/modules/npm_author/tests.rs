use super::*;

    #[test]
    fn accepts_only_username() {
        let m = NpmAuthor;
        assert!(m.accepts(&Target::new(TargetKind::Username, "sindresorhus")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }

    #[test]
    fn metadata() {
        let m = NpmAuthor;
        assert_eq!(m.name(), "npm_author");
        assert!(m.produces().contains(&EntityKind::Email));
    }

    #[test]
    fn deserializes_search_response() {
        let json = r#"{"objects":[{"package":{"name":"foo",
            "links":{"homepage":"https://foo.dev","repository":"https://github.com/k/foo"},
            "author":{"name":"K","email":"k@example.com","url":"https://k.dev"},
            "maintainers":[{"username":"kylo4kylo","email":"k@example.com"}]}}],"total":3}"#;
        let r: SearchResp = serde_json::from_str(json).unwrap();
        assert_eq!(r.total, 3);
        let p = r.objects[0].package.as_ref().unwrap();
        assert_eq!(p.name.as_deref(), Some("foo"));
        assert_eq!(p.maintainers[0].username.as_deref(), Some("kylo4kylo"));
        assert_eq!(p.maintainers[0].email.as_deref(), Some("k@example.com"));
        // Empty registry response deserializes to no objects.
        let empty: SearchResp = serde_json::from_str(r#"{"objects":[],"total":0}"#).unwrap();
        assert!(empty.objects.is_empty());
    }

    #[test]
    fn handle_validation() {
        let valid = |s: &str| -> bool {
            let s = s.to_lowercase();
            !s.is_empty()
                && s.len() <= 64
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        };
        assert!(valid("sindresorhus"));
        assert!(valid("kylo4kylo"));
        assert!(valid("my.scope-name_1"));
        assert!(!valid("has space"));
        assert!(!valid("bad/slash"));
    }

    // ── build_entities (pure extraction) ───────────────────────────────

    fn search(json: &str) -> SearchResp {
        serde_json::from_str(json).expect("fixture is valid SearchResp JSON")
    }
    fn of_kind(ents: &[Entity], kind: EntityKind) -> Vec<&Entity> {
        ents.iter().filter(|e| e.kind == kind).collect()
    }
    fn values(ents: &[Entity], kind: EntityKind) -> Vec<&str> {
        of_kind(ents, kind)
            .into_iter()
            .map(|e| e.value.as_str())
            .collect()
    }

    #[test]
    fn full_record_yields_username_email_and_urls() {
        let body = search(
            r#"{"objects":[{"package":{"name":"foo",
                "links":{"homepage":"https://foo.dev","repository":"https://github.com/k/foo"},
                "author":{"username":"kylo4kylo","email":"K@Example.com","url":"https://k.dev"},
                "maintainers":[{"username":"kylo4kylo","email":"k@example.com"}]}}],"total":3}"#,
        );
        let ents = build_entities(&body, "kylo4kylo", "s");

        // Confirmed-on-npm username is always present, with package coverage.
        // May also have a GitHub username pivot from repository URL.
        let user_ents = of_kind(&ents, EntityKind::Username);
        let user = user_ents
            .iter()
            .find(|e| e.value == "kylo4kylo")
            .expect("npm username entity");
        assert_eq!(user.value, "kylo4kylo");
        assert!(user.has_tag("npm") && user.has_tag("code"));
        let attr = |k: &str| user.evidence[0].attributes.get(k).map(String::as_str);
        // package_count comes from `total`, not the objects length.
        assert_eq!(attr("package_count"), Some("3"));
        assert_eq!(attr("packages"), Some("foo"));
        assert_eq!(attr("profile_url"), Some("https://www.npmjs.com/~kylo4kylo"));

        // The author/maintainer email (subject-owned), normalised + de-duped to one.
        let emails = values(&ents, EntityKind::Email);
        assert_eq!(emails, vec!["k@example.com"], "email lowercased and deduped");
        let email_e = of_kind(&ents, EntityKind::Email)[0];
        assert!(email_e.has_tag("npm") && email_e.has_tag("public-profile"));
        assert_eq!(
            email_e.evidence[0].attributes.get("package").map(String::as_str),
            Some("foo")
        );

        // Author URL + homepage + repository, all de-duplicated across records.
        let mut urls = values(&ents, EntityKind::Url);
        urls.sort_unstable();
        assert_eq!(
            urls,
            vec!["https://foo.dev", "https://github.com/k/foo", "https://k.dev"]
        );
    }

    #[test]
    fn co_maintainer_email_not_attributed_to_subject() {
        // The subject `alice` publishes; `bob` is a co-maintainer with a username
        // that does NOT match — his email must be skipped.
        let body = search(
            r#"{"objects":[{"package":{"name":"pkg",
                "maintainers":[
                    {"username":"alice","email":"alice@example.com"},
                    {"username":"bob","email":"bob@example.com"}
                ]}}],"total":1}"#,
        );
        let ents = build_entities(&body, "alice", "s");
        let emails = values(&ents, EntityKind::Email);
        assert_eq!(emails, vec!["alice@example.com"]);
    }

    #[test]
    fn co_maintainer_username_is_emitted_but_subject_not_duplicated() {
        // Same fixture as above: `bob`'s handle should now surface as its own
        // Username entity (co-maintainer), while `alice` — the subject — is not
        // duplicated via this path (she's already emitted once at 0.88 by the
        // final confirmed-on-npm block).
        let body = search(
            r#"{"objects":[{"package":{"name":"pkg",
                "maintainers":[
                    {"username":"alice","email":"alice@example.com"},
                    {"username":"bob","email":"bob@example.com"}
                ]}}],"total":1}"#,
        );
        let ents = build_entities(&body, "alice", "s");
        let usernames = values(&ents, EntityKind::Username);
        assert_eq!(usernames, vec!["bob", "alice"]);

        let bob = of_kind(&ents, EntityKind::Username)
            .into_iter()
            .find(|e| e.value == "bob")
            .expect("bob co-maintainer username entity");
        assert!(bob.has_tag("npm") && bob.has_tag("co-maintainer"));
        assert_eq!(bob.confidence, 0.55);
        assert_eq!(
            bob.evidence[0].attributes.get("package").map(String::as_str),
            Some("pkg")
        );

        let alice = of_kind(&ents, EntityKind::Username)
            .into_iter()
            .find(|e| e.value == "alice")
            .expect("alice subject username entity");
        assert_eq!(alice.confidence, 0.88);
        assert!(!alice.has_tag("co-maintainer"));
    }

    #[test]
    fn usernameless_record_email_is_kept() {
        // A record with an email but no username is treated as the subject's.
        let body = search(
            r#"{"objects":[{"package":{"name":"pkg",
                "author":{"email":"author@example.com"}}}],"total":1}"#,
        );
        let ents = build_entities(&body, "alice", "s");
        let emails = values(&ents, EntityKind::Email);
        assert_eq!(emails, vec!["author@example.com"]);
    }

    #[test]
    fn short_or_invalid_emails_are_skipped() {
        // `a@b` is 3 chars (< 5) and `not-an-email` has no `@`: neither qualifies.
        let body = search(
            r#"{"objects":[{"package":{"name":"pkg",
                "maintainers":[
                    {"username":"alice","email":"a@b"},
                    {"username":"alice","email":"not-an-email"}
                ]}}],"total":1}"#,
        );
        assert!(values(&build_entities(&body, "alice", "s"), EntityKind::Email).is_empty());
    }

    #[test]
    fn non_http_urls_are_skipped() {
        let body = search(
            r#"{"objects":[{"package":{"name":"pkg",
                "links":{"homepage":"ftp://files.example","repository":"git@github.com:x/y"},
                "author":{"username":"alice","url":"mailto:alice@example.com"}}}],"total":1}"#,
        );
        assert!(values(&build_entities(&body, "alice", "s"), EntityKind::Url).is_empty());
    }

    #[test]
    fn urls_deduplicated_across_packages() {
        // The same homepage on two packages yields a single Url entity.
        let body = search(
            r#"{"objects":[
                {"package":{"name":"a","links":{"homepage":"https://shared.dev"}}},
                {"package":{"name":"b","links":{"homepage":"https://shared.dev"}}}
            ],"total":2}"#,
        );
        let ents = build_entities(&body, "alice", "s");
        let urls = values(&ents, EntityKind::Url);
        assert_eq!(urls, vec!["https://shared.dev"]);
    }

    #[test]
    fn package_sample_is_capped_at_eight() {
        // 10 packages → coverage sample lists only the first 8, but the count
        // reflects `total`.
        let objects: Vec<String> = (0..10)
            .map(|i| format!(r#"{{"package":{{"name":"p{i}"}}}}"#))
            .collect();
        let json = format!(r#"{{"objects":[{}],"total":42}}"#, objects.join(","));
        let ents = build_entities(&search(&json), "alice", "s");
        let user = of_kind(&ents, EntityKind::Username)[0];
        let attr = |k: &str| user.evidence[0].attributes.get(k).map(String::as_str);
        assert_eq!(attr("package_count"), Some("42"));
        assert_eq!(attr("packages"), Some("p0, p1, p2, p3, p4, p5, p6, p7"));
    }

    #[test]
    fn every_returned_package_is_emitted() {
        // Full-fidelity policy: every package the API returns is scanned and
        // surfaced — no output cap. Give each a unique homepage and count them.
        let count = MAX_PACKAGES + 5;
        let objects: Vec<String> = (0..count)
            .map(|i| format!(r#"{{"package":{{"name":"p{i}","links":{{"homepage":"https://h{i}.dev"}}}}}}"#))
            .collect();
        let json = format!(
            r#"{{"objects":[{}],"total":{}}}"#,
            objects.join(","),
            count
        );
        let ents = build_entities(&search(&json), "alice", "s");
        // One Url per package — every returned package, none dropped.
        assert_eq!(of_kind(&ents, EntityKind::Url).len(), count);
    }
