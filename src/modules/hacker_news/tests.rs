use super::*;

    #[test]
    fn accepts_only_username() {
        let m = HackerNews;
        assert!(m.accepts(&Target::new(TargetKind::Username, "pg")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "ycombinator.com")));
    }

    #[test]
    fn metadata() {
        let m = HackerNews;
        assert_eq!(m.name(), "hacker_news");
        assert!(!m.description().is_empty());
        assert!(m.produces().contains(&EntityKind::Username));
    }

    #[test]
    fn deserializes_account_and_null() {
        let json = r#"{"id":"pg","created":1160418092,"karma":157222,
            "about":"Reach me at paul@example.com or https://paulgraham.com/",
            "submitted":[1,2,3]}"#;
        let u: Option<HnUser> = serde_json::from_str(json).unwrap();
        let u = u.unwrap();
        assert_eq!(u.id, "pg");
        assert_eq!(u.karma, Some(157222));
        assert_eq!(u.submitted.as_ref().unwrap().len(), 3);
        // The literal `null` (unknown handle) is a clean None.
        let none: Option<HnUser> = serde_json::from_str("null").unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn bio_extracts_email_and_url() {
        let (email_re, url_re) = bio_patterns();
        let about = "Contact: Paul@Example.com — site https://paulgraham.com/bio.html.";
        assert_eq!(
            email_re.find(about).unwrap().as_str().to_lowercase(),
            "paul@example.com"
        );
        let link = url_re
            .find(about)
            .unwrap()
            .as_str()
            .trim_end_matches(['.', ',', ')']);
        assert_eq!(link, "https://paulgraham.com/bio.html");
    }

    #[test]
    fn handle_validation() {
        let valid = |s: &str| -> bool {
            s.len() >= 2
                && s.len() <= 15
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        };
        assert!(valid("pg"));
        assert!(valid("kylo4kylo"));
        assert!(valid("user_name-1"));
        assert!(!valid("a")); // too short
        assert!(!valid("this_handle_is_too_long"));
        assert!(!valid("has space"));
        assert!(!valid("emoji😀"));
    }
