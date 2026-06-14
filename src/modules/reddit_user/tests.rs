use super::*;

    #[test]
    fn accepts_only_username() {
        let m = RedditUser;
        assert!(m.accepts(&Target::new(TargetKind::Username, "spez")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }

    #[test]
    fn metadata() {
        let m = RedditUser;
        assert_eq!(m.name(), "reddit_user");
        assert!(!m.description().is_empty());
        assert!(m.produces().contains(&EntityKind::Username));
    }

    #[test]
    fn deserializes_about_and_missing() {
        let json = r#"{"data":{"name":"spez","created_utc":1118030400.0,
            "link_karma":12,"comment_karma":34,"verified":true,"is_gold":false,
            "subreddit":{"public_description":"contact me@example.com https://example.com/me","title":"hi"}}}"#;
        let r: AboutResp = serde_json::from_str(json).unwrap();
        let d = r.data.unwrap();
        assert_eq!(d.name, "spez");
        assert_eq!(d.link_karma, Some(12));
        assert_eq!(d.verified, Some(true));
        // An empty/suspended response (no data) is a clean None.
        let empty: AboutResp = serde_json::from_str(r#"{"data":null}"#).unwrap();
        assert!(empty.data.is_none());
    }

    #[test]
    fn bio_extracts_email_and_url() {
        let bio = "Reach Me@Example.com — https://example.com/profile.";
        assert_eq!(
            BIO_EMAIL_RE.find(bio).unwrap().as_str().to_lowercase(),
            "me@example.com"
        );
        let link = BIO_URL_RE
            .find(bio)
            .unwrap()
            .as_str()
            .trim_end_matches(['.', ',', ')']);
        assert_eq!(link, "https://example.com/profile");
    }

    #[test]
    fn handle_validation() {
        let valid = |s: &str| -> bool {
            s.len() >= 3
                && s.len() <= 20
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        };
        assert!(valid("spez"));
        assert!(valid("kylo4kylo"));
        assert!(!valid("ab")); // too short
        assert!(!valid("this_handle_is_way_too_long"));
        assert!(!valid("has space"));
    }
