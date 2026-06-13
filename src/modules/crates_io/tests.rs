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
