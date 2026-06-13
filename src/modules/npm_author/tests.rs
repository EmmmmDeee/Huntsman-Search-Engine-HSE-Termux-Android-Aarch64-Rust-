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
