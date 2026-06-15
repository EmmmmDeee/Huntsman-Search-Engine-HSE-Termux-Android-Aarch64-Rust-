use super::*;
    use std::collections::HashMap;

    fn ctx() -> ModuleContext {
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        ModuleContext {
            scan_id: "t".into(),
            bus,
            http: crate::util::http::build_client(),
            keys: HashMap::default(),
            cancel: crate::core::cancel::CancelHandle::new(),
            proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
            response_sink: None,
        }
    }

    #[test]
    fn gmail_dots_are_stripped() {
        assert_eq!(
            canonicalise("john.doe@gmail.com").as_deref(),
            Some("johndoe@gmail.com")
        );
    }

    #[test]
    fn gmail_plus_tag_and_dots_stripped_together() {
        assert_eq!(
            canonicalise("john.doe+newsletter@gmail.com").as_deref(),
            Some("johndoe@gmail.com")
        );
    }

    #[test]
    fn googlemail_alias_folds_to_gmail() {
        assert_eq!(
            canonicalise("johndoe@googlemail.com").as_deref(),
            Some("johndoe@gmail.com")
        );
    }

    #[test]
    fn case_is_normalised() {
        assert_eq!(
            canonicalise("JOHN.DOE@GMAIL.COM").as_deref(),
            Some("johndoe@gmail.com")
        );
    }

    #[test]
    fn plus_tag_stripped_for_non_gmail_provider() {
        // +tag subaddressing applies broadly; dots are NOT stripped off-Gmail.
        assert_eq!(
            canonicalise("jane+promo@outlook.com").as_deref(),
            Some("jane@outlook.com")
        );
        // dots are significant for non-Gmail → no change → None
        assert_eq!(canonicalise("jane.smith@outlook.com"), None);
    }

    #[test]
    fn already_canonical_yields_none() {
        assert_eq!(canonicalise("johndoe@gmail.com"), None);
        assert_eq!(canonicalise("jane@outlook.com"), None);
    }

    #[test]
    fn malformed_addresses_yield_none() {
        assert_eq!(canonicalise("notanemail"), None);
        assert_eq!(canonicalise("@gmail.com"), None);
        assert_eq!(canonicalise("user@localhost"), None); // no dot in domain
        assert_eq!(canonicalise("+tag@gmail.com"), None); // empty base local
    }

    #[tokio::test]
    async fn process_emits_canonical_email_above_floor() {
        let t = Target::new(TargetKind::Email, "j.doe+work@googlemail.com");
        let r = EmailCanonical.process(&t, &ctx()).await.unwrap();
        assert_eq!(r.entities.len(), 1);
        let e = &r.entities[0];
        assert_eq!(e.kind, EntityKind::Email);
        assert_eq!(e.value, "jdoe@gmail.com");
        assert!(
            e.confidence >= 0.50,
            "canonical mailbox should pivot at depth"
        );
        assert!(e.has_tag("canonical"));
        assert_eq!(e.evidence[0].source, SRC);
    }

    #[tokio::test]
    async fn process_emits_nothing_when_already_canonical() {
        let t = Target::new(TargetKind::Email, "jdoe@gmail.com");
        let r = EmailCanonical.process(&t, &ctx()).await.unwrap();
        assert!(r.entities.is_empty());
    }

    #[test]
    fn accepts_email_only_and_is_passive() {
        assert!(EmailCanonical.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!EmailCanonical.accepts(&Target::new(TargetKind::Username, "x")));
        assert!(EmailCanonical.is_passive());
        assert_eq!(EmailCanonical.category(), ModuleCategory::Email);
    }
