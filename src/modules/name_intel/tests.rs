use super::*;
    use std::collections::HashMap;

    fn ctx(scan: &str) -> ModuleContext {
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        ModuleContext {
            scan_id: scan.into(),
            bus,
            http: crate::util::http::build_client(),
            keys: HashMap::default(),
            cancel: crate::core::cancel::CancelHandle::new(),
            proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        }
    }

    #[tokio::test]
    async fn metadata_and_acceptance() {
        let m = NameIntel;
        assert_eq!(m.name(), "name_intel");
        assert!(m.is_passive());
        assert!(!m.description().is_empty());
        assert!(m.accepts(&Target::new(TargetKind::FullName, "Jordan Meyers")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        // Default consumes() (probes accepts) must report exactly FullName so
        // the dispatch index serves it — and only it.
        assert_eq!(m.consumes(), vec![TargetKind::FullName]);
    }

    #[tokio::test]
    async fn emits_usernames_emails_and_pivots() {
        let m = NameIntel;
        let out = m
            .process(
                &Target::new(TargetKind::FullName, "Jordan Leigh Meyers 1987"),
                &ctx("scan-x"),
            )
            .await
            .unwrap();

        let mut persons = 0;
        let mut usernames = 0;
        let mut emails = 0;
        let mut pivots = 0;
        let mut gravatar_seen = false;
        for e in &out.entities {
            match e.kind {
                EntityKind::Person => {
                    persons += 1;
                    // The subject anchor: the operator's name, Probable-tier, so
                    // derived handles have an individual to attach to.
                    assert!(e.has_tag("subject") && e.has_tag("seed"));
                    assert_eq!(e.classify(), crate::core::entity::Classification::Probable);
                }
                EntityKind::Username => {
                    usernames += 1;
                    assert!(e.has_tag("name-derived"));
                }
                EntityKind::Email => {
                    emails += 1;
                    assert!(e.has_tag("permuted"));
                    assert!(e.value.contains('@'));
                    if e.evidence
                        .iter()
                        .any(|ev| ev.attributes.contains_key("gravatar"))
                    {
                        gravatar_seen = true;
                    }
                }
                EntityKind::Url => {
                    pivots += 1;
                    assert!(e.has_tag("search-pivot"));
                    assert!(e.raw_value.starts_with("https://"));
                }
                ref other => panic!("unexpected kind {other}"),
            }
        }
        assert_eq!(persons, 1, "exactly one subject Person anchor");
        assert!(usernames > 5, "expected several usernames, got {usernames}");
        assert!(emails > 0, "expected emails, got {emails}");
        assert!(pivots > 5, "expected several pivots, got {pivots}");
        assert!(gravatar_seen, "emails must carry a gravatar attribute");
    }

    #[tokio::test]
    async fn single_token_name_yields_nothing() {
        let m = NameIntel;
        let out = m
            .process(
                &Target::new(TargetKind::FullName, "Madonna"),
                &ctx("scan-y"),
            )
            .await
            .unwrap();
        assert!(out.entities.is_empty());
    }
