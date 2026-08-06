use crate::core::confidence;
use super::*;

    fn entry(json: &str) -> DomainEntry {
        serde_json::from_str(json).expect("should succeed")
    }

    #[test]
    fn accepts_domain_org_name() {
        let m = DomainsDb;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme")));
        assert!(m.accepts(&Target::new(TargetKind::FullName, "John Doe")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    }

    #[test]
    fn cost_is_keygated() {
        // Key-gated since the provider disabled anonymous access (2026). A
        // `Free` classification here silently swallowed every 401 and returned
        // nothing; KeyGated makes the "needs key" state honest and lets
        // `--free-only` skip it cleanly.
        assert!(matches!(
            DomainsDb.cost(),
            crate::core::module::ModuleCost::KeyGated
        ));
    }

    #[tokio::test]
    async fn missing_key_yields_a_clean_needs_key_skip_not_a_silent_empty() {
        // Regression: with anonymous access disabled upstream, an unconfigured
        // domainsdb must surface `Error::MissingKey` (→ dispatch renders a
        // "needs API key" skip with the signup hint), NOT `Ok(empty)` — which
        // is what the pre-fix Free module produced on every scan once its 401s
        // began, hiding the dead source from the operator entirely.
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        let ctx = ModuleContext {
            scan_id: "t".into(),
            bus,
            http: crate::util::http::build_client(),
            keys: std::collections::HashMap::new(),
            cancel: crate::core::cancel::CancelHandle::new(),
        };
        let err = DomainsDb
            .process(&Target::new(TargetKind::Domain, "example.com"), &ctx)
            .await
            .expect_err("an unconfigured key must be a MissingKey skip, not a silent empty result");
        assert!(
            matches!(err, crate::core::error::Error::MissingKey(ref k) if k == KEY_ENV),
            "must name the domainsdb key env so the operator sees the signup hint: {err:?}"
        );
    }

    #[tokio::test]
    async fn a_rejected_key_is_a_surfaced_error_not_a_clean_empty_result() {
        // Regression: the 401/403 arm reported the key to the pool and `break`,
        // then fell through to `Ok(result)` with `result` still empty — so a
        // configured-but-expired key was indistinguishable from "this subject
        // has no look-alike domains". The comment on that arm already promised
        // "the surfaced error is the operator's signal"; no error was ever
        // constructed. `ModuleResult::or_hard_failure` names this exact
        // invariant: "a total outage must never be indistinguishable from a
        // clean negative."
        //
        // Hermetic: a loopback listener, a plain `reqwest::Client` (NOT
        // `build_client()`, whose SSRF resolver filters loopback), and no
        // `ModuleContext` — so no `report_key_exhausted`, hence no key-pool
        // write under `$HOME`.
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let hits = Arc::new(AtomicU32::new(0));
        let hits_srv = Arc::clone(&hits);

        tokio::spawn(async move {
            // One accept per zone at most; the assertion below pins that the
            // sweep stops after the first rejection rather than earning six.
            for _ in 0..6 {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                hits_srv.fetch_add(1, Ordering::SeqCst);
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                    .await;
                let _ = sock.flush().await;
            }
        });

        let mut auth_rejected = None;
        let res = super::collect_zones(
            &reqwest::Client::new(),
            &format!("http://{addr}/v1/domains/search"),
            "expired-key",
            "acme",
            "t",
            &crate::core::cancel::CancelHandle::new(),
            &mut auth_rejected,
        )
        .await;

        // FAILS before the fix (pre-fix returned `Ok(ModuleResult::new())`).
        let err = res.expect_err(
            "a 401 on a CONFIGURED key must surface as an error, not Ok(empty) — \
             otherwise a dead key reads as a clean negative on every scan",
        );
        assert!(
            err.to_string().contains("401"),
            "the operator-facing message must name the rejecting status: {err}"
        );
        // The caller still gets the signal it needs to mark the key Invalid.
        assert_eq!(
            auth_rejected,
            Some(401),
            "the rejecting status must reach the caller so the key is reported to the pool"
        );
        // Retry-futile: one rejection ends the sweep, it does not earn six.
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "a dead key must not generate one rejected request per zone"
        );
    }

    #[test]
    fn a_rejection_never_discards_findings_already_collected() {
        // The other half of the contract: `or_hard_failure` errors ONLY when the
        // result is empty, so a rejection from a LATER zone can never throw away
        // domains an EARLIER zone already yielded. Pure — no listener needed.
        let mut partial = ModuleResult::new();
        partial.extend(build_domain_entity(
            &entry(r#"{"domain":"acme.com","create_date":"2020-01-01","isDead":"False"}"#),
            false,
            "t",
        ));
        assert_eq!(partial.len(), 1, "fixture must produce one entity");

        let kept = partial
            .or_hard_failure(Some(crate::core::error::Error::module(SRC, "HTTP 401")))
            .expect("a later zone's rejection must never discard an earlier zone's findings");
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn deser() {
        let j = r#"{"domains":[{"domain":"example.com","create_date":"2020-01-01","isDead":"False"}],"total":1}"#;
        let r: DbResp = serde_json::from_str(j).expect("should succeed");
        assert_eq!(r.domains.len(), 1);
        assert_eq!(r.total, Some(1));
    }

    #[test]
    fn live_domain_surfaces_created_and_updated() {
        let e = build_domain_entity(
            &entry(
                r#"{"domain":"acme-corp.com","create_date":"2019-03-01",
                    "update_date":"2024-06-15","country":"US","isDead":"False"}"#,
            ),
            false,
            "s",
        )
        .expect("should succeed");
        assert_eq!(e.kind, EntityKind::Domain);
        assert!(e.has_tag("domainsdb") && !e.has_tag("dead-domain") && !e.has_tag("broad-match"));
        assert!((e.confidence - confidence::MEDIUM_HIGH).abs() < 1e-9);
        let ev = &e.evidence[0];
        assert_eq!(
            ev.attributes.get("created").map(String::as_str),
            Some("2019-03-01")
        );
        // `updated` — the field the struct-level allow used to bury.
        assert_eq!(
            ev.attributes.get("updated").map(String::as_str),
            Some("2024-06-15")
        );
        assert_eq!(ev.attributes.get("country").map(String::as_str), Some("US"));
    }

    #[test]
    fn dead_domain_is_tagged_and_lower_confidence() {
        let e = build_domain_entity(
            &entry(r#"{"domain":"gone.com","isDead":"True"}"#),
            false,
            "s",
        )
        .expect("should succeed");
        assert!(e.has_tag("dead-domain"));
        assert!((e.confidence - 0.35).abs() < 1e-9);
    }

    #[test]
    fn broad_match_dampens_and_tags() {
        // A generic keyword (high `total`) → broad-match: tagged + 0.7× damped.
        let e = build_domain_entity(&entry(r#"{"domain":"john-smith.com"}"#), true, "s").expect("should succeed");
        assert!(e.has_tag("broad-match"));
        assert!((e.confidence - confidence::MEDIUM_HIGH * 0.7).abs() < 1e-9);
        // Dead + broad stacks both penalties.
        let dead = build_domain_entity(&entry(r#"{"domain":"x.com","isDead":"True"}"#), true, "s")
            .expect("should succeed");
        assert!((dead.confidence - 0.35 * 0.7).abs() < 1e-9);
    }

    #[test]
    fn blank_domain_is_skipped() {
        assert!(build_domain_entity(&entry(r#"{"domain":"  "}"#), false, "s").is_none());
    }
