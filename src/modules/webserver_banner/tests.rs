use super::*;
    use crate::core::entity::EntityKind;

    #[test]
    fn accepts_domain_ip_and_url() {
        let m = WebserverBanner;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com/path")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b")));
    }

    #[test]
    fn apply_stack_tags_recognises_common_stacks() {
        let mut e = Entity::new(EntityKind::Domain, "x.com", 0.5, "s");
        apply_stack_tags(
            &mut e,
            &[
                ("server".into(), "nginx/1.18.0".into()),
                ("x-powered-by".into(), "PHP/8.1.0".into()),
            ],
        );
        assert!(e.has_tag("nginx"));
        assert!(e.has_tag("php"));
        assert!(!e.has_tag("iis"));
    }

    #[test]
    fn apply_stack_tags_recognises_cdns() {
        let mut e = Entity::new(EntityKind::Domain, "x.com", 0.5, "s");
        apply_stack_tags(&mut e, &[("cf-ray".into(), "1234abcd".into())]);
        assert!(e.has_tag("cloudflare"));
    }

    fn tags_for(headers: &[(&str, &str)]) -> Entity {
        let mut e = Entity::new(EntityKind::Domain, "x.com", 0.5, "s");
        let owned: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        apply_stack_tags(&mut e, &owned);
        e
    }

    #[test]
    fn apply_stack_tags_covers_full_signature_set() {
        // IIS via Server value, ASP.NET via header name.
        let e = tags_for(&[
            ("server", "Microsoft-IIS/10.0"),
            ("x-aspnet-version", "4.0.30319"),
        ]);
        assert!(e.has_tag("iis") && e.has_tag("aspnet"));

        // Cloudflare via Server value (not just cf-ray).
        assert!(tags_for(&[("server", "cloudflare")]).has_tag("cloudflare"));
        // AWS CloudFront + Fastly are header-name driven.
        assert!(tags_for(&[("x-amz-cf-id", "abc")]).has_tag("aws-cloudfront"));
        assert!(tags_for(&[("x-served-by", "cache-syd")]).has_tag("fastly"));
        assert!(tags_for(&[("x-cache", "HIT")]).has_tag("fastly"));
        // CMS fingerprints in any header value.
        assert!(tags_for(&[("x-generator", "WordPress 6.5")]).has_tag("wordpress"));
        assert!(tags_for(&[("x-generator", "Drupal 10 (https://drupal.org)")]).has_tag("drupal"));
        // Apache.
        assert!(tags_for(&[("server", "Apache/2.4.52")]).has_tag("apache"));
    }

    #[test]
    fn apply_stack_tags_is_case_insensitive_and_quiet_on_unknown() {
        assert!(tags_for(&[("server", "NGINX/1.25")]).has_tag("nginx"));
        // An unrecognised stack raises none of the family tags.
        let e = tags_for(&[("server", "GoatServer/1.0")]);
        for t in ["nginx", "apache", "iis", "cloudflare", "wordpress", "php"] {
            assert!(!e.has_tag(t), "unexpected tag {t}");
        }
    }

    #[test]
    fn capture_headers_keeps_only_fingerprint_headers_nonempty() {
        use reqwest::header::{HeaderMap, HeaderValue};
        let mut h = HeaderMap::new();
        h.insert("server", HeaderValue::from_static("nginx"));
        h.insert("content-type", HeaderValue::from_static("text/html")); // not fingerprint
        h.insert("x-powered-by", HeaderValue::from_static("")); // empty → dropped
        let got = capture_headers(&h);
        assert_eq!(got, vec![("server".to_string(), "nginx".to_string())]);
    }

    #[test]
    fn extract_host_port_handles_url_domain_and_rejects_junk() {
        // URL with explicit port.
        assert_eq!(
            extract_host_port(TargetKind::Url, "https://example.com:8443/a"),
            Some(("example.com".to_string(), Some(8443)))
        );
        // URL without explicit port → None port.
        assert_eq!(
            extract_host_port(TargetKind::Url, "http://host.org/"),
            Some(("host.org".to_string(), None))
        );
        // Bare domain.
        assert_eq!(
            extract_host_port(TargetKind::Domain, "  example.com "),
            Some(("example.com".to_string(), None))
        );
        // Unparseable URL and a path-shaped domain → nothing to probe.
        assert_eq!(extract_host_port(TargetKind::Url, "not a url"), None);
        assert_eq!(extract_host_port(TargetKind::Domain, "x.com/path"), None);
        assert_eq!(extract_host_port(TargetKind::Domain, "  "), None);
    }

    #[test]
    fn banner_entity_rebases_a_url_target_to_its_host_domain() {
        // The probe only ever HEADs the domain root (see `extract_host_port`
        // discarding the path) — a real scan against a guessed profile handle
        // (`https://<platform>/<handle>`) showed this module re-emitting the
        // full path via `to_entity()`, so its evidence (which is identical
        // for ANY handle on that platform) counted as an "independent source"
        // corroborating that specific, unverified path. Rebasing to the host
        // as a Domain entity is the fix: the entity now matches what was
        // actually confirmed.
        let t = Target::new(TargetKind::Url, "https://onlyfans.com/rob_dorito");
        let e = banner_entity(&t, "onlyfans.com", 0.85, "scan1");
        assert_eq!(e.kind, EntityKind::Domain);
        assert_eq!(e.value, "onlyfans.com");
    }

    #[test]
    fn banner_entity_keeps_domain_and_ip_targets_as_is() {
        // These ARE the exact value HEADed, so re-emitting them verbatim via
        // `to_entity()` is correct — only the Url case needs rebasing.
        let t = Target::new(TargetKind::Domain, "example.com");
        let e = banner_entity(&t, "example.com", 0.85, "scan1");
        assert_eq!(e.kind, EntityKind::Domain);
        assert_eq!(e.value, "example.com");

        let t = Target::new(TargetKind::IpAddress, "1.2.3.4");
        let e = banner_entity(&t, "1.2.3.4", 0.85, "scan1");
        assert_eq!(e.kind, EntityKind::IpAddress);
        assert_eq!(e.value, "1.2.3.4");
    }

    // -- process() total-transport-failure guard (T2.166) -------------------

    fn test_ctx() -> ModuleContext {
        let (bus, _rx) = tokio::sync::broadcast::channel(1);
        ModuleContext {
            scan_id: "t".into(),
            bus,
            http: reqwest::Client::new(),
            keys: std::collections::HashMap::new(),
            cancel: crate::core::cancel::CancelHandle::new(),
        }
    }

    #[tokio::test]
    async fn process_surfaces_err_when_both_schemes_fail_transport() {
        // T2.166 regression: the loop's `let Ok(resp) = ... else { continue }`
        // previously discarded every transport failure with no counter, so a
        // host that refuses both HTTPS and HTTP outright produced the same
        // Ok(empty) as a host that answered both but had no fingerprint
        // headers.
        let target = Target::new(TargetKind::Url, "http://127.0.0.1:1/");
        let ctx = test_ctx();
        let out = WebserverBanner.process(&target, &ctx).await;
        assert!(
            out.is_err(),
            "a host refusing both schemes must surface as Err, not a silent empty result"
        );
    }

    #[tokio::test]
    async fn process_stays_ok_when_only_one_scheme_fails_transport() {
        // The HTTPS attempt against a plain-HTTP listener fails at the TLS
        // layer (a real transport failure); the HTTP fallback then reaches
        // the same server and gets a real answer. Only one of the two
        // attempts failed transport-wise, so this must stay Ok — never
        // escalate just because the higher-priority scheme alone failed.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // Exactly two sequential connection attempts are expected — the
            // failed HTTPS handshake, then the successful HTTP fallback.
            for _ in 0..2 {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = vec![0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body = "";
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });
        let target = Target::new(TargetKind::Url, format!("http://{addr}/"));
        let ctx = test_ctx();
        let out = WebserverBanner.process(&target, &ctx).await;
        assert!(
            out.is_ok(),
            "only one scheme failing transport-wise must not escalate to Err: {out:?}"
        );
    }
