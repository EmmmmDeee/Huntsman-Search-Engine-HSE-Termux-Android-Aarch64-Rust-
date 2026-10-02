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
        // Inverted (REQ-WEBBANNER-001). This previously read
        // `assert!(tags_for(&[("x-cache", "HIT")]).has_tag("fastly"));` —
        // asserting that a bare `x-cache` names Fastly. It does not:
        // IDENTIFYING_HEADERS' own doc lists `x-cache` as a generic caching
        // header, and Varnish, CloudFront, Akamai and nginx's proxy cache all
        // emit it. Naming one vendor from a signal shared by its competitors
        // is a guess, not a fingerprint.
        assert!(!tags_for(&[("x-cache", "HIT")]).has_tag("fastly"));
        // CMS fingerprints in an IDENTIFYING header's value — `x-generator`
        // here. A value carried by a generic header (a CSP, HSTS, XFO) is no
        // longer scanned; `a_csp_naming_someone_elses_cdn_is_not_this_sites_stack`
        // owns that case.
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
    fn banner_confidence_is_high_when_an_identifying_header_is_present() {
        let captured = vec![("server".to_string(), "nginx/1.24.0".to_string())];
        assert!((banner_confidence(&captured) - confidence::HIGH_PLUSPLUS_PLUS).abs() < f64::EPSILON);
    }

    #[test]
    fn banner_confidence_is_lower_for_generic_security_headers_alone() {
        // Regression: a capture made up ENTIRELY of generic security-posture
        // headers (present on countless unrelated stacks, revealing nothing
        // distinctive about this one) used to get the same flat
        // HIGH_PLUSPLUS_PLUS confidence as an actual stack banner.
        let captured = vec![
            ("x-frame-options".to_string(), "SAMEORIGIN".to_string()),
            ("strict-transport-security".to_string(), "max-age=31536000".to_string()),
        ];
        let got = banner_confidence(&captured);
        assert!(
            got < confidence::HIGH_PLUSPLUS_PLUS,
            "generic-only headers must not earn the same confidence as an identifying banner, got {got}"
        );
    }

    #[test]
    fn banner_confidence_upgrades_the_moment_one_identifying_header_appears() {
        // Even mixed in with generic headers, a single identifying header is
        // enough to earn the high-confidence verdict.
        let captured = vec![
            ("x-frame-options".to_string(), "SAMEORIGIN".to_string()),
            ("x-powered-by".to_string(), "PHP/8.1.0".to_string()),
        ];
        assert!((banner_confidence(&captured) - confidence::HIGH_PLUSPLUS_PLUS).abs() < f64::EPSILON);
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
        let e = banner_entity(&t, "onlyfans.com", confidence::HIGH_PLUSPLUS_PLUS, "scan1");
        assert_eq!(e.kind, EntityKind::Domain);
        assert_eq!(e.value, "onlyfans.com");
    }

    #[test]
    fn banner_entity_keeps_domain_and_ip_targets_as_is() {
        // These ARE the exact value HEADed, so re-emitting them verbatim via
        // `to_entity()` is correct — only the Url case needs rebasing.
        let t = Target::new(TargetKind::Domain, "example.com");
        let e = banner_entity(&t, "example.com", confidence::HIGH_PLUSPLUS_PLUS, "scan1");
        assert_eq!(e.kind, EntityKind::Domain);
        assert_eq!(e.value, "example.com");

        let t = Target::new(TargetKind::IpAddress, "1.2.3.4");
        let e = banner_entity(&t, "1.2.3.4", confidence::HIGH_PLUSPLUS_PLUS, "scan1");
        assert_eq!(e.kind, EntityKind::IpAddress);
        assert_eq!(e.value, "1.2.3.4");
    }

    /// REQ-WEBBANNER-001. `apply_stack_tags` joined EVERY captured header's
    /// value into one substring-searched blob, including the three
    /// `FINGERPRINT_HEADERS` that `IDENTIFYING_HEADERS`' own doc calls "purely
    /// security-posture / caching headers present on countless unrelated
    /// stacks [that] confirm nothing distinctive by themselves".
    ///
    /// A `content-security-policy` is the pointed case: it ENUMERATES OTHER
    /// PEOPLE'S DOMAINS by design. Loading a script from `cdnjs.cloudflare.com`
    /// — routine — put "cloudflare" in the blob and tagged the site as
    /// Cloudflare-fronted when it may have no CDN at all.
    ///
    /// Every generic-header carrier is swept and survivors collected, so a
    /// partial fix is named rather than masked by the first case.
    #[test]
    fn a_csp_naming_someone_elses_cdn_is_not_this_sites_stack() {
        let mut leaked: Vec<(&str, &str, &str)> = Vec::new();
        for (header, value, tag) in [
            // The real-world one: cdnjs is on countless sites' CSP.
            (
                "content-security-policy",
                "default-src 'self'; script-src https://cdnjs.cloudflare.com",
                "cloudflare",
            ),
            (
                "content-security-policy",
                "script-src https://s.w.org https://wordpress.example/wp.js",
                "wordpress",
            ),
            (
                "content-security-policy",
                "form-action https://legacy.example/login.php",
                "php",
            ),
            (
                "content-security-policy",
                "frame-ancestors https://portal.drupal.org",
                "drupal",
            ),
            // The other two generic carriers named in the doc.
            ("strict-transport-security", "max-age=31536000; nginx", "nginx"),
            ("x-frame-options", "ALLOW-FROM https://apache.example", "apache"),
            // `via` and `x-cache` are generic too (same doc sentence).
            ("via", "1.1 cloudflare", "cloudflare"),
            ("x-cache", "MISS from nginx-edge", "nginx"),
        ] {
            if tags_for(&[(header, value)]).has_tag(tag) {
                leaked.push((header, value, tag));
            }
        }
        assert!(
            leaked.is_empty(),
            "a generic header's value was read as this site's stack: {leaked:?}"
        );
    }

    /// Proves the filter keys on WHICH header carried the value rather than
    /// having disabled the tagging: every identifying carrier still
    /// fingerprints, including with a misleading generic header beside it.
    ///
    /// Note this is not a pure control — it also asserts the adjacent CSP does
    /// NOT tag, so it fails on the baseline for that reason. The tagging half
    /// (`nginx`, `php`, `apache`, `wordpress` from identifying headers) is what
    /// passes on both sides; the always-green controls are the pre-existing
    /// `apply_stack_tags_*` and `banner_confidence_*` tests, which the fix
    /// leaves untouched.
    #[test]
    fn an_identifying_header_still_fingerprints_beside_a_noisy_generic_one() {
        let e = tags_for(&[
            ("server", "nginx/1.24.0"),
            // A CSP naming a competitor must not add its tag…
            (
                "content-security-policy",
                "script-src https://cdnjs.cloudflare.com",
            ),
        ]);
        assert!(e.has_tag("nginx"), "the real Server banner must still tag");
        assert!(
            !e.has_tag("cloudflare"),
            "the CSP's third-party domain must not tag"
        );
        // And every identifying carrier keeps working on its own.
        assert!(tags_for(&[("x-powered-by", "PHP/8.1.0")]).has_tag("php"));
        assert!(tags_for(&[("server", "Apache/2.4.52")]).has_tag("apache"));
        assert!(tags_for(&[("x-generator", "WordPress 6.5")]).has_tag("wordpress"));
    }

    /// REQ-WEBBANNER-001, the transport half. Both schemes' failures were
    /// discarded by `let Ok(resp) = … else { continue; }` and the loop fell
    /// through to `Ok(empty)` — so "unreachable / TLS failed / refused" was
    /// indistinguishable from "answered, published no fingerprint headers".
    /// The second is a real negative finding; the first is no observation at
    /// all, and banking it as clean hides a dead host from the breaker, the
    /// doctor and the live-drift sweep.
    ///
    /// Driven against a CLOSED LOCAL PORT (`ClosedPort`, held for the whole
    /// test): a deterministic connection-refused with no DNS and no external
    /// network, so this runs in CI rather than being ignored.
    #[tokio::test]
    async fn both_transports_failing_is_not_a_clean_negative() {
        let closed = crate::util::http::test_server::ClosedPort::new();
        let port = closed.addr().port();
        let (bus, _rx) = tokio::sync::broadcast::channel(1);
        let ctx = ModuleContext {
            scan_id: "t".into(),
            bus,
            http: reqwest::Client::new(),
            keys: std::collections::HashMap::new(),
            cancel: crate::core::cancel::CancelHandle::new(),
        };
        let target = Target::new(TargetKind::Url, format!("http://127.0.0.1:{port}/"));
        let r = WebserverBanner.process(&target, &ctx).await;
        assert!(
            r.is_err(),
            "both transports refused must surface as an error, got {:?}",
            r.map(|ok| ok.entities.len())
        );
    }
