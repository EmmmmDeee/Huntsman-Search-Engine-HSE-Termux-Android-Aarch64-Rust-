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
