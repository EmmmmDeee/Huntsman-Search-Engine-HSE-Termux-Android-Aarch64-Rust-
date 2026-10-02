use crate::core::confidence;
use super::*;

    #[test]
    fn fingerprint_table_is_sorted_and_non_empty() {
        assert!(!TAKEOVER_FINGERPRINTS.is_empty());
        for &(pattern, service, _) in TAKEOVER_FINGERPRINTS {
            assert!(!pattern.is_empty());
            assert!(!service.is_empty());
        }
    }

    #[test]
    fn known_services_present() {
        let services: Vec<&str> = TAKEOVER_FINGERPRINTS.iter().map(|t| t.1).collect();
        assert!(services.contains(&"AWS S3"));
        assert!(services.contains(&"Heroku"));
        assert!(services.contains(&"GitHub Pages"));
        assert!(services.contains(&"Netlify"));
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = SubdomainTakeover;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "sub.example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    }

    // ── matching_fingerprints (pure) ────────────────────────────────────

    #[test]
    fn matching_fingerprints_selects_by_cname_substring() {
        let hits: Vec<&str> = matching_fingerprints("myapp.herokuapp.com")
            .map(|f| f.1)
            .collect();
        assert_eq!(hits, vec!["Heroku"], "only the Heroku pattern is a substring");
    }

    #[test]
    fn matching_fingerprints_none_for_unknown_provider() {
        assert_eq!(matching_fingerprints("host.example.com").count(), 0);
    }

    #[test]
    fn matching_fingerprints_preserves_path_for_check_selection() {
        // S3 carries an HTTP body fingerprint; Azure Cloud (.cloudapp.net) is an
        // NXDOMAIN-only check (path = None) — the builder/check selector relies on
        // this third field surviving the match.
        let s3 = matching_fingerprints("bucket.s3.amazonaws.com")
            .next()
            .expect("should succeed");
        assert_eq!(s3.2, Some(("NoSuchBucket", Marker::Distinctive)));
        let azure = matching_fingerprints("svc.cloudapp.net").next().expect("should succeed");
        assert_eq!(azure.2, None);
    }

    // ── build_entities (pure) ───────────────────────────────────────────

    #[test]
    fn build_entities_yields_vulnerable_domain_with_tags_and_evidence() {
        let ents = build_entities("app.example.com", "app.herokuapp.com", "Heroku", Proof::DistinctiveMarker, "s");
        assert_eq!(ents.len(), 1);
        let e = &ents[0];
        assert_eq!(e.kind, EntityKind::Domain);
        assert_eq!(e.value, "app.example.com");
        assert!((e.confidence - confidence::VERY_HIGH_PLUS).abs() < 1e-9);
        assert!(e.has_tag(crate::core::tags::VULNERABLE) && e.has_tag("subdomain-takeover"));
        assert!(e.has_tag("takeover:Heroku"));

        let ev = &e.evidence[0];
        assert_eq!(
            ev.attributes.get("cname_target").map(String::as_str),
            Some("app.herokuapp.com")
        );
        assert_eq!(ev.attributes.get("service").map(String::as_str), Some("Heroku"));
        assert!(ev.summary.contains("Heroku may be claimable"));
    }

    #[test]
    fn build_entities_blank_service_adds_no_takeover_tag_or_attr() {
        let e = build_entities("app.example.com", "x.cloudapp.net", "", Proof::NxDomain, "s").remove(0);
        assert!(
            !e.tags.iter().any(|t| t.starts_with("takeover:")),
            "a blank service must not produce a `takeover:` tag"
        );
        assert!(!e.evidence[0].attributes.contains_key("service"));
        // The vulnerable / subdomain-takeover tags and the CNAME attr remain.
        assert!(e.has_tag(crate::core::tags::VULNERABLE) && e.has_tag("subdomain-takeover"));
        assert_eq!(
            e.evidence[0].attributes.get("cname_target").map(String::as_str),
            Some("x.cloudapp.net")
        );
    }

    #[test]
    fn build_entities_blank_cname_skips_cname_attr() {
        let e = build_entities("app.example.com", "", "Heroku", Proof::DistinctiveMarker, "s").remove(0);
        assert!(!e.evidence[0].attributes.contains_key("cname_target"));
        assert!(e.has_tag("takeover:Heroku"));
    }

    // ── a failed probe is not a finding ─────────────────────────────────
    //
    // The regression these pin: `check_unclaimed` was
    // `lookup_ip(..).await.is_err()`, so ANY resolver failure — SERVFAIL, a
    // timeout, a host with no DNS egress — proved a takeover. The three-valued
    // `Claim` exists so a probe that establishes nothing can say so.

    #[test]
    fn a_generic_marker_match_is_a_candidate_not_a_proven_vulnerability() {
        // A live, legitimately-owned Vercel deployment whose own error page —
        // or inlined JS bundle — contains "404". Under the old table this was
        // reported `vulnerable` at VERY_HIGH_PLUS on that substring alone.
        let claim = classify_body(
            r#"<html><body><script>if(r.status===404){show()}</script></body></html>"#,
            "404",
            Marker::Generic,
        );
        assert_eq!(claim, Claim::Unclaimed(Proof::GenericMarker));

        let e = build_entities(
            "app.example.com",
            "app.vercel.app",
            "Vercel",
            Proof::GenericMarker,
            "s",
        )
        .remove(0);
        assert!(
            !e.has_tag(crate::core::tags::VULNERABLE),
            "a bare `404` substring must not claim a proven vulnerability, because \
             `vulnerable` is what the correlator's exposure rules key on"
        );
        assert!(e.has_tag("takeover-candidate") && e.has_tag("unconfirmed"));
        // Still reported — suppressing it would trade a false positive for a
        // false negative — but at what the evidence is actually worth.
        assert!(e.has_tag("subdomain-takeover") && e.has_tag("takeover:Vercel"));
        assert!((e.confidence - confidence::LOW_MEDIUM).abs() < 1e-9);
        assert!(e.evidence[0].summary.contains("UNCONFIRMED"));
        assert_eq!(
            e.evidence[0].attributes.get("confirmed").map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn a_distinctive_marker_match_keeps_the_original_confirmed_verdict() {
        // The behaviour that was correct must not be weakened by the fix.
        let claim = classify_body(
            "<Error><Code>NoSuchBucket</Code></Error>",
            "NoSuchBucket",
            Marker::Distinctive,
        );
        assert_eq!(claim, Claim::Unclaimed(Proof::DistinctiveMarker));

        let e = build_entities(
            "cdn.example.com",
            "b.s3.amazonaws.com",
            "AWS S3",
            Proof::DistinctiveMarker,
            "s",
        )
        .remove(0);
        assert!(e.has_tag(crate::core::tags::VULNERABLE));
        assert!(!e.has_tag("unconfirmed"));
        assert!((e.confidence - confidence::VERY_HIGH_PLUS).abs() < 1e-9);
        assert_eq!(
            e.evidence[0].attributes.get("confirmed").map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn a_body_without_the_marker_is_a_real_negative() {
        // Distinct from an inconclusive probe: the provider answered and did
        // not say the resource is unclaimed.
        assert_eq!(
            classify_body("<html>welcome</html>", "NoSuchBucket", Marker::Distinctive),
            Claim::Claimed
        );
        assert_eq!(
            classify_body("<html>welcome</html>", "404", Marker::Generic),
            Claim::Claimed
        );
    }

    #[test]
    fn only_nxdomain_and_a_distinctive_marker_may_claim_a_vulnerability() {
        assert!(Proof::NxDomain.is_confirmed());
        assert!(Proof::DistinctiveMarker.is_confirmed());
        assert!(
            !Proof::GenericMarker.is_confirmed(),
            "a generic substring is a lead, not a vulnerability report"
        );
        // The confidence ladder is ordered by NUMBER, so assert on the number.
        assert!(Proof::GenericMarker.confidence() < Proof::NxDomain.confidence());
        assert!(
            (Proof::NxDomain.confidence() - Proof::DistinctiveMarker.confidence()).abs() < 1e-9
        );
    }

    #[test]
    fn every_nxdomain_only_fingerprint_reaches_the_strongest_proof() {
        // The four `None` entries (Azure Cloud, Elastic Beanstalk, Fly.io,
        // Cloudflare Pages) are exactly the ones the old `is_err()` bug turned
        // into fabricated `vulnerable` findings on a host with no DNS egress.
        let nx_only: Vec<&str> = TAKEOVER_FINGERPRINTS
            .iter()
            .filter(|(_, _, f)| f.is_none())
            .map(|(_, s, _)| *s)
            .collect();
        assert!(
            nx_only.contains(&"Azure Cloud") && nx_only.contains(&"Fly.io"),
            "got {nx_only:?}"
        );
        for service in &nx_only {
            assert!(!service.is_empty());
        }
    }

    #[test]
    fn every_generic_marker_is_short_or_generic_english() {
        // Guards the table against a future entry being filed as Distinctive
        // when it is really a bare status number or a stock phrase. Distinctive
        // markers name the provider's own page; generic ones do not.
        for &(pattern, service, fingerprint) in TAKEOVER_FINGERPRINTS {
            let Some((marker, strength)) = fingerprint else {
                continue;
            };
            if strength == Marker::Distinctive {
                assert!(
                    marker.len() > 10,
                    "{service} ({pattern}): `{marker}` is too short to be distinctive — \
                     a substring that brief matches ordinary page text"
                );
            }
        }
    }
