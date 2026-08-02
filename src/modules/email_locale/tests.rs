use super::*;

    #[test]
    fn swedish_surname() {
        let geo = detect_locale_from_local_part("erik.johansson").expect("should succeed");
        assert!(geo.region.contains("Scandinavia"));
    }

    #[test]
    fn polish_surname() {
        let geo = detect_locale_from_local_part("jan.kowalczyk").expect("should succeed");
        assert!(geo.region.contains("Poland"));
    }

    #[test]
    fn french_given_name() {
        let geo = detect_locale_from_local_part("guillaume.martin").expect("should succeed");
        assert!(geo.region.contains("France"));
    }

    #[test]
    fn detection_is_case_insensitive() {
        // Local-part case isn't significant; a capitalised name (the common
        // `First.Last@` form) or an all-caps address must match the same as the
        // lowercase form — not silently miss.
        assert!(
            detect_locale_from_local_part("Guillaume.Martin")
                .expect("should succeed")
                .region
                .contains("France")
        );
        assert!(
            detect_locale_from_local_part("ERIK.JOHANSSON")
                .expect("should succeed")
                .region
                .contains("Scandinavia")
        );
    }

    #[test]
    fn generic_name_returns_none() {
        assert!(detect_locale_from_local_part("john.smith").is_none());
    }

    #[test]
    fn no_dot_returns_none() {
        assert!(detect_locale_from_local_part("johndoe").is_none());
    }

    #[test]
    fn ambiguous_cctld_locales_get_their_own_country_centroid() {
        // `es-mx`, `es-ar`, and `pt-br` are unambiguous ccTLD-derived signals
        // (.mx/.ar/.br) and must each resolve to their OWN national capital, not
        // be folded into the "parent language" country's centroid (Madrid /
        // Lisbon) — Mexico City is not Madrid, Buenos Aires is not Madrid, and
        // Brasília is not Lisbon.
        let (mx_lat, mx_lon) = locale_centroid("es-mx").expect("should succeed");
        let (es_lat, es_lon) = locale_centroid("es").expect("should succeed");
        assert!(
            (mx_lat - es_lat).abs() > 1.0 || (mx_lon - es_lon).abs() > 1.0,
            "es-mx must not resolve to Spain's centroid: got ({mx_lat}, {mx_lon})"
        );
        assert!(
            (mx_lat - 19.4326).abs() < 0.01 && (mx_lon - (-99.1332)).abs() < 0.01,
            "es-mx must resolve to Mexico City: got ({mx_lat}, {mx_lon})"
        );

        let (ar_lat, ar_lon) = locale_centroid("es-ar").expect("should succeed");
        assert!(
            (ar_lat - es_lat).abs() > 1.0 || (ar_lon - es_lon).abs() > 1.0,
            "es-ar must not resolve to Spain's centroid: got ({ar_lat}, {ar_lon})"
        );
        assert!(
            (ar_lat - (-34.6037)).abs() < 0.01 && (ar_lon - (-58.3816)).abs() < 0.01,
            "es-ar must resolve to Buenos Aires: got ({ar_lat}, {ar_lon})"
        );

        let (br_lat, br_lon) = locale_centroid("pt-br").expect("should succeed");
        let (pt_lat, pt_lon) = locale_centroid("pt").expect("should succeed");
        assert!(
            (br_lat - pt_lat).abs() > 1.0 || (br_lon - pt_lon).abs() > 1.0,
            "pt-br must not resolve to Portugal's centroid: got ({br_lat}, {br_lon})"
        );
        assert!(
            (br_lat - (-15.7939)).abs() < 0.01 && (br_lon - (-47.8827)).abs() < 0.01,
            "pt-br must resolve to Brasília: got ({br_lat}, {br_lon})"
        );
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = EmailLocale;
        assert!(m.is_passive());
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
    }

    /// AU-083 (`core::correlator::rules::locale::rule_au_083_locale_multi_email_corroboration`)
    /// requires >=2 `email_locale`-sourced evidence entries on the SAME
    /// locale-inferred Address entity — i.e. two DISTINCT emails independently
    /// matching the same locale pattern. `Entity::absorb`'s evidence dedup keys
    /// on `(source, summary)`, so if the emitted summary is derived only from
    /// the locale/pattern (not the source email), two genuinely different
    /// emails matching the SAME pattern produce byte-identical evidence and
    /// collapse into ONE entry on merge — the real end-to-end path this test
    /// exercises (module emission → same-uid merge), unlike the correlator's
    /// own unit tests which hand-construct two evidence entries directly and
    /// so never exercise the dedup that breaks the real pipeline.
    #[tokio::test]
    async fn two_distinct_emails_sharing_a_locale_pattern_both_survive_the_merge() {
        let (bus, _rx) = tokio::sync::broadcast::channel(1);
        let ctx = ModuleContext {
            scan_id: "s".into(),
            bus,
            http: reqwest::Client::new(),
            keys: std::collections::HashMap::new(),
            cancel: crate::core::cancel::CancelHandle::new(),
        };

        // Two DIFFERENT people, both with Swedish "-sson" surnames — distinct
        // local-parts independently matching the same "sv" locale pattern.
        let r1 = EmailLocale
            .process(&Target::new(TargetKind::Email, "erik.hansson@example.com"), &ctx)
            .await
            .expect("should succeed");
        let r2 = EmailLocale
            .process(&Target::new(TargetKind::Email, "lars.svensson@example.net"), &ctx)
            .await
            .expect("should succeed");

        let mut addr1 = r1
            .entities
            .into_iter()
            .find(|e| e.kind == EntityKind::Address && e.has_tag("locale-inferred"))
            .expect("erik.hansson must produce a locale-inferred Address entity");
        let addr2 = r2
            .entities
            .into_iter()
            .find(|e| e.kind == EntityKind::Address && e.has_tag("locale-inferred"))
            .expect("lars.svensson must produce a locale-inferred Address entity");
        assert_eq!(
            addr1.uid, addr2.uid,
            "both emails must resolve to the SAME region/uid — the scenario AU-083 corroborates"
        );

        addr1.merge(addr2);
        let locale_count = addr1
            .evidence
            .iter()
            .filter(|ev| ev.source == "email_locale")
            .count();
        assert_eq!(
            locale_count, 2,
            "two DISTINCT emails matching the same locale pattern must both survive the merge \
             as separate evidence entries, or AU-083 can never fire from real scan data: {:?}",
            addr1.evidence
        );
    }
