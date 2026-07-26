use super::*;
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::core::event::EventKind;

    /// A `LiveCmd` matching exactly what clap produces when every new flag is
    /// omitted (the CLI-declared `default_value_t`/`Option::None` defaults).
    fn cmd_with_defaults() -> LiveCmd {
        LiveCmd {
            kind: None,
            value: "acme.com".to_string(),
            interval: 30,
            iterations: None,
            depth: 0,
            free_only: false,
            passive_only: false,
            modules: None,
            exclude: None,
            throttle_ms: 0,
            min_confidence: None,
            min_expand_confidence: crate::core::scan::DEFAULT_MIN_EXPAND_CONFIDENCE,
            max_entities: None,
            max_wall_time_secs: None,
            max_concurrent: 2,
            max_roi: false,
            convex_budget: false,
            skip_dead_modules: false,
            regional_search: true,
            min_marginal_yield: None,
            expansion_strategy: "geo_converge".to_string(),
            seeknow_scan_cap: None,
            expand_all_identities: false,
            gate_speculative: false,
            radar: false,
            json: false,
        }
    }

    #[test]
    fn build_live_scan_options_applies_product_defaults_when_every_flag_is_omitted() {
        // The exact discrepancy the audit flagged: `hse live` used to build
        // ScanOptions via `..Default::default()`, landing on the conservative
        // LIBRARY defaults (min_expand_confidence=0.50, max_entities=None)
        // instead of the comprehensive PRODUCT defaults `hse scan` and the
        // API's `default_scan_options()` both apply. Pin the fixed values.
        let opts = build_live_scan_options(&cmd_with_defaults()).expect("should succeed");
        assert_eq!(
            opts.min_expand_confidence,
            crate::core::scan::DEFAULT_MIN_EXPAND_CONFIDENCE,
            "must use the comprehensive 0.20 product floor, not the library's 0.50"
        );
        assert_eq!(
            opts.max_entities,
            Some(crate::core::scan::DEFAULT_MAX_ENTITIES),
            "must apply the product entity cap, not the library's uncapped None"
        );
        assert_eq!(opts.max_concurrent, 2);
        assert!(opts.regional_search);
        assert_eq!(
            opts.expansion_strategy,
            crate::core::scan::ExpansionStrategy::GeoConverge
        );
    }

    #[test]
    fn build_live_scan_options_threads_every_new_flag_through() {
        // Every ScanOptions field the audit found silently dropped
        // (min_confidence, throttle_ms, max_entities, max_wall_time_secs,
        // max_concurrent, max_roi, convex_budget, regional_search,
        // min_marginal_yield, expansion_strategy, seeknow_scan_cap,
        // expand_all_identities, gate_speculative, exclude_modules) must
        // actually reach the ScanOptions passed to the engine, not just exist
        // as inert CLI flags.
        let cmd = LiveCmd {
            modules: Some("whois,dns_intel".to_string()),
            exclude: Some("crtsh".to_string()),
            throttle_ms: 500,
            min_confidence: Some(0.42),
            min_expand_confidence: 0.33,
            max_entities: Some(77),
            max_wall_time_secs: Some(900),
            max_concurrent: 5,
            max_roi: true,
            convex_budget: true,
            regional_search: false,
            min_marginal_yield: Some(0.6),
            expansion_strategy: "richest_first".to_string(),
            seeknow_scan_cap: Some(40),
            expand_all_identities: true,
            gate_speculative: true,
            ..cmd_with_defaults()
        };
        let opts = build_live_scan_options(&cmd).expect("should succeed");
        assert_eq!(opts.modules, Some(vec!["whois".into(), "dns_intel".into()]));
        assert_eq!(opts.exclude_modules, vec!["crtsh".to_string()]);
        assert_eq!(opts.throttle_ms, 500);
        assert_eq!(opts.min_confidence, Some(0.42));
        assert!((opts.min_expand_confidence - 0.33).abs() < 1e-9);
        assert_eq!(opts.max_entities, Some(77));
        assert_eq!(opts.max_wall_time_secs, Some(900));
        assert_eq!(opts.max_concurrent, 5);
        assert!(opts.max_roi);
        assert!(opts.convex_budget);
        assert!(!opts.regional_search);
        assert_eq!(opts.min_marginal_yield, Some(0.6));
        assert_eq!(
            opts.expansion_strategy,
            crate::core::scan::ExpansionStrategy::RichestFirst
        );
        assert_eq!(opts.seeknow_scan_cap, Some(40));
        assert!(opts.expand_all_identities);
        assert!(opts.gate_speculative);
    }

    #[test]
    fn build_live_scan_options_rejects_an_unknown_expansion_strategy() {
        let cmd = LiveCmd {
            expansion_strategy: "bogus".to_string(),
            ..cmd_with_defaults()
        };
        let err = build_live_scan_options(&cmd).expect_err("bogus strategy must be rejected");
        assert!(
            err.to_string().contains("expansion-strategy"),
            "error must name the offending flag: {err}"
        );
    }

    #[test]
    fn render_entity_prints_full_unredacted_evidence() {
        // A stealer record: the password and raw URL MUST appear verbatim — the
        // live view is the transparency contract, nothing masked or truncated.
        let mut e = Entity::new(
            EntityKind::Credential,
            "victim@https://site/login",
            0.6,
            "scan",
        );
        e.tag("see-know");
        e.tag("stealer");
        e.add_evidence(
            Evidence::new("see_know", "SeekNow record from RedlineStealer")
                .with_attr("password", "hunter2-PLAINTEXT")
                .with_attr("url", "https://site/login")
                .with_attr("source", "RedlineStealer"),
        );
        let out = render_event(&EventKind::EntityFound { entity: e });
        assert!(out.contains("victim@https://site/login"));
        assert!(out.contains("see-know, stealer"), "tags must show: {out}");
        // The cleartext secret is present, in full, unmasked.
        assert!(out.contains("password: hunter2-PLAINTEXT"), "got: {out}");
        assert!(out.contains("url: https://site/login"));
    }

    #[test]
    fn render_event_suppresses_empty_module_done() {
        // A module that found nothing yields no line (kept quiet), but a
        // productive one is announced.
        assert_eq!(
            render_event(&EventKind::ModuleDone {
                module: "see_know".into(),
                found: 0,
            }),
            ""
        );
        assert!(
            render_event(&EventKind::ModuleDone {
                module: "see_know".into(),
                found: 3,
            })
            .contains("see_know")
        );
    }
