use super::*;

    #[test]
    fn resolve_known_profiles() {
        assert!(resolve_profile("passive").is_some());
        assert!(resolve_profile("footprint").is_some());
        assert!(resolve_profile("investigate").is_some());
        assert!(resolve_profile("fast").is_some());
    }

    #[test]
    fn resolve_unknown_returns_none() {
        assert!(resolve_profile("nonexistent").is_none());
    }

    #[test]
    fn passive_profile_is_passive_and_free() {
        let opts = resolve_profile("passive").unwrap();
        assert!(opts.passive_only);
        assert!(opts.free_only);
    }

    #[test]
    fn investigate_profile_has_max_depth() {
        let opts = resolve_profile("investigate").unwrap();
        assert_eq!(opts.depth, 5);
        assert!(opts.max_entities.is_some());
    }

    #[test]
    fn fast_profile_is_depth_zero() {
        let opts = resolve_profile("fast").unwrap();
        assert_eq!(opts.depth, 0);
        assert!(opts.free_only);
    }

    #[test]
    fn list_profiles_returns_all() {
        let profiles = list_profiles();
        assert_eq!(profiles.len(), 6);
        assert!(profiles.iter().any(|(n, _)| *n == "recommended"));
        assert!(profiles.iter().any(|(n, _)| *n == "passive"));
        assert!(profiles.iter().any(|(n, _)| *n == "footprint"));
        assert!(profiles.iter().any(|(n, _)| *n == "skiptrace"));
    }

    #[test]
    fn skiptrace_focuses_person_location_and_geo_converges() {
        let opts = resolve_profile("skiptrace").unwrap();
        // Focused on the person-locating categories — and pointedly NOT on the
        // noise categories (infra/threat/DNS/sensor).
        assert_eq!(opts.category_focus, SKIPTRACE_CATEGORIES.to_vec());
        for want in [
            ModuleCategory::People,
            ModuleCategory::Phone,
            ModuleCategory::Geo,
            ModuleCategory::Corporate,
            ModuleCategory::Breach,
        ] {
            assert!(opts.category_focus.contains(&want), "must focus {want:?}");
        }
        for noise in [
            ModuleCategory::Infrastructure,
            ModuleCategory::Threat,
            ModuleCategory::DnsRecon,
            ModuleCategory::Sensor,
        ] {
            assert!(
                !opts.category_focus.contains(&noise),
                "must NOT spend budget on {noise:?}"
            );
        }
        // Converges on where the person lives, expands a few hops, stays bounded.
        assert_eq!(
            opts.expansion_strategy,
            crate::core::scan::ExpansionStrategy::GeoConverge
        );
        assert_eq!(opts.depth, 3);
        assert!(opts.min_expand_confidence <= 0.45);
        assert!(opts.max_entities.is_some() && opts.max_wall_time_secs.is_some());
        // `locate` is an alias for the same profile.
        assert_eq!(resolve_profile("locate").unwrap().depth, opts.depth);
    }

    #[test]
    fn recommended_is_zero_setup_and_correlation_ready() {
        // The out-of-box default: needs no keys (free-only), and expands exactly
        // one round so the cross-service correlation rules can actually fire —
        // depth 0 would find entities but never link them. `default` is an alias.
        let opts = resolve_profile("recommended").unwrap();
        assert!(opts.free_only, "must need no manual key setup");
        assert_eq!(
            opts.depth, 1,
            "one expansion round enables cross-service links"
        );
        assert!(opts.max_entities.is_some(), "phone-safe bound");
        assert!(
            opts.max_wall_time_secs.is_some(),
            "phone-safe wall-time bound"
        );
        // The `default` alias resolves to the same options.
        let aliased = resolve_profile("default").unwrap();
        assert_eq!(aliased.depth, opts.depth);
        assert_eq!(aliased.free_only, opts.free_only);
    }

    #[test]
    fn apply_profile_overlay_preserves_orthogonal_caller_fields() {
        // The bug this function fixes: `opts = profile_opts` (a full replace)
        // silently discarded every client-supplied field the profile doesn't
        // itself tune. `modules`/`min_confidence`/`webhook_url` have no profile
        // equivalent at all, so they must survive the overlay untouched.
        let base = ScanOptions {
            modules: Some(vec!["hunter_io".to_string()]),
            min_confidence: Some(0.7),
            webhook_url: Some("https://example.com/hook".to_string()),
            scan_tags: vec!["case-42".to_string()],
            throttle_ms: 250,
            ..ScanOptions::default()
        };
        let profile = resolve_profile("investigate").unwrap();
        let merged = apply_profile_overlay(base.clone(), profile.clone());

        assert_eq!(
            merged.modules, base.modules,
            "modules must survive the overlay"
        );
        assert_eq!(
            merged.min_confidence, base.min_confidence,
            "min_confidence must survive the overlay"
        );
        assert_eq!(
            merged.webhook_url, base.webhook_url,
            "webhook_url must survive the overlay"
        );
        assert_eq!(merged.scan_tags, base.scan_tags);
        assert_eq!(merged.throttle_ms, base.throttle_ms);

        // The profile's own tuning DOES take effect.
        assert_eq!(merged.depth, profile.depth);
        assert_eq!(merged.max_entities, profile.max_entities);
    }

    #[test]
    fn apply_profile_overlay_carries_every_profile_tuning_field() {
        // skiptrace is the profile that exercises every tuning field,
        // including expansion_strategy/regional_search — the two fields the
        // CLI's old hand-written overlay omitted (dormant only because
        // `ScanOptions::default()` happened to coincide with skiptrace's
        // values for both).
        let base = ScanOptions::default();
        let profile = resolve_profile("skiptrace").unwrap();
        let merged = apply_profile_overlay(base, profile.clone());

        assert_eq!(merged.category_focus, profile.category_focus);
        assert_eq!(merged.depth, profile.depth);
        assert_eq!(merged.min_expand_confidence, profile.min_expand_confidence);
        assert_eq!(merged.max_concurrent, profile.max_concurrent);
        assert_eq!(merged.max_entities, profile.max_entities);
        assert_eq!(merged.max_wall_time_secs, profile.max_wall_time_secs);
        assert_eq!(
            merged.expansion_strategy, profile.expansion_strategy,
            "expansion_strategy must be carried by the overlay"
        );
        assert_eq!(
            merged.regional_search, profile.regional_search,
            "regional_search must be carried by the overlay"
        );
    }
