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
