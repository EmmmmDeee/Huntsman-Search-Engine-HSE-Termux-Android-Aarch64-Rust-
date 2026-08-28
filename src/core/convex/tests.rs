use super::*;

    #[test]
    fn dispatch_cost_prices_infrastructure_above_identity() {
        assert_eq!(dispatch_cost(TargetKind::Email), 1.0);
        assert_eq!(dispatch_cost(TargetKind::Username), 1.0);
        assert!(dispatch_cost(TargetKind::Domain) > dispatch_cost(TargetKind::Email));
        assert!(dispatch_cost(TargetKind::Asn) > dispatch_cost(TargetKind::Domain));
        // Every kind costs at least "free".
        for k in [
            TargetKind::Email,
            TargetKind::Domain,
            TargetKind::Asn,
            TargetKind::IpAddress,
            TargetKind::Coordinates,
            TargetKind::Url,
        ] {
            assert!(dispatch_cost(k) >= 1.0);
        }
    }

    #[test]
    fn upside_tail_is_high_for_rich_uncertain_unexplored_and_low_otherwise() {
        // Rich, uncertain, single-source → high optionality.
        let hi = upside_tail(1, 0.30, 1.0);
        // Same richness but already confident → low.
        let confident = upside_tail(1, 0.95, 1.0);
        // Same richness/uncertainty but heavily corroborated → damped.
        let explored = upside_tail(8, 0.30, 1.0);
        // Low richness → low regardless.
        let thin = upside_tail(1, 0.30, 0.05);
        assert!(hi > confident, "{hi} !> {confident}");
        assert!(hi > explored, "{hi} !> {explored}");
        assert!(hi > thin, "{hi} !> {thin}");
        // Bounded to [0,1].
        for t in [hi, confident, explored, thin] {
            assert!((0.0..=1.0).contains(&t), "tail {t} out of range");
        }
    }

    #[test]
    fn multiplier_lifts_cheap_rich_leads_and_damps_saturated_infrastructure() {
        // A rich, unconfirmed, single-source Email — the barbell's left end.
        let identity = optionality_multiplier(TargetKind::Email, 1, 0.30, 1.0);
        // A confirmed, saturated mega-domain — the expensive, explored end.
        let infra = optionality_multiplier(TargetKind::Domain, 6, 0.95, 0.4);
        assert!(identity > 1.0, "cheap rich identity lifted: {identity}");
        assert!(infra < 1.0, "saturated infra damped: {infra}");
        assert!(
            identity > infra * 2.0,
            "identity must clearly outrank infra"
        );
    }

    #[test]
    fn confident_cheap_core_stays_neutral() {
        // A fully-explored, confident identity lead: premium ≈ 1, cost = 1, so the
        // multiplier is ≈ 1 — the confident core keeps its existing ranking and
        // only the uncertain tail / expensive infra is re-sorted.
        let m = optionality_multiplier(TargetKind::Email, 5, 0.97, 0.6);
        assert!(
            (m - 1.0).abs() < 0.15,
            "near-neutral for the confident core: {m}"
        );
    }

    // ── Query-level convexity (module dispatch ordering) ─────────────────────

    #[test]
    fn module_dispatch_cost_orders_passive_below_free_below_keyed_below_paid() {
        let passive = module_dispatch_cost(ModuleCost::Free, true);
        let free = module_dispatch_cost(ModuleCost::Free, false);
        let keyed = module_dispatch_cost(ModuleCost::KeyGated, false);
        let paid = module_dispatch_cost(ModuleCost::Paid, false);
        assert!(passive < free, "passive local read is cheapest: {passive}");
        assert!(free < keyed, "keyless < key-gated: {free} !< {keyed}");
        assert!(keyed < paid, "key-gated < paid: {keyed} !< {paid}");
    }

    #[test]
    fn entity_cascade_ranks_identity_and_keys_above_terminal_geo() {
        // Identity/credential outputs open the most new query surface; a coordinate
        // is terminal.
        assert!(entity_cascade(&EntityKind::Email) > entity_cascade(&EntityKind::Domain));
        assert!(entity_cascade(&EntityKind::ApiKey) > entity_cascade(&EntityKind::IpAddress));
        assert!(
            entity_cascade(&EntityKind::Username) > entity_cascade(&EntityKind::Coordinates),
            "identity outranks terminal geo"
        );
        // Every weight stays in range.
        for k in [
            EntityKind::Person,
            EntityKind::ApiKey,
            EntityKind::IpAddress,
            EntityKind::Coordinates,
            EntityKind::Other("x".into()),
        ] {
            let w = entity_cascade(&k);
            assert!((0.0..=1.0).contains(&w), "cascade {w} out of range for {k}");
        }
    }

    #[test]
    fn module_cascade_takes_the_max_of_outputs_and_category() {
        // A module that emits even one high-optionality kind earns the premium,
        // regardless of how terminal its other outputs (or category) are.
        let mixed = module_cascade(
            &[EntityKind::Coordinates, EntityKind::Email],
            ModuleCategory::Geo,
        );
        assert!(mixed >= entity_cascade(&EntityKind::Email) - 1e-12);
        // With NO declared outputs the category proxy carries the estimate, so a
        // breach-category module still ranks as a high-cascade query.
        let undeclared_breach = module_cascade(&[], ModuleCategory::Breach);
        assert!(
            undeclared_breach > 0.9,
            "breach category floor applies when outputs undeclared: {undeclared_breach}"
        );
        let undeclared_geo = module_cascade(&[], ModuleCategory::Geo);
        assert!(undeclared_breach > undeclared_geo);
    }

    #[test]
    fn query_value_puts_cheap_cascading_queries_first_and_paid_terminal_last() {
        // The barbell's left end: a keyless breach/identity module that unlocks
        // credentials → more queries.
        let cheap_multiplier = query_value(
            ModuleCost::Free,
            false,
            module_cascade(&[EntityKind::Email, EntityKind::ApiKey], ModuleCategory::Breach),
        );
        // The right end: a paid, terminal scoring provider (an abuse score).
        let paid_terminal = query_value(
            ModuleCost::Paid,
            false,
            module_cascade(&[EntityKind::Other("score".into())], ModuleCategory::Threat),
        );
        assert!(
            cheap_multiplier > 1.0,
            "cheap cascading query lifted above neutral: {cheap_multiplier}"
        );
        assert!(
            paid_terminal < 1.0,
            "paid terminal query damped below neutral: {paid_terminal}"
        );
        assert!(
            cheap_multiplier > paid_terminal * 2.0,
            "cheap cascade must clearly outrank paid-terminal: {cheap_multiplier} vs {paid_terminal}"
        );
    }

    #[test]
    fn query_value_is_deterministic_and_finite() {
        // Same inputs → identical output (precomputed order must be reproducible).
        for cost in [ModuleCost::Free, ModuleCost::KeyGated, ModuleCost::Paid] {
            for passive in [false, true] {
                for cascade in [0.0, 0.3, 0.7, 1.0] {
                    let a = query_value(cost, passive, cascade);
                    let b = query_value(cost, passive, cascade);
                    assert_eq!(a.to_bits(), b.to_bits(), "non-deterministic query_value");
                    assert!(a.is_finite() && a > 0.0, "query_value must be finite +ve");
                }
            }
        }
    }
