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
