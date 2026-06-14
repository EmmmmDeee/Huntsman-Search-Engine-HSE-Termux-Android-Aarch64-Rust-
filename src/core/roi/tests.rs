use super::*;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    fn make(conf: f64, corrob: u32) -> Entity {
        let mut e = Entity::new(EntityKind::Email, "x@y.com", conf, "scan");
        e.corroboration = corrob;
        e
    }

    #[test]
    fn saturation_requires_both_corroboration_and_confidence() {
        // High conf but a SINGLE source → below the 2-source floor → not saturated.
        assert!(!is_saturated(&make(0.95, 1)));
        // Moderate conf with only 2 sources → c_eff still < 0.85 → not saturated.
        assert!(!is_saturated(&make(0.50, 2)));
        // Both gates cleared → saturated.
        assert!(is_saturated(&make(0.90, 3)));
        // Upgraded confidence model: enough INDEPENDENT sources lift even a
        // moderate finding past the threshold — strong cross-source agreement IS
        // high effective confidence (5 sources at C=0.50 → c_eff ≈ 0.91), so it
        // saturates and is (correctly) pruned from re-expansion under max_roi.
        assert!(is_saturated(&make(0.50, 5)));
    }

    #[test]
    fn single_source_high_magnitude_is_not_saturated() {
        // 8 observations but all from ONE source (e.g. one hibp hit listing 8
        // breaches): source_count()==1 < 2, so it stays expandable even though
        // the summed corroboration magnitude is high. The pre-fix code read
        // `corroboration` and would have wrongly pruned this pivot under --max-roi.
        let mut e = Entity::new(EntityKind::Email, "x@y.com", 0.95, "scan");
        e.corroboration = 8;
        e.add_evidence(Evidence::new("hibp", "8 breaches"));
        assert_eq!(e.source_count(), 1);
        assert!(!is_saturated(&e), "one distinct source must not saturate");
        // A second DISTINCT source at the same confidence does saturate.
        e.add_evidence(Evidence::new("dehashed", "also seen"));
        assert_eq!(e.source_count(), 2);
        assert!(is_saturated(&e));
    }

    #[test]
    fn top_k_scales_with_concurrency() {
        assert_eq!(top_k_for_round(0), 10); // 2*1+8
        assert_eq!(top_k_for_round(4), 16);
        assert_eq!(top_k_for_round(16), 40);
    }

    #[test]
    fn effective_cutoff_drops_long_tail_below_the_knee() {
        // Leader 50; tail of 5.0 (10%, kept) and 2.0 (4%, < 5% knee → dropped).
        // facebook.com-class noise (weight ~5 vs a ~50 geo lead) sits right at
        // the boundary; the sub-knee 2.0 entries are cut despite fitting top-K.
        let w = [50.0, 40.0, 10.0, 5.0, 2.0, 2.0, 1.0, 0.5];
        // knee keeps weights >= 2.5: 50,40,10,5 → 4 candidates.
        assert_eq!(effective_cutoff(&w, 4), 4);
    }

    #[test]
    fn effective_cutoff_keeps_a_flat_round_up_to_top_k() {
        // All candidates within the knee of the leader → quality gate is inert,
        // top-K is the only bound. 20 equal weights, top_k(4)=16.
        let w = vec![1.0_f64; 20];
        assert_eq!(effective_cutoff(&w, 4), 16);
        // Fewer than top-K and all flat → keep them all.
        let w2 = vec![1.0_f64; 5];
        assert_eq!(effective_cutoff(&w2, 4), 5);
    }

    #[test]
    fn effective_cutoff_is_bounded_and_never_starves() {
        // Empty → 0.
        assert_eq!(effective_cutoff(&[], 4), 0);
        // Single candidate → always keep the leader.
        assert_eq!(effective_cutoff(&[42.0], 4), 1);
        // A lone leader towering over sub-knee noise still keeps >= 1.
        assert_eq!(effective_cutoff(&[100.0, 0.1, 0.1], 4), 1);
        // Degenerate all-zero round: no quality signal, fall back to top-K.
        let z = vec![0.0_f64; 30];
        assert_eq!(effective_cutoff(&z, 4), top_k_for_round(4));
        // Never exceeds top-K.
        let many = vec![10.0_f64; 100];
        assert!(effective_cutoff(&many, 8) <= top_k_for_round(8));
    }

    #[test]
    fn marginal_yield_handles_zero_dispatches() {
        assert_eq!(marginal_yield(0, 0), f64::INFINITY);
        assert_eq!(marginal_yield(10, 5), 2.0);
        assert_eq!(marginal_yield(1, 4), 0.25);
    }

    #[test]
    fn adaptive_termination_only_fires_when_enabled_and_below_floor() {
        // Disabled → never terminates
        assert!(!should_terminate_adaptive(false, 0, 100, 1.0));
        // Enabled, no prior dispatches → no termination (insufficient data)
        assert!(!should_terminate_adaptive(true, 0, 0, 1.0));
        // Enabled, yield above floor → continue
        assert!(!should_terminate_adaptive(true, 10, 5, 1.0));
        // Enabled, yield below floor → terminate
        assert!(should_terminate_adaptive(true, 1, 10, 1.0));
    }
