use super::*;

    #[test]
    fn multipliers_include_infrastructure_services() {
        assert_eq!(classify("shodan"), KeyRoi::Multiplier);
        assert_eq!(classify("censys"), KeyRoi::Multiplier);
        assert_eq!(classify("securitytrails"), KeyRoi::Multiplier);
        assert_eq!(classify("hunter"), KeyRoi::Multiplier);
        assert_eq!(classify("proxycurl"), KeyRoi::Multiplier);
    }

    #[test]
    fn multipliers_include_self_and_competitors() {
        // OathNet self-discovery — finding more OathNet keys scales
        // our own quota.
        assert_eq!(classify("oathnet"), KeyRoi::Multiplier);
        // Competitors — same data surface, parallel quota pools.
        assert_eq!(classify("see_know"), KeyRoi::Multiplier);
        assert_eq!(classify("snusbase"), KeyRoi::Multiplier);
        assert_eq!(classify("leakcheck"), KeyRoi::Multiplier);
        assert_eq!(classify("dehashed"), KeyRoi::Multiplier);
        assert_eq!(classify("hibp"), KeyRoi::Multiplier);
        assert_eq!(classify("intelx"), KeyRoi::Multiplier);
    }

    /// The full breach-with-credentials cohort must classify as Multiplier using
    /// the EMITTED service name (the value the key-harvester writes to
    /// `FoundKey.service`). Regression-guards the `xposed_or_not` typo: that
    /// literal used the underscored HSE module id, which the harvester never
    /// emits, so a discovered XposedOrNot key silently dropped to `Expansion`
    /// instead of the intended `Multiplier`. `hudsonrock` and `xposedornot` were
    /// the two cohort members no earlier test covered.
    #[test]
    fn breach_credential_cohort_are_multipliers_by_emitted_name() {
        for svc in ["hibp", "dehashed", "intelx", "hudsonrock", "xposedornot"] {
            assert_eq!(
                classify(svc),
                KeyRoi::Multiplier,
                "breach-with-credentials service {svc:?} must be a Multiplier"
            );
        }
        // The underscored module id is NOT the harvested service vocabulary and
        // must not be what earns the Multiplier tier (it matched nothing before).
        assert_ne!(
            classify("xposed_or_not"),
            KeyRoi::Multiplier,
            "the HSE module id (underscored) is not a harvested service name"
        );
    }

    #[test]
    fn expansion_includes_non_key_services() {
        assert_eq!(classify("opencorporates"), KeyRoi::Expansion);
        assert_eq!(classify("wigle"), KeyRoi::Expansion);
    }

    #[test]
    fn terminal_includes_scoring_services() {
        assert_eq!(classify("abuseipdb"), KeyRoi::Terminal);
        assert_eq!(classify("greynoise"), KeyRoi::Terminal);
        assert_eq!(classify("ip2location"), KeyRoi::Terminal);
    }

    #[test]
    fn unknown_defaults_to_expansion() {
        assert_eq!(classify("some_unknown_service"), KeyRoi::Expansion);
    }

    #[test]
    fn ord_prioritises_multiplier() {
        assert!(KeyRoi::Multiplier > KeyRoi::Expansion);
        assert!(KeyRoi::Expansion > KeyRoi::Terminal);
    }

    #[test]
    fn label_maps_each_tier_to_its_tag_string() {
        // The `roi:{label}` entity tags downstream consumers match on depend on
        // these exact strings — lock them.
        assert_eq!(KeyRoi::Terminal.label(), "terminal");
        assert_eq!(KeyRoi::Expansion.label(), "expansion");
        assert_eq!(KeyRoi::Multiplier.label(), "multiplier");
    }

    #[test]
    fn label_round_trips_through_classify() {
        assert_eq!(classify("shodan").label(), "multiplier");
        assert_eq!(classify("abuseipdb").label(), "terminal");
        assert_eq!(classify("some_unknown_service").label(), "expansion");
    }
