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
