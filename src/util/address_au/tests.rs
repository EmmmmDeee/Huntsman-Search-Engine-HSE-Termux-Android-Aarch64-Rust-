use super::*;

    #[test]
    fn parses_level_address() {
        let s = "Our office is at Level 11, 133 Mary Street, Brisbane City QLD 4000";
        let a = extract_first(s).expect("should match");
        assert_eq!(a.level.as_deref(), Some("Level 11"));
        assert_eq!(a.street_number, "133");
        assert_eq!(a.street, "Mary Street");
        assert_eq!(a.suburb, "Brisbane City");
        assert_eq!(a.state, "QLD");
        assert_eq!(a.postcode, "4000");
        assert!(a.confidence() >= 0.80);
    }

    #[test]
    fn parses_plain_address() {
        let s = "Visit us at 1 Haengabell Close, Bracken Ridge, QLD 4017 for inspection.";
        let a = extract_first(s).expect("should match");
        assert_eq!(a.street_number, "1");
        assert!(a.street.contains("Haengabell"));
        assert_eq!(a.state, "QLD");
        assert_eq!(a.postcode, "4017");
    }

    #[test]
    fn rejects_wrong_state_postcode() {
        // NSW with VIC postcode → invalid
        let s = "5 Test Street, Sydney NSW 3000";
        assert!(extract_first(s).is_none());
    }

    #[test]
    fn accepts_valid_nsw_postcode_range() {
        // Positive coverage for the NSW arm (1000–2999, one contiguous span):
        // a geographic 2xxx and an LVR 1xxx both accept; 3000 (VIC) rejects.
        let geo = extract_first("1 George Street, Sydney NSW 2000").expect("2000 is NSW");
        assert_eq!(geo.state, "NSW");
        assert_eq!(geo.postcode, "2000");
        assert!(extract_first("1 George Street, Sydney NSW 1234").is_some()); // LVR range
        assert!(extract_first("1 George Street, Sydney NSW 3000").is_none()); // VIC range
    }

    #[test]
    fn state_for_postcode_maps_ranges_and_prefers_act_inside_nsw() {
        assert_eq!(state_for_postcode("4000"), Some("QLD"));
        assert_eq!(state_for_postcode("3000"), Some("VIC"));
        assert_eq!(state_for_postcode("2000"), Some("NSW"));
        // 2600 falls inside the NSW span but is an ACT range — ACT wins.
        assert_eq!(state_for_postcode("2600"), Some("ACT"));
        assert_eq!(state_for_postcode("0800"), Some("NT"));
        assert_eq!(state_for_postcode("9000"), Some("QLD")); // QLD PO-box range
        assert_eq!(state_for_postcode("0100"), None); // 100 → no assigned range
    }

    #[test]
    fn state_code_resolves_abbrev_fullname_and_postcode() {
        // Abbreviation, whole-token.
        assert_eq!(state_code("Brisbane City QLD 4000"), Some("QLD"));
        // Full name.
        assert_eq!(
            state_code("Brisbane City, Queensland, Australia"),
            Some("QLD")
        );
        assert_eq!(state_code("Sydney, New South Wales"), Some("NSW"));
        // Postcode-only fallback.
        assert_eq!(state_code("PO Box, 3001"), Some("VIC"));
        // No state signal.
        assert_eq!(state_code("just some text"), None);
        // Whole-word discipline: a suburb containing "wa"/"sa" must not match.
        assert_eq!(state_code("Wagga Wagga"), None);
        assert_eq!(state_code("Sandgate"), None);
    }

    #[test]
    fn locality_key_folds_postcode_variants_but_keeps_streets_distinct() {
        // Same suburb, two granularities → one key.
        assert_eq!(
            locality_key("Murrumbateman, NSW"),
            locality_key("Murrumbateman, NSW 2582")
        );
        // Case / punctuation insensitive.
        assert_eq!(
            locality_key("murrumbateman nsw"),
            locality_key("Murrumbateman, NSW")
        );
        // US 5-digit ZIP folds too.
        assert_eq!(
            locality_key("Springfield, Illinois"),
            locality_key("Springfield, Illinois 62704")
        );
        // Leading street number preserved → distinct street addresses stay distinct.
        assert_ne!(
            locality_key("12 Main St, Brisbane QLD"),
            locality_key("99 Main St, Brisbane QLD")
        );
        // A street address is NOT folded into the bare suburb.
        assert_ne!(
            locality_key("Brisbane QLD"),
            locality_key("12 Main St, Brisbane QLD")
        );
        // State abbreviation ↔ full name fold to one key (a live name-scan
        // surfaced "Kuraby, QLD" and "Kuraby, Queensland" as two entities).
        assert_eq!(
            locality_key("Kuraby, QLD"),
            locality_key("Kuraby, Queensland")
        );
        // Whole-token only: the `wa` inside "wales" must NOT expand (regression
        // guard for the naive substring-replace trap).
        assert_eq!(locality_key("Newcastle, NSW"), "newcastle new south wales");
        // Distinct states stay distinct (a mis-paired "Brisbane, VIC" is not
        // merged into the real "Brisbane, QLD").
        assert_ne!(locality_key("Brisbane VIC"), locality_key("Brisbane QLD"));
    }

    #[test]
    fn normalises_phone_e164() {
        assert_eq!(
            normalise_phone("0410 959 140").as_deref(),
            Some("+61410959140")
        );
        assert_eq!(
            normalise_phone("(07) 3739 4511").as_deref(),
            Some("+61737394511")
        );
        assert_eq!(
            normalise_phone("+61 7 3739 4511").as_deref(),
            Some("+61737394511")
        );
        assert_eq!(
            normalise_phone("1300 846 637").as_deref(),
            Some("+611300846637")
        );
    }
