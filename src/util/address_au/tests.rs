use super::*;

    fn extract_first(text: &str) -> Option<AuAddress> {
        extract_all(text).into_iter().next()
    }

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
    fn state_code_does_not_read_a_leading_us_street_number_as_an_au_postcode() {
        // Real captured US breach-record addresses (Huntsman scan 90b936dc…). A
        // 4-digit US STREET NUMBER must not be mistaken for an AU postcode: the
        // real ZIP is 5 digits and trails, so the final numeric run is rejected and
        // the leading street number is never considered. Each must yield NO AU
        // state — e.g. an Arizona address must not resolve to "SA".
        for addr in [
            "5528 North 73rd Avenue, Glendale, AZ, 85303, US",
            "1019 Winston Dr, Jefferson City, MO, 65101, US",
            "9025 W. 84th St N, Valley Center, KS, 67147, US",
            "3145 Rochambeau Ave, Bronx, NY, 10467, US",
            "3809 Slalom Dr, Billings, MT, 59102, US",
        ] {
            assert_eq!(state_code(addr), None, "no AU state for US address {addr:?}");
        }
        // The trailing-postcode path still works: a genuine AU postcode-only string
        // (no state word, so it reaches step 3) still resolves.
        assert_eq!(state_code("PO Box, 3001"), Some("VIC"));
        assert_eq!(state_code("Beerwah 4519"), Some("QLD"));
    }

    #[test]
    fn single_state_code_only_resolves_unambiguous_states() {
        // A single, unambiguous state → resolved (by code or by full name).
        assert_eq!(single_state_code("Melbourne / VIC"), Some("VIC"));
        assert_eq!(single_state_code("Brisbane / QLD"), Some("QLD"));
        assert_eq!(single_state_code("Hobart / TAS"), Some("TAS"));
        assert_eq!(single_state_code("Sydney, New South Wales"), Some("NSW"));
        // Ambiguous multi-state labels — a coarse phone area code (02, 08) spans
        // several states — must NOT collapse to one fabricated jurisdiction.
        assert_eq!(single_state_code("Sydney / NSW / ACT"), None);
        assert_eq!(single_state_code("Perth / SA / NT"), None);
        // No state signal, and (unlike `state_code`) NO postcode fallback: an
        // explicit state mention is required.
        assert_eq!(single_state_code("just some text"), None);
        assert_eq!(single_state_code("PO Box, 3001"), None);
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

    #[test]
    fn normalise_phone_never_emits_invalid_e164() {
        // Regression: the `+61…` / `0061…` / `1300…` branches used to return
        // their candidate unvalidated, leaking syntactically invalid E.164
        // (too short, or country-code-only) straight into correlation keys.
        // Every branch now routes through the strict E.164 gate.
        for junk in [
            "+61",          // country code only
            "+6100",        // too short + invalid national lead
            "+610",         // leading-zero national part, too short
            "0061",         // → "+61", country code only
            "0061 0",       // → "+610", too short
            "1300",         // → "+611300", 6 digits, below the 10-digit floor
            "1800",         // → "+611800", ditto
        ] {
            assert_eq!(
                normalise_phone(junk),
                None,
                "invalid/too-short input {junk:?} must not yield a malformed E.164"
            );
        }
        // A well-formed international/local number is still accepted unchanged.
        assert_eq!(
            normalise_phone("+61 2 9374 4000").as_deref(),
            Some("+61293744000")
        );
    }

    #[test]
    fn normalise_phone_ten_digit_leading_zero_requires_a_real_au_trunk_digit() {
        // Regression: the 10-digit `0…` branch lacked the trunk-digit gate
        // its 9-digit sibling already enforces, so any 10-digit string
        // starting with `0` was fabricated into a non-existent Australian
        // number. A French local mobile "0612345678" has lead digit `6`,
        // which is not a real AU national-significant-number lead (`8`
        // itself IS a valid AU lead — SA/WA/NT geographic — so a foreign
        // number coincidentally sharing a valid AU lead digit is an
        // inherent, irreducible ambiguity this gate narrows but cannot
        // fully eliminate; rejecting the clearly-wrong leads 0/1/6/9 is the
        // confirmed bug this fixes).
        assert_eq!(normalise_phone("0612345678"), None);
        for lead in ['2', '3', '4', '5', '7', '8'] {
            let local = format!("0{lead}12345678");
            assert!(
                normalise_phone(&local).is_some(),
                "a real AU trunk digit {lead} must still normalise: {local}"
            );
        }
        for lead in ['0', '1', '6', '9'] {
            let local = format!("0{lead}12345678");
            assert_eq!(
                normalise_phone(&local),
                None,
                "lead digit {lead} is not a real AU trunk code: {local}"
            );
        }
    }

    #[test]
    fn normalise_phone_nine_digit_nsn_matches_the_ten_digit_trunk_lead_set() {
        // The 9-digit national-significant-number branch must accept exactly the
        // ACMA lead set the 10-digit `0…` branch documents — {2,3,4,5,7,8}. It
        // previously omitted `5` (location-independent / VoIP `05x` numbers), so a
        // VoIP number's bare 9-digit NSN form was rejected while its equivalent
        // 10-digit `05…` form was accepted: the two spellings of one number
        // disagreed, and the 10-digit branch's comment falsely claimed parity.
        for lead in ['2', '3', '4', '5', '7', '8'] {
            let nsn = format!("{lead}12345678"); // lead + 8 digits = 9 total
            let with_zero = format!("0{nsn}"); // = 10 digits
            assert_eq!(
                normalise_phone(&nsn).as_deref(),
                Some(format!("+61{nsn}").as_str()),
                "9-digit NSN with real AU lead {lead} must normalise: {nsn}"
            );
            // Both spellings of the same number must produce the same E.164.
            assert_eq!(
                normalise_phone(&nsn),
                normalise_phone(&with_zero),
                "9-digit and 10-digit forms of one number must agree: {nsn}"
            );
        }
        // Non-lead digits are still rejected by the 9-digit branch.
        for lead in ['0', '1', '6', '9'] {
            assert_eq!(
                normalise_phone(&format!("{lead}12345678")),
                None,
                "lead digit {lead} is not a real AU trunk code"
            );
        }
    }

    #[test]
    fn au_phone_region_maps_geographic_area_codes() {
        // The four geographic area codes → region + member states.
        assert_eq!(
            au_phone_region("+61 2 9876 5432"),
            Some(("central-east", "Central East", &["NSW", "ACT"][..]))
        );
        assert_eq!(
            au_phone_region("(03) 9876 5432"),
            Some(("south-east", "South East", &["VIC", "TAS"][..]))
        );
        assert_eq!(
            au_phone_region("0730001234"),
            Some(("north-east", "North East", &["QLD"][..]))
        );
        assert_eq!(
            au_phone_region("+61881234567"),
            Some(("central-west", "Central and West", &["SA", "WA", "NT"][..]))
        );
    }

    #[test]
    fn au_phone_region_is_none_for_non_geographic_and_non_au() {
        assert!(au_phone_region("0412 345 678").is_none()); // mobile
        assert!(au_phone_region("1800 123 456").is_none()); // freephone
        assert!(au_phone_region("1300 846 637").is_none()); // local-rate
        assert!(au_phone_region("+1 555 123 4567").is_none()); // US
        assert!(au_phone_region("not a phone").is_none());
    }

    #[test]
    fn au_phone_line_type_classifies_every_au_number_class() {
        // Mobile, geographic, VoIP, and the three service classes.
        assert_eq!(
            au_phone_line_type("0412 345 678").unwrap().0,
            AuLineType::Mobile
        );
        assert_eq!(
            au_phone_line_type("(07) 3739 4511").unwrap().0,
            AuLineType::GeographicFixed
        );
        assert_eq!(
            au_phone_line_type("+61 2 9876 5432").unwrap().0,
            AuLineType::GeographicFixed
        );
        assert_eq!(
            au_phone_line_type("0512 345 678").unwrap().0,
            AuLineType::Voip
        );
        assert_eq!(
            au_phone_line_type("1800 123 456").unwrap().0,
            AuLineType::Freephone
        );
        assert_eq!(
            au_phone_line_type("1300 975 707").unwrap().0,
            AuLineType::LocalRate
        );
        // The 6-digit `13xxxx` short form the normaliser doesn't tabulate.
        assert_eq!(
            au_phone_line_type("13 11 14").unwrap().0,
            AuLineType::LocalRate
        );
        assert_eq!(
            au_phone_line_type("1902 123 456").unwrap().0,
            AuLineType::Premium
        );
        // Not Australian / not a phone.
        assert!(au_phone_line_type("+1 555 123 4567").is_none());
        assert!(au_phone_line_type("not a phone").is_none());
    }

    #[test]
    fn au_line_type_predicates_split_personal_from_business() {
        assert!(!AuLineType::Mobile.is_business_service());
        assert!(AuLineType::Freephone.is_business_service());
        assert!(AuLineType::LocalRate.is_business_service());
        assert!(AuLineType::Premium.is_business_service());
        // Slugs are stable.
        assert_eq!(AuLineType::Mobile.slug(), "mobile");
        assert_eq!(AuLineType::GeographicFixed.slug(), "geographic");
    }

    #[test]
    fn au_gov_domain_state_maps_state_subdomains() {
        assert_eq!(au_gov_domain_state("health.nsw.gov.au"), Some("NSW"));
        assert_eq!(au_gov_domain_state("transport.nsw.gov.au"), Some("NSW"));
        assert_eq!(au_gov_domain_state("TRANSPORT.VIC.GOV.AU"), Some("VIC"));
        assert_eq!(
            au_gov_domain_state("schools.education.qld.gov.au"),
            Some("QLD")
        );
        assert_eq!(au_gov_domain_state("police.nt.gov.au"), Some("NT"));
        assert_eq!(au_gov_domain_state("sa.gov.au"), Some("SA")); // bare state apex
    }

    #[test]
    fn au_gov_domain_state_is_none_for_federal_and_non_gov() {
        assert_eq!(au_gov_domain_state("ato.gov.au"), None); // federal, no state
        assert_eq!(au_gov_domain_state("my.gov.au"), None); // federal
        assert_eq!(au_gov_domain_state("acme.com.au"), None); // not gov
        assert_eq!(au_gov_domain_state("nsw.example.com"), None); // not gov.au
        assert_eq!(au_gov_domain_state(""), None);
    }

    #[test]
    fn au_edu_domain_state_maps_state_school_systems() {
        assert_eq!(au_edu_domain_state("schools.nsw.edu.au"), Some("NSW"));
        assert_eq!(au_edu_domain_state("DET.NSW.EDU.AU"), Some("NSW"));
        assert_eq!(au_edu_domain_state("sa.edu.au"), Some("SA"));
        assert_eq!(au_edu_domain_state("decd.tas.edu.au"), Some("TAS"));
        // Education Queensland's `eq.edu.au` carries no state label.
        assert_eq!(au_edu_domain_state("eq.edu.au"), Some("QLD"));
        assert_eq!(au_edu_domain_state("myschool.eq.edu.au"), Some("QLD"));
    }

    #[test]
    fn au_edu_domain_state_is_none_for_universities_and_non_edu() {
        // Universities are institution-named (no state code) → resolved to their
        // city elsewhere, not a state here.
        assert_eq!(au_edu_domain_state("uq.edu.au"), None);
        assert_eq!(au_edu_domain_state("anu.edu.au"), None);
        assert_eq!(au_edu_domain_state("unimelb.edu.au"), None);
        assert_eq!(au_edu_domain_state("monash.edu"), None); // not .edu.au
        assert_eq!(au_edu_domain_state("acme.com.au"), None); // not edu
    }

    #[test]
    fn au_domain_registrant_classifies_each_2ld() {
        let cat = |d| au_domain_registrant(d).map(|c| c.0);
        assert_eq!(cat("john.id.au"), Some("individual"));
        assert_eq!(cat("acme.com.au"), Some("commercial"));
        assert_eq!(cat("mail.acme.net.au"), Some("commercial")); // sub-labels irrelevant
        assert_eq!(cat("foundation.org.au"), Some("non-profit"));
        assert_eq!(cat("club.asn.au"), Some("association"));
        assert_eq!(cat("ato.gov.au"), Some("government"));
        assert_eq!(cat("uq.edu.au"), Some("education"));
        // Case-insensitive and trailing-dot tolerant.
        assert_eq!(cat("JANE.ID.AU"), Some("individual"));
        assert_eq!(cat("acme.com.au."), Some("commercial"));
        // Each carries a human label distinct from the bare tag.
        assert!(au_domain_registrant("john.id.au").unwrap().1.contains("natural-person"));
    }

    #[test]
    fn au_domain_registrant_is_none_for_non_au_and_direct_rego() {
        assert_eq!(au_domain_registrant("example.com"), None);
        assert_eq!(au_domain_registrant("example.co.uk"), None);
        assert_eq!(au_domain_registrant("direct.au"), None); // direct .au, no 2LD category
        assert_eq!(au_domain_registrant(""), None);
        // `.au` must be a real suffix, not a substring of another label.
        assert_eq!(au_domain_registrant("acme.com.audata.io"), None);
    }

    #[test]
    fn au_network_operator_recognises_isps_and_rejects_noise() {
        assert_eq!(
            au_network_operator("AS1221 Telstra Corporation"),
            Some(("Telstra", AuNetworkKind::Consumer))
        );
        assert_eq!(
            au_network_operator("aussie broadband pty ltd"),
            Some(("Aussie Broadband", AuNetworkKind::Consumer))
        );
        assert_eq!(
            au_network_operator("AARNET"),
            Some(("AARNet", AuNetworkKind::Academic))
        );
        // Foreign / unrelated providers must not match.
        assert_eq!(au_network_operator("Google LLC"), None);
        assert_eq!(au_network_operator("Amazon Data Services"), None);
        // Short brand must be whole-word, not a substring.
        assert_eq!(au_network_operator("ACMETPGENETICS LIMITED"), None);
    }
