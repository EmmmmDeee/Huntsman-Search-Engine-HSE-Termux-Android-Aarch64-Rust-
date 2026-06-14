use super::*;

    #[test]
    fn validates_known_abns() {
        // ATO's own ABN (a canonical documented value).
        assert!(is_valid_abn("51824753556"));
        assert!(is_valid_abn("51 824 753 556")); // spaced form
        // Flip the last digit → checksum fails.
        assert!(!is_valid_abn("51824753557"));
        // Wrong length / leading zero / non-digits.
        assert!(!is_valid_abn("5182475355")); // 10 digits
        assert!(!is_valid_abn("01824753556")); // leading 0
        assert!(!is_valid_abn("abc"));
    }

    #[test]
    fn validates_known_acns() {
        // ASIC's worked example, and a second independently-computed valid ACN.
        assert!(is_valid_acn("000000019"));
        assert!(is_valid_acn("004085616"));
        assert!(is_valid_acn("004 085 616")); // spaced form
        // Wrong check digit.
        assert!(!is_valid_acn("000000018"));
        assert!(!is_valid_acn("004085617"));
        // Wrong length.
        assert!(!is_valid_acn("00000001")); // 8 digits
        assert!(!is_valid_acn("0000000190")); // 10 digits
    }

    /// Structural property of a check digit: for **every** 8-digit prefix,
    /// exactly one of the ten possible final digits yields a valid ACN. This
    /// proves the validator is a proper check function — it never accepts two
    /// check digits for one prefix (too permissive) and never rejects the one
    /// correct number (too strict) — without reimplementing the algorithm here.
    #[test]
    fn acn_has_exactly_one_valid_check_digit_per_prefix() {
        // A deterministic spread of prefixes (small LCG; no rand dependency).
        let mut state: u32 = 0x1234_5678;
        for _ in 0..20_000 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let prefix = state % 100_000_000; // 8 digits (leading zeros allowed)
            let prefix_str = format!("{prefix:08}");
            let valid = (0..10)
                .filter(|d| is_valid_acn(&format!("{prefix_str}{d}")))
                .count();
            assert_eq!(
                valid, 1,
                "prefix {prefix_str} accepted {valid} check digits, expected exactly 1"
            );
        }
    }

    /// The defining guarantee of the ABN's mod-89 checksum: it detects *all*
    /// single-digit errors. For a population of valid ABNs, mutating any one
    /// digit to any other value must always invalidate the number. (Holds because
    /// 89 is prime and no `Δdigit × positional-weight` is a multiple of it for
    /// digit deltas in 1..=9.)
    #[test]
    fn abn_rejects_every_single_digit_mutation_of_a_valid_abn() {
        // Collect valid ABNs by deterministic rejection sampling.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut checked = 0usize;
        while checked < 300 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let n = state % 100_000_000_000; // 11 digits
            let s = format!("{n:011}");
            if !is_valid_abn(&s) {
                continue;
            }
            let digits: Vec<u8> = s.bytes().map(|b| b - b'0').collect();
            for pos in 0..11 {
                for nd in 0..10u8 {
                    if nd == digits[pos] {
                        continue;
                    }
                    let mut m = digits.clone();
                    m[pos] = nd;
                    let mutated: String = m.iter().map(|d| (d + b'0') as char).collect();
                    assert!(
                        !is_valid_abn(&mutated),
                        "single-digit mutation {mutated} of valid ABN {s} was accepted"
                    );
                }
            }
            checked += 1;
        }
        assert_eq!(checked, 300, "should have sampled 300 valid ABNs");
    }

    #[test]
    fn company_names_splits_real_joint_syndicates() {
        // Real owner strings from the QLD register (q="Pty Ltd").
        assert_eq!(
            company_names("DEV PTY LTD & GWAD PTY LTD & GWAD2 PTY LTD & GWAD3 PTY LTD"),
            vec![
                "DEV PTY LTD",
                "GWAD PTY LTD",
                "GWAD2 PTY LTD",
                "GWAD3 PTY LTD"
            ]
        );
        // Trailing "- SEE B" batch marker is dropped from the last name.
        assert_eq!(
            company_names("PORTIMAO PTY LTD & KILKIRK PTY LTD & CONWALL PTY LTD - SEE B"),
            vec!["PORTIMAO PTY LTD", "KILKIRK PTY LTD", "CONWALL PTY LTD"]
        );
        // A single "& CO" company is NOT split into two non-companies.
        assert_eq!(company_names("SMITH & CO"), vec!["SMITH & CO"]);
        // Regression: the "& Co" idiom INSIDE a syndicate must stay attached to
        // its name, not be orphaned into a bogus standalone "Co Pty Ltd".
        assert_eq!(
            company_names("ASHTON & CO PTY LTD & BERG PTY LTD"),
            vec!["ASHTON & CO PTY LTD", "BERG PTY LTD"]
        );
        // "Company" spelled out, and a real `&`-joined firm name, both survive.
        assert_eq!(
            company_names("DALE & COMPANY PTY LTD & ROE PTY LTD"),
            vec!["DALE & COMPANY PTY LTD", "ROE PTY LTD"]
        );
        // A non-"Co" word starting with "co" (Coffee) is NOT a continuation.
        assert_eq!(
            company_names("COFFEE PTY LTD & BREW PTY LTD"),
            vec!["COFFEE PTY LTD", "BREW PTY LTD"]
        );
        // A plain single company is returned whole.
        assert_eq!(
            company_names("ACME WIDGETS PTY LTD"),
            vec!["ACME WIDGETS PTY LTD"]
        );
        // Individuals (incl. joint individuals) yield nothing.
        assert!(company_names("KAREEM AYALA").is_empty());
        assert!(company_names("SALIM ATSHAN FAHD & MOHAMMED ABDUL KAREEM").is_empty());
    }

    #[test]
    fn detects_company_forms_not_individuals() {
        assert!(looks_like_company("ACME PTY LTD"));
        assert!(looks_like_company("Widgets Pty. Ltd."));
        assert!(looks_like_company("BHP GROUP LIMITED"));
        assert!(looks_like_company("Acme Holdings Ltd"));
        assert!(looks_like_company("SMITH & CO"));
        // Individuals and joint individuals are not companies.
        assert!(!looks_like_company("JOHN SMITH"));
        assert!(!looks_like_company("HAYLEY AVERY & CURT AVERY"));
        assert!(!looks_like_company("KAREEM AYALA"));
        // No false match inside a word.
        assert!(!looks_like_company("INCANDESCENT BAY"));
        assert!(!looks_like_company("ALTDORF ESTATES"));
    }

    #[test]
    fn company_form_survives_trailing_punctuation() {
        // Regression: a legal-form suffix as the final token followed by
        // punctuation (comma, period, semicolon, paren) previously failed the
        // space-bounded match, misreading a real company as an individual and
        // suppressing the ABN/ACN resolvers. Punctuation now folds to a space.
        for name in [
            "ACME HOLDINGS LIMITED.",
            "WIDGETS LTD;",
            "ACME INC,",
            "Smith Pty. Ltd.",
            "(BHP GROUP LIMITED)",
            "FOO BAR NL.",
        ] {
            assert!(
                looks_like_company(name),
                "{name:?} should look like a company"
            );
        }
        // `& CO` survives — the `&` is preserved, not folded to a space (which
        // would leave a bare " CO " that must NOT match on its own).
        assert!(looks_like_company("SMITH & CO."));
        assert!(!looks_like_company("ACME COMPANY")); // bare "CO..." is not a form
    }
