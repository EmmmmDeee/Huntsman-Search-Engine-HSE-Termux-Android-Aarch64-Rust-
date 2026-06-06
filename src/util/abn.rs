//! Australian Business Number (ABN) and Company Number (ACN) validation +
//! company-form detection. Pure, dependency-free, no I/O.
//!
//! Both identifiers carry a deterministic check-digit, so a candidate string can
//! be rejected *algorithmically* rather than trusted on surrounding text alone —
//! which slashes false positives when harvesting 9/11-digit numbers from web
//! text, breach dumps or registry fields. Shared so every module validates ABNs
//! and ACNs identically.

/// Validate an 11-digit ABN by its ATO modulus-89 weighted checksum.
///
/// Algorithm (ATO): subtract 1 from the first digit, multiply each digit by its
/// positional weight `[10,1,3,5,7,9,11,13,15,17,19]`, sum, and require the total
/// to be divisible by 89. Non-digits are ignored so spaced forms
/// (`"51 824 753 556"`) validate.
pub fn is_valid_abn(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 11 {
        return false;
    }
    // ABNs never begin with 0 (the leading pair is a checksum in 10..=99).
    if digits[0] == 0 {
        return false;
    }
    let weights = [10u32, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
    let mut sum = 0u32;
    for (i, &w) in weights.iter().enumerate() {
        let d = if i == 0 { digits[i] - 1 } else { digits[i] };
        sum += d * w;
    }
    sum.is_multiple_of(89)
}

/// Validate a 9-digit ACN by its ASIC check-digit.
///
/// Algorithm (ASIC): weight the first 8 digits by `[8,7,6,5,4,3,2,1]`, sum, take
/// `complement = (10 - (sum % 10)) % 10`, and require it to equal the 9th
/// (check) digit. Non-digits are ignored so `"004 085 616"` validates.
pub fn is_valid_acn(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 9 {
        return false;
    }
    let weights = [8u32, 7, 6, 5, 4, 3, 2, 1];
    let sum: u32 = weights.iter().zip(&digits[..8]).map(|(w, d)| w * d).sum();
    let complement = (10 - (sum % 10)) % 10;
    digits[8] == complement
}

/// Heuristic: does `name` carry an Australian corporate legal-form suffix
/// (`PTY LTD`, `LIMITED`, `LTD`, `PTY`, `INC`, `NL`, `& CO`)? Used to decide
/// whether a register owner is a company worth pivoting to the ABN/ACN
/// resolvers, vs an individual. Case-insensitive and punctuation-insensitive.
pub fn looks_like_company(name: &str) -> bool {
    // Normalise so a legal-form suffix is recognised regardless of surrounding
    // punctuation: uppercase, reduce every char that is not alphanumeric or `&`
    // (the only punctuation that is itself part of a form — "& CO") to a space,
    // and collapse runs of whitespace. This folds "Pty. Ltd.", "LTD,",
    // "LIMITED.", "Inc)" onto the canonical space-delimited tokens below —
    // previously a trailing comma/period/paren on the final token defeated the
    // match and a real company was misread as an individual.
    let folded: String = name
        .to_uppercase()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '&' {
                c
            } else {
                ' '
            }
        })
        .collect();
    // Double-pad the collapsed token stream so each suffix matches only as a
    // whitespace-bounded token — otherwise " INC" would falsely fire inside
    // "INCANDESCENT", " LTD" inside "ALTDORF".
    let u = format!(
        " {} ",
        folded.split_whitespace().collect::<Vec<_>>().join(" ")
    );
    const SUFFIXES: &[&str] = &[
        " PTY LTD ",
        " LIMITED ",
        " LTD ",
        " PTY ",
        " INCORPORATED ",
        " INC ",
        " NL ",
        " & CO ",
        " AND CO ",
    ];
    SUFFIXES.iter().any(|s| u.contains(s))
}

/// Split a register owner string into individually ABN-resolvable company
/// names. Owners are frequently joint syndicates
/// (`"DEV PTY LTD & GWAD PTY LTD & ..."`) where each company has its own ABN, so
/// we split on `&`/`and`, drop a trailing `- SEE …` batch cross-reference, and —
/// crucially — only treat it as a syndicate when **two or more** parts carry a
/// corporate legal form. That keeps single names like `"SMITH & CO"` intact
/// (one company, not two individuals "SMITH" and "CO"). Returns deduped names,
/// capped at 5 so a large trust can't flood the graph. Empty for individuals.
pub fn company_names(owner: &str) -> Vec<String> {
    let normalised = owner.replace(" AND ", " & ").replace(" and ", " & ");
    let parts: Vec<String> = normalised
        .split('&')
        .map(|p| match p.find("- SEE") {
            Some(i) => p[..i].trim().to_string(),
            None => p.trim().to_string(),
        })
        .filter(|p| p.len() >= 4 && looks_like_company(p))
        .collect();

    if parts.len() >= 2 {
        // Joint syndicate: each company is its own ABN target.
        let mut out: Vec<String> = Vec::new();
        for c in parts {
            if !out.contains(&c) {
                out.push(c);
                if out.len() >= 5 {
                    break;
                }
            }
        }
        out
    } else if looks_like_company(owner) {
        // A single company (possibly "X & CO") — keep the whole name.
        vec![owner.trim().to_string()]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
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
        assert!(!looks_like_company("HAYLEY DIEGMANN & CURT DIEGMANN"));
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
}
