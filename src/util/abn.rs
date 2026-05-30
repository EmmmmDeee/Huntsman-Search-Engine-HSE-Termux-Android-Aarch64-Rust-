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
/// resolvers, vs an individual. Case-insensitive; leading space anchors each
/// suffix so substrings inside words (e.g. `BUILT`) don't match.
pub fn looks_like_company(name: &str) -> bool {
    // Double-pad so each suffix can be matched as a whitespace-bounded token —
    // otherwise " INC" would falsely fire inside "INCANDESCENT", " LTD" inside
    // "ALTDORF", etc.
    let u = format!(" {} ", name.to_uppercase());
    const SUFFIXES: &[&str] = &[
        " PTY LTD ",
        " PTY. LTD. ",
        " PTY LTD. ",
        " PTY. LTD ",
        " LIMITED ",
        " LTD ",
        " LTD. ",
        " PTY ",
        " PTY. ",
        " INCORPORATED ",
        " INC ",
        " INC. ",
        " NL ",
        " & CO ",
        " AND CO ",
    ];
    SUFFIXES.iter().any(|s| u.contains(s))
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
    }
}
