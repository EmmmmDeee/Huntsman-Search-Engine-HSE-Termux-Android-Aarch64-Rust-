//! Australian Bank-State-Branch (BSB) number → financial institution.
//! Pure, dependency-free, no I/O.
//!
//! A BSB is the 6-digit `BBB-BBB` code that prefixes every Australian bank
//! account; its leading digits identify the account-holding institution under
//! the AusPayNet BSB allocation. Resolving it turns a bare BSB found in a
//! breach/stealer record (or any `bsb`/`bank_state_branch` field) into a named
//! bank — a people-centric financial-attribution signal that applies to the
//! overwhelming majority of Australian adults (almost everyone holds a bank
//! account).
//!
//! Accuracy over coverage: the table carries only institution prefixes that are
//! stable and well-established (the big four plus the major second-tier banks),
//! matched longest-prefix-first, and returns `None` for anything else rather
//! than guess — so a resolved BSB names the right bank, and an unrecognised one
//! simply yields no (potentially wrong) attribution.

/// Reduce a candidate BSB to its canonical 6-digit form, or `None` if it is not
/// a 6-digit Bank-State-Branch code. Separators (`-`, space) are ignored, so the
/// dotted `062-000` and bare `062000` forms both normalise to `"062000"`.
///
/// ```
/// use huntsman_search_engine::util::bsb::normalise_bsb;
///
/// assert_eq!(normalise_bsb("062-000").as_deref(), Some("062000"));
/// assert_eq!(normalise_bsb("062 000").as_deref(), Some("062000"));
/// assert_eq!(normalise_bsb("06200").as_deref(), None);   // only 5 digits
/// assert_eq!(normalise_bsb("not a bsb"), None);
/// ```
#[must_use]
pub fn normalise_bsb(raw: &str) -> Option<String> {
    let digits: String = raw.chars().filter(char::is_ascii_digit).collect();
    (digits.len() == 6).then_some(digits)
}

/// True if `raw` is a well-formed 6-digit BSB. A convenience predicate over
/// [`normalise_bsb`] for callers that only need to recognise the shape.
#[must_use]
pub fn is_bsb_shaped(raw: &str) -> bool {
    normalise_bsb(raw).is_some()
}

/// Institution prefixes, matched **longest-first** so a 3-digit entry overrides
/// the 2-digit block it sits inside. Only stable, well-established allocations
/// are listed — accuracy over coverage.
const INSTITUTIONS: &[(&str, &str)] = &[
    // ── 3-digit (second-tier banks; override the 2-digit block) ──────────────
    ("182", "Macquarie Bank"),
    ("183", "Macquarie Bank"),
    ("193", "Bank of Melbourne"),
    ("105", "BankSA"),
    ("484", "Suncorp Bank"),
    ("923", "ING"),
    // ── 2-digit (institution-wide blocks) ────────────────────────────────────
    ("01", "ANZ"),
    ("03", "Westpac"),
    ("06", "Commonwealth Bank"),
    ("08", "NAB"),
    ("11", "St George Bank"),
    ("30", "Bankwest"),
    ("63", "Bendigo Bank"),
];

/// The Australian financial institution a BSB belongs to, by its AusPayNet
/// allocation prefix, or `None` for an unrecognised / malformed BSB. The match is
/// longest-prefix-first over a curated, high-confidence table (the big four plus
/// the major second-tier banks), so a returned name is reliable and an
/// unrecognised BSB yields no attribution rather than a guess. Pure; no I/O.
///
/// ```
/// use huntsman_search_engine::util::bsb::bsb_institution;
///
/// assert_eq!(bsb_institution("062-000"), Some("Commonwealth Bank"));
/// assert_eq!(bsb_institution("012-003"), Some("ANZ"));
/// assert_eq!(bsb_institution("182-512"), Some("Macquarie Bank")); // 3-digit wins over 18→…
/// assert_eq!(bsb_institution("999-999"), None);                   // unallocated → no guess
/// ```
#[must_use]
pub fn bsb_institution(bsb: &str) -> Option<&'static str> {
    let canon = normalise_bsb(bsb)?;
    INSTITUTIONS
        .iter()
        .find(|(prefix, _)| canon.starts_with(prefix))
        .map(|&(_, name)| name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_accepts_six_digits_with_or_without_separators() {
        assert_eq!(normalise_bsb("062-000").as_deref(), Some("062000"));
        assert_eq!(normalise_bsb("062 000").as_deref(), Some("062000"));
        assert_eq!(normalise_bsb("062000").as_deref(), Some("062000"));
    }

    #[test]
    fn normalise_rejects_wrong_length_and_junk() {
        assert_eq!(normalise_bsb("06200"), None); // 5 digits
        assert_eq!(normalise_bsb("0620000"), None); // 7 digits
        assert_eq!(normalise_bsb(""), None);
        assert_eq!(normalise_bsb("not a bsb"), None);
        assert!(is_bsb_shaped("033-088"));
        assert!(!is_bsb_shaped("33-088"));
    }

    #[test]
    fn resolves_the_big_four() {
        assert_eq!(bsb_institution("012-003"), Some("ANZ"));
        assert_eq!(bsb_institution("032-000"), Some("Westpac"));
        assert_eq!(bsb_institution("062-000"), Some("Commonwealth Bank"));
        assert_eq!(bsb_institution("082-001"), Some("NAB"));
    }

    #[test]
    fn three_digit_prefix_wins_over_two_digit_block() {
        // 182/183 (Macquarie) sit inside the 18x space; the 3-digit entry must
        // win the longest-prefix match.
        assert_eq!(bsb_institution("182-512"), Some("Macquarie Bank"));
        assert_eq!(bsb_institution("183-334"), Some("Macquarie Bank"));
    }

    #[test]
    fn resolves_major_second_tier_banks() {
        assert_eq!(bsb_institution("112-879"), Some("St George Bank"));
        assert_eq!(bsb_institution("306-089"), Some("Bankwest"));
        assert_eq!(bsb_institution("633-000"), Some("Bendigo Bank"));
        assert_eq!(bsb_institution("484-799"), Some("Suncorp Bank"));
        assert_eq!(bsb_institution("105-900"), Some("BankSA"));
        assert_eq!(bsb_institution("193-879"), Some("Bank of Melbourne"));
        assert_eq!(bsb_institution("923-100"), Some("ING"));
    }

    #[test]
    fn unrecognised_or_malformed_yields_none() {
        assert_eq!(bsb_institution("999-999"), None); // unallocated
        assert_eq!(bsb_institution("06200"), None); // malformed
        assert_eq!(bsb_institution("not a bsb"), None);
    }
}
