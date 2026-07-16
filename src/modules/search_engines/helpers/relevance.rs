//! Subject-relevance predicates that gate snippet extraction against a single
//! search result — the guard that stops PII / geo being mined from a page that
//! does not actually mention the subject.
//!
//! The existing name-based gate (`build_entities`) requires a multi-part name's
//! surname to appear in a result before trusting its snippet. But a PHONE seed
//! is a single token, so it fell through to the permissive branch and mined
//! EVERY result — and when the number itself is not indexed anywhere, the search
//! engines return generic country pages whose place-names get geocoded as if
//! they were the subject's location. A live `+61…` scan reproduced exactly this:
//! a `weather.com` "Ghan, NT, 0872" result — which never contained the number —
//! was geocoded into a confident Northern Territory location. This module gives a
//! phone seed the precise-identifier anchor it needs.

/// True if `hay` (a result's title + snippet + URL) plausibly mentions the phone
/// number `seed_phone`, in ANY format. Both sides are reduced to their digit
/// runs and the seed's trailing **subscriber** digits (country / trunk code
/// stripped) must appear — so `"0400 232 390"`, `"+61 400 232 390"` and
/// `"61400232390"` all match one seed, while an unrelated page (a generic
/// country result, a different local number) does not.
///
/// A phone is a precise identifier: unlike a surname it cannot legitimately be
/// "about the subject" while absent from the text. Reducing to the trailing
/// subscriber digits makes the match format-agnostic without the false matches a
/// bare full-string compare would miss. Requires ≥7 significant digits so a
/// coincidental short run can never false-match.
pub(in crate::modules::search_engines) fn result_mentions_phone(
    hay: &str,
    seed_phone: &str,
) -> bool {
    let seed_digits: String = seed_phone.chars().filter(char::is_ascii_digit).collect();
    // 9 trailing digits cover AU / UK / US subscriber numbers; a shorter seed
    // uses all of its digits. Below 7 the run is too short to anchor on.
    let sig_len = seed_digits.len().min(9);
    if sig_len < 7 {
        return false;
    }
    let significant = &seed_digits[seed_digits.len() - sig_len..];
    let hay_digits: String = hay.chars().filter(char::is_ascii_digit).collect();
    hay_digits.contains(significant)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = "+61400232390";

    #[test]
    fn matches_the_number_in_any_common_format() {
        assert!(result_mentions_phone("call me on 0400 232 390 today", SEED));
        assert!(result_mentions_phone("reach us: +61 400 232 390", SEED));
        assert!(result_mentions_phone(
            "contact 61400232390 for details",
            SEED
        ));
        assert!(result_mentions_phone("Mob: 0400-232-390", SEED));
    }

    #[test]
    fn rejects_a_result_that_does_not_contain_the_number() {
        // The exact false-positive that geocoded to the NT: a generic weather page.
        assert!(!result_mentions_phone(
            "Ghan, Northern Territory, 0872, Australia — 10-day weather",
            SEED
        ));
        assert!(!result_mentions_phone(
            "Australia population 25,690,000 (2026)",
            SEED
        ));
        // A DIFFERENT local number must not satisfy the gate.
        assert!(!result_mentions_phone(
            "Darwin office: (08) 8999 5511",
            SEED
        ));
    }

    #[test]
    fn short_seeds_never_anchor() {
        // Fewer than 7 significant digits → refuse (too collision-prone).
        assert!(!result_mentions_phone(
            "code 12345 and 12345 again",
            "12345"
        ));
    }
}
