//! Subject-relevance predicates that gate snippet extraction against a single
//! search result — the guard that stops PII / geo being mined from a page that
//! does not actually mention the subject.
//!
//! Asymmetry fix (Issue #4): Phones require the actual number to appear
//! (precise identifier); emails now require domain validation to prevent
//! attribution of unrelated company emails. A page "Alice works at ACME" with
//! email `bob@acme.com` should not extract that email as belonging to Alice.

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
    let seed_digits = crate::util::str_util::ascii_digits(seed_phone);
    // 9 trailing digits cover AU / UK / US subscriber numbers; a shorter seed
    // uses all of its digits. Below 7 the run is too short to anchor on.
    let sig_len = seed_digits.len().min(9);
    if sig_len < 7 {
        return false;
    }
    let significant = &seed_digits[seed_digits.len() - sig_len..];
    let hay_digits = crate::util::str_util::ascii_digits(hay);
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

/// True if an email extracted from a result plausibly belongs to the target.
///
/// For an EMAIL seed, requires the email domain to match the seed domain
/// (exact match or subdomain). For other seeds, requires the email domain
/// to match an expected context for the target type — a DOMAIN seed should
/// see emails on that domain, not unrelated company emails.
///
/// This prevents extraction of arbitrary company emails from pages that
/// merely mention the subject by name ("Alice works at ACME" → extract
/// `bob@acme.com` as Alice's email). The email domain is a precise identifier
/// that must align with the target, not just surname presence.
pub(in crate::modules::search_engines) fn email_plausibly_belongs_to_seed(
    email: &str,
    seed_kind: &super::super::TargetKind,
    seed_value: &str,
) -> bool {
    let email_domain = match email.rsplit_once('@') {
        Some((_, d)) => d.to_lowercase(),
        None => return false,
    };

    match seed_kind {
        super::super::TargetKind::Email => {
            let seed_domain = match seed_value.rsplit_once('@') {
                Some((_, d)) => d.to_lowercase(),
                None => return false,
            };
            email_domain == seed_domain
                || crate::util::domains::is_proper_subdomain_of(&email_domain, &seed_domain)
        }
        super::super::TargetKind::Domain => {
            let seed_domain = seed_value.to_lowercase();
            email_domain == seed_domain
                || crate::util::domains::is_proper_subdomain_of(&email_domain, &seed_domain)
        }
        super::super::TargetKind::Username => false,
        _ => false,
    }
}

#[cfg(test)]
mod email_tests {
    use super::*;

    #[test]
    fn email_seed_requires_domain_match() {
        assert!(email_plausibly_belongs_to_seed(
            "alice@example.com",
            &super::super::TargetKind::Email,
            "alice@example.com"
        ));
        assert!(email_plausibly_belongs_to_seed(
            "alice@mail.example.com",
            &super::super::TargetKind::Email,
            "alice@example.com"
        ));
        assert!(!email_plausibly_belongs_to_seed(
            "bob@acme.com",
            &super::super::TargetKind::Email,
            "alice@example.com"
        ));
    }

    #[test]
    fn domain_seed_requires_domain_match() {
        assert!(email_plausibly_belongs_to_seed(
            "contact@example.com",
            &super::super::TargetKind::Domain,
            "example.com"
        ));
        assert!(email_plausibly_belongs_to_seed(
            "info@mail.example.com",
            &super::super::TargetKind::Domain,
            "example.com"
        ));
        assert!(!email_plausibly_belongs_to_seed(
            "bob@acme.com",
            &super::super::TargetKind::Domain,
            "example.com"
        ));
    }

    #[test]
    fn username_seed_never_validates_email() {
        assert!(!email_plausibly_belongs_to_seed(
            "alice@example.com",
            &super::super::TargetKind::Username,
            "alice_name"
        ));
    }
}

/// True when `needle` occurs in `hay` as a bounded token, not merely a raw
/// substring: the byte immediately before and after every candidate match is
/// outside the token's own alphabet (`is_inner`), or the match sits at a text
/// boundary. A relevance gate over free-text SERP snippets that used a plain
/// `contains` false-matched a short subject inside a longer word
/// (REQ-SEARCH-003). `needle` is assumed already lowercased by the caller;
/// an empty `needle` never matches. Byte-boundary safe on UTF-8 text: a
/// non-ASCII neighbour byte is never `is_inner`, so it reads as a boundary.
fn token_bounded(hay: &str, needle: &str, is_inner: impl Fn(u8) -> bool) -> bool {
    if needle.is_empty() {
        return false;
    }
    let hb = hay.as_bytes();
    let nlen = needle.len();
    hay.match_indices(needle).any(|(start, _)| {
        let before_ok = start == 0 || !is_inner(hb[start - 1]);
        let end = start + nlen;
        let after_ok = end == hb.len() || !is_inner(hb[end]);
        before_ok && after_ok
    })
}

/// True when `term` occurs in `hay` as a whole word — bounded by the start/end
/// of the text or a non-alphanumeric byte. Closes the false match a raw
/// `contains` made of a short single-token subject (a 3-char handle `abc`)
/// inside a longer word (`abcnews.com`) — REQ-SEARCH-003, the residual an
/// adversarial re-attack found in REQ-SEARCH-002's snippet gate. `term` is
/// assumed lowercased.
pub(in crate::modules::search_engines) fn names_word_token(hay: &str, term: &str) -> bool {
    token_bounded(hay, term, |b| b.is_ascii_alphanumeric())
}

/// True when `domain` occurs in `hay` as a domain unit — bounded by the
/// start/end or a byte that is not a domain-label byte (`[a-z0-9-]`). A `.`
/// before it is a boundary, so `mail.art.com` names the seed `art.com`, while
/// `smart.com` (leading `m`), `my-art.com` (leading `-`) and `art.community`
/// (trailing `m`) do not — REQ-SEARCH-003, the residual an adversarial
/// re-attack found in REQ-PROBE-003's Domain relevance gate. `domain` is
/// assumed lowercased.
pub(in crate::modules::search_engines) fn names_domain_token(hay: &str, domain: &str) -> bool {
    token_bounded(hay, domain, |b| b.is_ascii_alphanumeric() || b == b'-')
}

#[cfg(test)]
mod token_boundary_tests {
    use super::*;

    #[test]
    fn a_short_subject_is_a_word_not_a_substring() {
        assert!(names_word_token("visit abc today", "abc"));
        assert!(names_word_token("github.com/abc profile", "abc"));
        assert!(names_word_token("john.doe@x.com wrote", "doe"));
        assert!(!names_word_token("abcnews.com covered it", "abc"));
        assert!(!names_word_token("see cabca listed", "abc"));
        assert!(!names_word_token("", "abc"));
        assert!(!names_word_token("anything at all", ""));
        // A distinctive longer token still matches exactly as `contains` did.
        assert!(names_word_token(
            "profile of gd618sephcjw here",
            "gd618sephcjw"
        ));
        assert!(!names_word_token("nothing relevant here", "gd618sephcjw"));
    }

    #[test]
    fn a_domain_is_a_registrable_unit_not_a_substring() {
        assert!(names_domain_token("mail.art.com/login", "art.com"));
        assert!(names_domain_token("about art.com since 2019", "art.com"));
        assert!(names_domain_token("https://art.com", "art.com"));
        assert!(!names_domain_token("https://smart.com/x", "art.com"));
        assert!(!names_domain_token("start.com homepage", "art.com"));
        assert!(!names_domain_token("my-art.com blog", "art.com"));
        assert!(!names_domain_token("art.community forum", "art.com"));
        // A long seed and its subdomains are unaffected.
        assert!(names_domain_token(
            "supplier to targetcorp.com.au since 2019",
            "targetcorp.com.au"
        ));
        assert!(names_domain_token(
            "https://mail.targetcorp.com.au/x",
            "targetcorp.com.au"
        ));
        assert!(!names_domain_token("index.hu news", "targetcorp.com.au"));
    }
}
