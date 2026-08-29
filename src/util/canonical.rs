//! Pure, offline canonical-identity-form primitives shared by every layer that
//! needs to recognise the SAME real-world email mailbox, person name or
//! handle despite superficial spelling differences.
//!
//! # Why this lives in `util`
//! Several independent call sites need the identical rule:
//!   * [`crate::core::resolve`] buckets *existing* entities by their canonical
//!     form to suggest merges the exact-UID correlator's own normalisation
//!     misses;
//!   * [`crate::modules::email_canonical`] *emits* the canonical form as a new
//!     `Email` entity for one seed, so the correlator pivots on it directly at
//!     depth;
//!   * `crate::modules::name_intel::permute` (private) strips a trailing
//!     suffix before deriving username/email permutations from a display
//!     name;
//!   * AU-081 (`core::correlator::rules::identity::account::platform`)
//!     tokenizes both sides of a cross-source person-name match, so a
//!     hyphenated compound surname (`"Smith-Jones"`) can never collide with
//!     an unrelated space-separated name (`"Smith Jones"`) the way it did
//!     before it shared [`name_word_tokens`] with `core::resolve`.
//!
//! `core` must not depend on `modules` (see `tests/architecture.rs`'s
//! `core_does_not_import_modules`), so no caller here can simply call
//! another's implementation. Before this module existed, `core::resolve`
//! carried its own self-contained reimplementation of the Gmail-dot/`+tag`
//! rule and the generational-suffix list, and AU-081 carried a THIRD, looser
//! name-tokeniser that treated a hyphen as a separator — copies of logic that
//! must never disagree, with no compiler check that they didn't (and, for the
//! AU-081 copy, one already had: it folded a hyphenated compound surname onto
//! an unrelated space-separated name, the exact false-merge class
//! `core::resolve`'s own module docs describe fixing there but which was never
//! ported to AU-081). Every rule below is pure, offline and dependency-free,
//! so `util` (the one layer both `core` and `modules` may call into) is where
//! a single, testable definition belongs instead — the same fix already
//! applied to the shared entity-extraction regexes (see
//! `tests/architecture.rs`'s `entity_extractor_reuses_core_patterns`, which
//! asserts `util::entity_extractor` re-exports the *same* compiled `Regex`
//! instances `core::classifier` owns, rather than a second copy that could
//! silently drift).
//!
//! Everything here is pure and offline — no I/O, no network, no shared state —
//! which is what makes it safe for `core` to call directly under the
//! `core_does_not_import_util_directly` architecture test's pure/leaf
//! allowlist, the same leaf category as `util::confusable` / `util::abn`.

/// The two Gmail-family domains that share one mailbox namespace and treat
/// dots in the local-part as insignificant. `googlemail.com` is a legacy alias
/// of `gmail.com`, so both canonicalise to `gmail.com` (see
/// [`canonical_email_mailbox`]).
pub const GMAIL_DOMAINS: [&str; 2] = ["gmail.com", "googlemail.com"];

/// Generational/professional suffix tokens that follow a comma WITHOUT making
/// it a surname-first separator (`"Smith, Jr."`, `"Smith, PhD"`).
///
/// Shared by [`crate::core::resolve`] (deciding whether a post-comma segment
/// is a real given name or just a suffix, before folding a name to its
/// canonical surname-first-normalised form) and
/// `crate::modules::name_intel::permute` (private; stripping a trailing
/// suffix before deriving username/email permutations from a display name) —
/// the same list,
/// so a name that is "just a suffix" to one is never "a given name" to the
/// other.
pub const GEN_SUFFIXES: &[&str] = &[
    "jr", "sr", "ii", "iii", "iv", "v", "vi", "esq", "phd", "md", "dds", "jd", "mba", "rn", "np",
    "do", "psyd",
];

/// Canonical mailbox form of an email address, or `None` when it has no `@`,
/// an empty local-part or domain, or no canonical local-part survives.
///
/// Rules (the equivalences are documented routing behaviour, not guesses):
/// * lowercase the whole address (a full Unicode case-fold, matching
///   [`crate::core::entity`]'s entity-UID normaliser for `Email`, so a
///   non-ASCII capital folds identically at both layers);
/// * strip a `+tag` suffix from the local-part — plus-addressing routes to the
///   base mailbox on every major provider (Gmail, Outlook/Microsoft, Fastmail,
///   Proton, iCloud, …), so it never distinguishes identity;
/// * for **Gmail only** ([`GMAIL_DOMAINS`]) additionally drop **all dots** in
///   the local-part and fold the domain to `gmail.com` — Gmail treats
///   `j.o.h.n` and `john` as one mailbox.
///
/// Provider-specific stance: dots are **kept** for every non-Gmail domain.
/// Most providers treat `a.b@corp.com` and `ab@corp.com` as *different*
/// mailboxes, so stripping dots universally would be a false merge. This is
/// deliberately the conservative choice — only the documented Gmail rule drops
/// dots.
///
/// ```
/// use huntsman_search_engine::util::canonical::canonical_email_mailbox;
///
/// assert_eq!(
///     canonical_email_mailbox("Jo.hn+promo@GoogleMail.com").as_deref(),
///     Some("john@gmail.com")
/// );
/// // Non-Gmail: dots are significant — only the +tag is stripped.
/// assert_eq!(
///     canonical_email_mailbox("jane+promo@corp.com").as_deref(),
///     Some("jane@corp.com")
/// );
/// assert_eq!(canonical_email_mailbox("not-an-email"), None);
/// ```
#[must_use]
pub fn canonical_email_mailbox(value: &str) -> Option<String> {
    let lower = value.trim().to_lowercase();
    let (local, domain) = lower.split_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }

    // `+tag` subaddressing: the base mailbox before the first '+' is the
    // identity. Universally safe — every major provider routes the base.
    let base = local.split('+').next().unwrap_or(local);

    let (local_canon, domain_canon) = if GMAIL_DOMAINS.contains(&domain) {
        // Gmail dot-blindness, and googlemail.com == gmail.com.
        (base.replace('.', ""), "gmail.com")
    } else {
        // Non-Gmail: keep dots (significant on most providers), keep the domain.
        (base.to_string(), domain)
    };

    if local_canon.is_empty() {
        return None;
    }
    Some(format!("{local_canon}@{domain_canon}"))
}

/// Split `value` into its whitespace-delimited word tokens: lowercased
/// (a full Unicode case-fold), with each token's SURROUNDING punctuation
/// stripped but INTERNAL punctuation (a hyphen, an apostrophe, a dot, an
/// underscore) preserved. A token that reduces to nothing after stripping is
/// dropped.
///
/// Deliberately does NOT split on every non-alphanumeric character the way a
/// naive name/handle tokeniser might: a hyphen, apostrophe, dot or underscore
/// INSIDE a name or handle usually joins two components into one meaningful
/// unit (`Smith-Jones`, `O'Brien`, a platform-specific handle separator)
/// rather than separating them, so splitting on it turns one token into two
/// and risks folding two meaningfully different values onto one canonical
/// key. Only WHITESPACE separates tokens; non-alphanumeric characters at a
/// token's own EDGES (a stray quote, a trailing comma, the dot on a trailing
/// `"Jr."`) are still stripped, which is enough to fold `"Bamford, Haigen"`
/// (comma immediately followed by whitespace) without also splitting
/// `"Smith-Jones"` into `"smith"` + `"jones"` — two tokens a genuinely
/// different, unrelated `"Smith Jones"` would ALSO produce.
///
/// This is the shared tokeniser behind [`crate::core::resolve`]'s canonical
/// name/handle folding and AU-081's cross-source person-name correlation
/// (`core::correlator::rules::identity::account::platform`), so a hyphenated
/// compound surname tokenizes identically in both — neither can fold it onto
/// an unrelated space-separated name the other keeps distinct.
///
/// ```
/// use huntsman_search_engine::util::canonical::name_word_tokens;
///
/// assert_eq!(
///     name_word_tokens("Anna Smith-Jones"),
///     vec!["anna", "smith-jones"]
/// );
/// assert_eq!(name_word_tokens("Mary O'Brien"), vec!["mary", "o'brien"]);
/// // A trailing comma is edge punctuation, not a separator to split on.
/// assert_eq!(name_word_tokens("Bamford,  Haigen"), vec!["bamford", "haigen"]);
/// ```
#[must_use]
pub fn name_word_tokens(value: &str) -> Vec<String> {
    let lower = value.to_lowercase();
    lower
        .split_whitespace()
        .filter_map(|tok| {
            let trimmed = tok.trim_matches(|c: char| !c.is_alphanumeric());
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gmail_dots_and_plus_tag_both_fold() {
        assert_eq!(
            canonical_email_mailbox("jo.hn+promo@gmail.com").as_deref(),
            Some("john@gmail.com")
        );
    }

    #[test]
    fn googlemail_alias_folds_to_gmail() {
        assert_eq!(
            canonical_email_mailbox("john.doe@googlemail.com").as_deref(),
            Some("johndoe@gmail.com")
        );
    }

    #[test]
    fn non_gmail_keeps_dots_but_strips_plus_tag() {
        assert_eq!(
            canonical_email_mailbox("jane.smith+promo@corp.com").as_deref(),
            Some("jane.smith@corp.com")
        );
    }

    #[test]
    fn case_is_fully_unicode_folded() {
        // A non-ASCII capital must fold the same as the base-entity
        // normaliser's Unicode case-fold, not just the ASCII A-Z range.
        assert_eq!(
            canonical_email_mailbox("ANDRÉ@CORP.COM").as_deref(),
            Some("andré@corp.com")
        );
    }

    #[test]
    fn malformed_addresses_yield_none() {
        assert_eq!(canonical_email_mailbox("notanemail"), None);
        assert_eq!(canonical_email_mailbox("@gmail.com"), None);
        assert_eq!(canonical_email_mailbox("user@"), None);
        assert_eq!(canonical_email_mailbox("+tag@gmail.com"), None);
    }

    #[test]
    fn hyphen_apostrophe_and_underscore_stay_inside_their_token() {
        assert_eq!(
            name_word_tokens("Anna Smith-Jones"),
            vec!["anna", "smith-jones"]
        );
        assert_eq!(name_word_tokens("Mary O'Brien"), vec!["mary", "o'brien"]);
        assert_eq!(
            name_word_tokens("jordan_avery handle"),
            vec!["jordan_avery", "handle"]
        );
    }

    #[test]
    fn edge_punctuation_is_stripped_not_split_on() {
        assert_eq!(
            name_word_tokens("Bamford,  Haigen"),
            vec!["bamford", "haigen"]
        );
        assert_eq!(name_word_tokens("\"quoted\""), vec!["quoted"]);
    }

    #[test]
    fn empty_and_punctuation_only_tokens_are_dropped() {
        assert!(name_word_tokens("").is_empty());
        assert!(name_word_tokens("   ").is_empty());
        assert_eq!(name_word_tokens("a - b"), vec!["a", "b"]);
    }
}
