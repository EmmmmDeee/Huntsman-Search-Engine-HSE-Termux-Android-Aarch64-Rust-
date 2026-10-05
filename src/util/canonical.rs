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
//!     before it shared [`name_word_tokens`] with `core::resolve`;
//!   * the resolver's `SameAs` suggestions, the relation layer's structural
//!     `AliasOf` builder and co-reference scoring's handle-equivalence tier
//!     all decide "same account handle" by [`username_account_key`] /
//!     [`email_account_keys`], so a separator one of them keeps can never be
//!     folded away by another (Copilot review of #649).
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

/// Domains whose mail service implements RFC 5233 `+tag` subaddressing by
/// default, so `jane+promo@…` and `jane@…` are provably the SAME mailbox and
/// may be folded onto one canonical identity.
///
/// Deliberately an ALLOWLIST, not a universal rule (REQ-EMAILCANON-001).
/// Plus-addressing is a per-mail-server opt-in convention, not a property of
/// the address string: an arbitrary corporate or self-hosted domain may route
/// `jane+promo@corp.example` to a different mailbox than `jane@corp.example`,
/// or nowhere at all (Microsoft 365/Exchange Online tenants, for instance,
/// require an administrator to enable it explicitly). Folding unconditionally
/// therefore fused two potentially DIFFERENT real people onto one identity —
/// and [`crate::modules::email_canonical`] emits that fold as a new `Email`
/// entity above the expansion floor, so the scan actively pivots the whole
/// email pipeline onto the fabricated link.
///
/// The list is intentionally conservative and limited to the providers whose
/// support is documented and default-on (RULE.md: no assumed contract). An
/// unrecognised domain keeps its tag: the fail-safe direction is to leave two
/// addresses SEPARATE when equivalence is unproven, since a missed merge is
/// recoverable while a false merge silently corrupts an identity. Notably
/// absent: Yahoo, which offers disposable addresses rather than `+tag`
/// subaddressing.
pub const PLUS_ADDRESSING_DOMAINS: &[&str] = &[
    // Google (both namespace aliases — see `GMAIL_DOMAINS`).
    "gmail.com",
    "googlemail.com",
    // Microsoft consumer accounts.
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    // Fastmail.
    "fastmail.com",
    "fastmail.fm",
    // Proton.
    "proton.me",
    "protonmail.com",
    "protonmail.ch",
    "pm.me",
    // Apple iCloud.
    "icloud.com",
    "me.com",
    "mac.com",
];

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
/// * strip a `+tag` suffix from the local-part **only for a domain whose mail
///   service is known to implement RFC 5233 subaddressing**
///   ([`PLUS_ADDRESSING_DOMAINS`] — Gmail, Outlook/Microsoft, Fastmail,
///   Proton, iCloud); there the tag provably routes to the base mailbox and so
///   never distinguishes identity. For any other domain the tag is PRESERVED,
///   because plus-addressing is a per-server opt-in rather than a property of
///   the address, and folding it blind fused two potentially different real
///   people onto one identity (REQ-EMAILCANON-001);
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
/// // A known subaddressing provider: dots are significant off-Gmail, but the
/// // +tag provably routes to the base mailbox, so it is stripped.
/// assert_eq!(
///     canonical_email_mailbox("Jane.Doe+promo@Outlook.com").as_deref(),
///     Some("jane.doe@outlook.com")
/// );
/// // An arbitrary domain: subaddressing is NOT guaranteed, so the tag is kept
/// // rather than fusing two possibly-different mailboxes (REQ-EMAILCANON-001).
/// assert_eq!(
///     canonical_email_mailbox("jane+promo@corp.com").as_deref(),
///     Some("jane+promo@corp.com")
/// );
/// assert_eq!(canonical_email_mailbox("not-an-email"), None);
/// ```
#[must_use]
pub fn canonical_email_mailbox(value: &str) -> Option<String> {
    let lower = value.trim().to_lowercase();
    let (base, domain) = routed_local_part(&lower)?;

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

/// The provider-routed local part of an already-lowercased address and its
/// domain: `(local part with a `+tag` stripped ONLY for a
/// [`PLUS_ADDRESSING_DOMAINS`] provider, domain)`, or `None` when there is no
/// `@` or either side is empty. The one statement of the `+tag` rule, shared
/// by [`canonical_email_mailbox`] (which additionally applies Gmail
/// dot-blindness) and [`email_account_keys`], so the two can never disagree on
/// which tags route to the base mailbox.
fn routed_local_part(lower: &str) -> Option<(&str, &str)> {
    let (local, domain) = lower.split_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    // `+tag` subaddressing: the base mailbox before the first '+' is the
    // identity — but ONLY where the provider is known to implement it. See
    // `PLUS_ADDRESSING_DOMAINS` for why this is an allowlist rather than the
    // universal rule it used to be (REQ-EMAILCANON-001).
    let base = if PLUS_ADDRESSING_DOMAINS.contains(&domain) {
        local.split('+').next().unwrap_or(local)
    } else {
        local
    };
    Some((base, domain))
}

/// The account key of a username / handle: lowercase, whitespace runs
/// collapsed to single spaces — and NOTHING else. Every other character,
/// including a `.`, `_` or `-` at the very start or end of the handle, is kept
/// verbatim. `None` for a value with nothing but whitespace.
///
/// Two handles are one account only when their account keys are equal. A
/// separator is part of the account's name: no platform treats `.`, `_` and
/// `-` as interchangeable — GitHub handles allow only hyphens, Twitter/X only
/// underscores, Instagram dots and underscores as DISTINCT characters — and
/// Instagram and X register a leading or trailing `_` (Instagram a `.` too) as
/// an account-distinguishing character. So `jordan.avery` / `jordan_avery`,
/// and `_ianthorpe_` / `ianthorpe`, are different accounts that merely share
/// letters. Only case (handles are case-insensitive everywhere HSE reads
/// them) and whitespace (formatting noise from a scraped page) are folded.
/// The leading `@` is already stripped by the entity normaliser before a value
/// reaches this.
///
/// The single authority for "same account handle", shared by
/// [`crate::core::resolve`]'s `SameAs` merge suggestions, the relation layer's
/// structural `AliasOf` builder and co-reference scoring's handle-equivalence
/// tier. Each of them once folded separators — the resolver through a
/// tokeniser that treated every non-alphanumeric character as a separator and
/// then one that trimmed a token's edge punctuation (REQ-RESOLVE-001, scan
/// `7258fc07`, target "Ian Thorpe": Instagram `_ianthorpe_` fused with the
/// subject's `ianthorpe`, X `carolathorpe` with Instagram `carolathorpe_`, two
/// Instagram accounts `_caroline.thorpe` / `caroline.thorpe`), and the relation
/// layer through the alphanumeric-only `identity_norm`, which re-created the
/// same false merges as `AliasOf` after the resolver stopped making them
/// (Copilot review of #649).
///
/// ```
/// use huntsman_search_engine::util::canonical::username_account_key;
///
/// assert_eq!(username_account_key(" IanThorpe ").as_deref(), Some("ianthorpe"));
/// // Every separator is part of the account's name, even at an edge.
/// assert_ne!(username_account_key("_ianthorpe_"), username_account_key("ianthorpe"));
/// assert_ne!(username_account_key("jordan.avery"), username_account_key("jordan_avery"));
/// assert_eq!(username_account_key("   "), None);
/// ```
#[must_use]
pub fn username_account_key(value: &str) -> Option<String> {
    let folded = value
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    (!folded.is_empty()).then_some(folded)
}

/// The account keys an email address answers to as a HANDLE — the forms of
/// its local part that name the same account a username of that spelling
/// would, for matching a mailbox against a username or another mailbox.
///
/// * The literal local part, lowercased, with a `+tag` stripped only for a
///   [`PLUS_ADDRESSING_DOMAINS`] provider (the same routing rule
///   [`canonical_email_mailbox`] applies): `ian.thorpe@gmail.com` answers to
///   `ian.thorpe`, so it matches the username `ian.thorpe`.
/// * For a [`GMAIL_DOMAINS`] mailbox only, ALSO the dot-free form: Gmail
///   documents that dots in the local part do not distinguish accounts, so
///   `ian.thorpe@gmail.com` is the account `ianthorpe` as well, and matches
///   the username `ianthorpe` and the mailbox `ianthorpe@gmail.com`.
///
/// Everywhere else a dot, underscore or hyphen is kept: `ian.thorpe@outlook.com`
/// and `ianthorpe@outlook.com` are two Outlook accounts and share no key. Empty
/// when the address has no `@` or an empty side; a key that folds to nothing
/// is omitted. At most two keys, literal first, never duplicated.
///
/// Emails are keyed on the local part alone — the domain is deliberately not
/// part of the key, because a mailbox's local part matching a username IS the
/// cross-kind handle pivot these keys exist for. Two mailboxes at different
/// domains share a key without being one account; the callers withhold that
/// pair through `core::coref::mailboxes_at_different_domains`.
///
/// ```
/// use huntsman_search_engine::util::canonical::email_account_keys;
///
/// assert_eq!(email_account_keys("Ian.Thorpe+x@GMAIL.com"), vec!["ian.thorpe", "ianthorpe"]);
/// assert_eq!(email_account_keys("jsmith@gmail.com"), vec!["jsmith"]);
/// assert_eq!(email_account_keys("ian.thorpe@outlook.com"), vec!["ian.thorpe"]);
/// // An arbitrary domain keeps its tag, exactly as `canonical_email_mailbox` does.
/// assert_eq!(email_account_keys("jane+promo@corp.com"), vec!["jane+promo"]);
/// assert!(email_account_keys("not-an-email").is_empty());
/// ```
#[must_use]
pub fn email_account_keys(value: &str) -> Vec<String> {
    let lower = value.trim().to_lowercase();
    let Some((base, domain)) = routed_local_part(&lower) else {
        return Vec::new();
    };
    let mut keys: Vec<String> = Vec::with_capacity(2);
    if !base.is_empty() {
        keys.push(base.to_string());
    }
    if GMAIL_DOMAINS.contains(&domain) {
        let dot_free = base.replace('.', "");
        if !dot_free.is_empty() && !keys.contains(&dot_free) {
            keys.push(dot_free);
        }
    }
    keys
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
    fn non_gmail_subaddressing_provider_keeps_dots_but_strips_plus_tag() {
        // The original intent of this test — "off Gmail, dots are significant
        // but the +tag is not" — is preserved, moved onto a domain where
        // subaddressing is actually documented. It previously used `corp.com`,
        // an arbitrary domain, which is what locked in REQ-EMAILCANON-001's
        // universal-strip bug.
        assert_eq!(
            canonical_email_mailbox("jane.smith+promo@outlook.com").as_deref(),
            Some("jane.smith@outlook.com")
        );
    }

    #[test]
    fn an_arbitrary_domain_keeps_its_plus_tag() {
        // REQ-EMAILCANON-001. `+tag` subaddressing is a per-mail-server opt-in
        // (RFC 5233), not a property of the address string, so an arbitrary
        // corporate or self-hosted domain may route `jane+promo@` to a
        // different mailbox than `jane@` — or nowhere. Folding it
        // unconditionally fused two potentially DIFFERENT real people onto one
        // canonical identity. Dots stay significant here too.
        assert_eq!(
            canonical_email_mailbox("jane.smith+promo@corp.com").as_deref(),
            Some("jane.smith+promo@corp.com")
        );
        assert_eq!(
            canonical_email_mailbox("bob+x@smallbiz.example").as_deref(),
            Some("bob+x@smallbiz.example")
        );
        // ...so the two spellings do NOT collapse onto one key.
        assert_ne!(
            canonical_email_mailbox("bob+x@smallbiz.example"),
            canonical_email_mailbox("bob@smallbiz.example"),
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

    /// Copilot review of #649: the account key is the one "same handle"
    /// authority for the resolver, the relation layer and co-reference
    /// scoring. Case and whitespace fold; every separator, even at an edge,
    /// stays part of the account's name.
    #[test]
    fn username_account_key_keeps_every_separator() {
        assert_eq!(
            username_account_key("  IanThorpe ").as_deref(),
            Some("ianthorpe")
        );
        assert_eq!(
            username_account_key("Ian   Thorpe").as_deref(),
            Some("ian thorpe")
        );
        for (a, b) in [
            ("_ianthorpe_", "ianthorpe"),
            ("carolathorpe", "carolathorpe_"),
            ("_caroline.thorpe", "caroline.thorpe"),
            ("jordan.avery", "jordan_avery"),
            ("jordan-avery", "jordan.avery"),
        ] {
            assert_ne!(
                username_account_key(a),
                username_account_key(b),
                "{a} / {b}"
            );
        }
        assert_eq!(username_account_key(" \t "), None);
    }

    /// An email's account keys: its literal (routed) local part, plus the
    /// dot-free form for Gmail only — the provider rules shared with
    /// `canonical_email_mailbox` through one helper.
    #[test]
    fn email_account_keys_follow_the_provider_rules() {
        assert_eq!(
            email_account_keys("ian.thorpe@gmail.com"),
            vec!["ian.thorpe", "ianthorpe"]
        );
        assert_eq!(
            email_account_keys("Ian.Thorpe+news@googlemail.com"),
            vec!["ian.thorpe", "ianthorpe"],
            "googlemail is Gmail; its +tag routes to the base mailbox"
        );
        assert_eq!(email_account_keys("ianthorpe@gmail.com"), vec!["ianthorpe"]);
        assert_eq!(
            email_account_keys("ian.thorpe+x@outlook.com"),
            vec!["ian.thorpe"],
            "Outlook strips the tag but keeps its dots"
        );
        assert_eq!(
            email_account_keys("_ianthorpe_@corp.example"),
            vec!["_ianthorpe_"]
        );
        assert_eq!(
            email_account_keys("jane+promo@corp.com"),
            vec!["jane+promo"],
            "an arbitrary domain keeps its tag (REQ-EMAILCANON-001)"
        );
        assert!(email_account_keys("not-an-email").is_empty());
        assert!(email_account_keys("+tag@gmail.com").is_empty());
        // The mailbox rule is unchanged by the shared helper.
        assert_eq!(
            canonical_email_mailbox("Ian.Thorpe+news@googlemail.com").as_deref(),
            Some("ianthorpe@gmail.com")
        );
    }

    #[test]
    fn empty_and_punctuation_only_tokens_are_dropped() {
        assert!(name_word_tokens("").is_empty());
        assert!(name_word_tokens("   ").is_empty());
        assert_eq!(name_word_tokens("a - b"), vec!["a", "b"]);
    }
}
