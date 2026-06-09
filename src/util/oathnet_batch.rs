//! Built-in OathNet **batch query generator**.
//!
//! Expands a single seed (email / username / name / phone / IP / domain) into
//! a large, de-duplicated array of distinct OathNet queries by crossing three
//! axes:
//!
//!   1. **Surface** — the breach corpus, plus (for login-indexable selectors)
//!      the stealer corpus.
//!   2. **Selector field** — `email` / `username` / `phone` / `domain` / `ip`
//!      / `q`, derived from the seed *and* from sub-parts of it (an email's
//!      local part becomes a `username` search, its domain a `domain` search).
//!   3. **Value permutation** — names and email local parts fan out into the
//!      handle shapes real accounts use (`first.last`, `flast`, `firstl`, …);
//!      phone numbers fan out into the digit/E.164 formats breach dumps store
//!      them in.
//!
//! The surface↔path and target-kind↔selector-field vocabulary is shared with
//! the `oathnet_pro` scan module via [`crate::util::oathnet`] (single source of
//! truth) rather than re-encoded here.
//!
//! The generator is **pure** (no IO, no quota) so the full plan can be previewed
//! for free and is exhaustively unit-testable; the CLI layer is what actually
//! dispatches it (and is what spends OathNet credits).
//!
//! # Guarantees
//!
//! [`generate`] returns a `Vec<BatchQuery>` that is:
//!
//! * **deterministic** — the same input always yields the same vec, in the same
//!   order (no `HashMap` iteration order leaks in);
//! * **seed-first** — the seed's own queries precede every derived query;
//! * **de-duplicated** — no two queries share a `(surface, field, value)` triple
//!   when compared case-insensitively on the value;
//! * **well-formed** — every query's `value` is trimmed and non-empty and its
//!   `field` is one of OathNet's selector fields; and
//! * **bounded** — at most `opts.max_queries` queries when that cap is non-zero.
//!
//! These are enforced by the test suite, not merely intended.
//!
//! # Limitations
//!
//! Handle permutation is **ASCII-only**: [`name_tokens`] treats any non-ASCII
//! character as a separator, so an accented name (`"Renée"`) loses the accented
//! run rather than being transliterated. This is deliberate — account handles
//! are overwhelmingly ASCII and a fold table would add a dependency for little
//! real-world recall — but it means non-Latin seeds fall back to the free-text
//! `q` search only.

use std::collections::HashSet;

use crate::core::scan::TargetKind;
use crate::util::oathnet;

// The surface vocabulary (breach/stealer ↔ path) is the shared OathNet query
// model — re-exported so `BatchQuery` and the CLI keep naming it
// `oathnet_batch::Surface` while there is exactly one definition.
pub use crate::util::oathnet::Surface;

/// Why a query was generated — surfaced in the plan so an operator can see how
/// each query relates to the seed, and so callers can weight derived queries
/// below the direct seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    /// The seed value itself, searched on its native selector.
    Seed,
    /// A `username` search built from an email's local part.
    EmailLocalPart,
    /// A `domain` search built from an email's domain.
    EmailDomain,
    /// A `username` search built from a name/handle permutation.
    Handle,
    /// A reformatted phone number (digits-only, E.164, …).
    PhoneFormat,
    /// A synthesised candidate email (handle/role crossed with a domain).
    EmailCandidate,
}

impl Origin {
    /// Short human/JSON label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::EmailLocalPart => "email-local-part",
            Self::EmailDomain => "email-domain",
            Self::Handle => "handle-permutation",
            Self::PhoneFormat => "phone-format",
            Self::EmailCandidate => "email-candidate",
        }
    }
}

/// A single generated query: one surface × one selector field × one value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchQuery {
    /// Which OathNet corpus this query targets.
    pub surface: Surface,
    /// OathNet selector field (`email`, `username`, `phone`, `domain`, `ip`, `q`).
    pub field: &'static str,
    /// The value to search for — always trimmed and non-empty.
    pub value: String,
    /// Why this query was generated — its provenance back to the seed.
    pub origin: Origin,
}

/// Knobs controlling how aggressively the seed is expanded.
///
/// Build from [`BatchOptions::default`] and override the fields you need:
///
/// ```
/// use huntsman_search_engine::util::oathnet_batch::BatchOptions;
///
/// // Breach-only, no speculative handle permutations, capped at 8 queries.
/// let opts = BatchOptions {
///     include_stealer: false,
///     permute_handles: false,
///     max_queries: 8,
///     ..BatchOptions::default()
/// };
/// assert!(!opts.synthesize_emails); // the conservative default is preserved
/// ```
#[derive(Debug, Clone)]
pub struct BatchOptions {
    /// Also emit stealer-surface queries for login-indexable selectors
    /// (`email`/`username`). Breach is always emitted.
    pub include_stealer: bool,
    /// Fan names and email local parts out into handle permutations.
    pub permute_handles: bool,
    /// Synthesise candidate emails (handle/role crossed with common providers).
    /// Explosive and speculative — off by default.
    pub synthesize_emails: bool,
    /// Cap on the number of queries returned after de-duplication. `0` = no cap.
    pub max_queries: usize,
}

impl Default for BatchOptions {
    fn default() -> Self {
        Self {
            include_stealer: true,
            permute_handles: true,
            synthesize_emails: false,
            max_queries: 0,
        }
    }
}

/// OathNet selector field for usernames — the derived field used when an email
/// local part or a name fans out into handle searches. Named once so the magic
/// string isn't sprinkled through the derivation logic.
const FIELD_USERNAME: &str = "username";
/// OathNet selector field for emails — used for synthesised candidate emails.
const FIELD_EMAIL: &str = "email";
/// OathNet selector field for domains — used for an email's domain pivot.
const FIELD_DOMAIN: &str = "domain";

/// Common free email providers — used both to synthesise candidate emails and
/// to SKIP as `domain` searches (querying e.g. `gmail.com` as a domain returns
/// the entire provider corpus, which is noise, not signal).
const FREEMAIL: &[&str] = &[
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "icloud.com",
    "proton.me",
    "aol.com",
];

/// Role local-parts crossed with a seed domain when `synthesize_emails` is set.
const ROLE_LOCALPARTS: &[&str] = &["admin", "info", "contact", "support", "sales"];

fn is_freemail(domain: &str) -> bool {
    let d = domain.trim().to_ascii_lowercase();
    FREEMAIL.contains(&d.as_str())
}

/// First character of a non-empty token (used for initials).
fn initial(token: &str) -> char {
    token.chars().next().unwrap_or('x')
}

/// Split a raw string into ASCII-lowercased alphabetic tokens of length ≥ 2.
/// Digits and punctuation are separators, so `"john.doe99"` → `["john","doe"]`.
fn name_tokens(raw: &str) -> Vec<String> {
    raw.split(|c: char| !c.is_ascii_alphabetic())
        .filter(|t| t.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Generate the handle shapes real accounts use from a set of name tokens.
/// A single opaque token yields only itself (it can't be recombined); two or
/// more tokens fan out into first/last/initial combinations with the common
/// separators. Deterministic and de-duplicated, best-shapes-first.
fn handle_permutations(tokens: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    match tokens {
        [] => return out,
        [only] => {
            out.push(only.clone());
            return out;
        }
        _ => {}
    }
    let f = tokens[0].as_str();
    let l = tokens[tokens.len() - 1].as_str();
    let fi = initial(f);
    let li = initial(l);

    // Primary — the shapes that dominate real-world account handles.
    for h in [
        format!("{f}.{l}"),
        format!("{f}{l}"),
        format!("{fi}{l}"),
        format!("{f}_{l}"),
        format!("{f}{li}"),
    ] {
        out.push(h);
    }
    // Secondary — reversed and punctuation-joined variants.
    for h in [
        format!("{l}.{f}"),
        format!("{l}{f}"),
        format!("{fi}.{l}"),
        format!("{f}-{l}"),
        format!("{l}_{f}"),
    ] {
        out.push(h);
    }
    // Middle-name blends, when a middle token is present.
    if tokens.len() >= 3 {
        let m = tokens[1].as_str();
        let mi = initial(m);
        for h in [
            format!("{f}{m}{l}"),
            format!("{f}{mi}{l}"),
            format!("{fi}{mi}{l}"),
        ] {
            out.push(h);
        }
    }

    // Stable de-dup, first-occurrence (priority) order preserved.
    let mut seen = HashSet::new();
    out.retain(|h| seen.insert(h.clone()));
    out
}

/// Distinct query-able formats of a phone number: the raw form, digits-only,
/// the AU E.164 normalisation (when it applies), and a `+`-prefixed
/// international form. De-dup at the end collapses any that coincide.
fn phone_formats(raw: &str) -> Vec<(String, Origin)> {
    let mut out: Vec<(String, Origin)> = vec![(raw.trim().to_string(), Origin::Seed)];
    let digits = crate::util::str_util::ascii_digits(raw);
    if !digits.is_empty() {
        out.push((digits.clone(), Origin::PhoneFormat));
        // A plausibly-international number (country code + subscriber) also gets
        // a `+`-prefixed form, which is how many corpora store E.164.
        if digits.len() >= 11 {
            out.push((format!("+{digits}"), Origin::PhoneFormat));
        }
    }
    if let Some(norm) = crate::util::address_au::normalise_phone(raw) {
        out.push((norm, Origin::PhoneFormat));
    }
    out
}

/// Push a breach query (and, for login-indexable fields, a stealer query) for
/// `value`. Blank values are dropped. Stealer-indexability is the shared
/// [`oathnet::stealer_indexable`] rule.
fn add(
    out: &mut Vec<BatchQuery>,
    opts: &BatchOptions,
    field: &'static str,
    value: &str,
    origin: Origin,
) {
    push_one(out, Surface::Breach, field, value, origin);
    if opts.include_stealer && oathnet::stealer_indexable(field) {
        push_one(out, Surface::Stealer, field, value, origin);
    }
}

/// Push a breach-only query for `value`.
fn add_breach(out: &mut Vec<BatchQuery>, field: &'static str, value: &str, origin: Origin) {
    push_one(out, Surface::Breach, field, value, origin);
}

fn push_one(
    out: &mut Vec<BatchQuery>,
    surface: Surface,
    field: &'static str,
    value: &str,
    origin: Origin,
) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    out.push(BatchQuery {
        surface,
        field,
        value: value.to_string(),
        origin,
    });
}

fn gen_email(out: &mut Vec<BatchQuery>, opts: &BatchOptions, native: &'static str, v: &str) {
    add(out, opts, native, v, Origin::Seed);
    if let Some((local, domain)) = v.split_once('@') {
        let local = local.trim();
        let domain = domain.trim().to_ascii_lowercase();
        if local.len() >= 2 {
            add(out, opts, FIELD_USERNAME, local, Origin::EmailLocalPart);
            if opts.permute_handles {
                for h in handle_permutations(&name_tokens(local)) {
                    add(out, opts, FIELD_USERNAME, &h, Origin::Handle);
                }
            }
        }
        // Only pivot on a plausibly-real domain: a free provider is noise, and a
        // malformed host (no dot, or a stray `@` from a double-`@` address) is
        // not a domain worth a query. The dot check also subsumes "non-empty".
        if domain.contains('.') && !domain.contains('@') && !is_freemail(&domain) {
            add_breach(out, FIELD_DOMAIN, &domain, Origin::EmailDomain);
        }
    }
}

fn gen_username(out: &mut Vec<BatchQuery>, opts: &BatchOptions, native: &'static str, v: &str) {
    add(out, opts, native, v, Origin::Seed);
    if opts.permute_handles {
        for h in handle_permutations(&name_tokens(v)) {
            add(out, opts, native, &h, Origin::Handle);
        }
    }
    if opts.synthesize_emails {
        for d in FREEMAIL {
            add(out, opts, FIELD_EMAIL, &format!("{v}@{d}"), Origin::EmailCandidate);
        }
    }
}

fn gen_name(out: &mut Vec<BatchQuery>, opts: &BatchOptions, native: &'static str, v: &str) {
    // Free-text name search is breach-only (the stealer corpus has no name index).
    add_breach(out, native, v, Origin::Seed);
    if !opts.permute_handles {
        return;
    }
    let handles = handle_permutations(&name_tokens(v));
    for h in &handles {
        add(out, opts, FIELD_USERNAME, h, Origin::Handle);
    }
    if opts.synthesize_emails {
        for h in &handles {
            for d in FREEMAIL {
                add(out, opts, FIELD_EMAIL, &format!("{h}@{d}"), Origin::EmailCandidate);
            }
        }
    }
}

fn gen_domain(out: &mut Vec<BatchQuery>, opts: &BatchOptions, native: &'static str, v: &str) {
    let d = v.trim().to_ascii_lowercase();
    add_breach(out, native, &d, Origin::Seed);
    if opts.synthesize_emails && !is_freemail(&d) {
        for role in ROLE_LOCALPARTS {
            add(out, opts, FIELD_EMAIL, &format!("{role}@{d}"), Origin::EmailCandidate);
        }
    }
}

/// Generate the full, de-duplicated batch of OathNet queries for `value`
/// interpreted as `kind`.
///
/// Returns an empty vec for a blank `value`, or for a `kind` OathNet does not
/// index (per [`oathnet::selector_field`]). See the [module docs](self) for the
/// full list of guarantees the returned vec upholds.
///
/// # Examples
///
/// An email seed fans out across surfaces, derived fields, and handle shapes:
///
/// ```
/// use huntsman_search_engine::util::oathnet_batch::{generate, BatchOptions, Surface};
/// use huntsman_search_engine::core::scan::TargetKind;
///
/// let plan = generate(TargetKind::Email, "jane.doe@example.com", &BatchOptions::default());
///
/// // The seed is searched first, on both corpora.
/// assert_eq!(plan[0].field, "email");
/// assert_eq!(plan[0].value, "jane.doe@example.com");
/// assert!(plan.iter().any(|q| q.surface == Surface::Stealer));
///
/// // The local part fans out into username handles — a "large array".
/// assert!(plan.iter().any(|q| q.field == "username" && q.value == "jdoe"));
/// assert!(plan.len() > 10);
/// ```
///
/// `max_queries` caps the plan, keeping the highest-priority queries:
///
/// ```
/// use huntsman_search_engine::util::oathnet_batch::{generate, BatchOptions};
/// use huntsman_search_engine::core::scan::TargetKind;
///
/// let opts = BatchOptions { max_queries: 3, ..BatchOptions::default() };
/// let plan = generate(TargetKind::Email, "jane.doe@example.com", &opts);
/// assert_eq!(plan.len(), 3);
/// ```
#[must_use]
pub fn generate(kind: TargetKind, value: &str, opts: &BatchOptions) -> Vec<BatchQuery> {
    let mut out = Vec::new();
    let v = value.trim();
    if v.is_empty() {
        return out;
    }
    // The seed's native selector field is the single-sourced kind→field mapping;
    // `None` means OathNet does not index this kind, so there is nothing to do.
    let Some(native) = oathnet::selector_field(kind) else {
        return out;
    };
    match kind {
        TargetKind::Email => gen_email(&mut out, opts, native, v),
        TargetKind::Username => gen_username(&mut out, opts, native, v),
        TargetKind::FullName => gen_name(&mut out, opts, native, v),
        TargetKind::Phone => {
            for (fmt, origin) in phone_formats(v) {
                add_breach(&mut out, native, &fmt, origin);
            }
        }
        TargetKind::IpAddress => add_breach(&mut out, native, v, Origin::Seed),
        TargetKind::Domain => gen_domain(&mut out, opts, native, v),
        // `native` is `Some` only for the kinds above, so reaching here means
        // `selector_field` learned a kind `generate` hasn't — a single-source
        // drift. Surface it in tests/debug; no-op (drop the kind) in release.
        _ => debug_assert!(
            false,
            "oathnet::selector_field returned Some for {kind:?} but \
             oathnet_batch::generate does not handle it",
        ),
    }

    // Collapse exact (surface, field, lowercased-value) duplicates, keeping the
    // first (highest-priority) occurrence.
    let mut seen = HashSet::new();
    out.retain(|q| seen.insert((q.surface, q.field, q.value.to_lowercase())));

    if opts.max_queries > 0 && out.len() > opts.max_queries {
        out.truncate(opts.max_queries);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count_surface(qs: &[BatchQuery], s: Surface) -> usize {
        qs.iter().filter(|q| q.surface == s).count()
    }

    fn has(qs: &[BatchQuery], s: Surface, field: &str, value: &str) -> bool {
        qs.iter()
            .any(|q| q.surface == s && q.field == field && q.value == value)
    }

    #[test]
    fn email_seed_fans_out_across_surfaces_fields_and_handles() {
        let qs = generate(
            TargetKind::Email,
            "john.doe@example.com",
            &BatchOptions::default(),
        );
        // Direct email on both surfaces.
        assert!(has(&qs, Surface::Breach, "email", "john.doe@example.com"));
        assert!(has(&qs, Surface::Stealer, "email", "john.doe@example.com"));
        // Local part as a username on both surfaces.
        assert!(has(&qs, Surface::Breach, "username", "john.doe"));
        assert!(has(&qs, Surface::Stealer, "username", "john.doe"));
        // Handle permutations from the local part.
        assert!(has(&qs, Surface::Breach, "username", "johndoe"));
        assert!(has(&qs, Surface::Breach, "username", "jdoe"));
        // Domain pivot (breach only).
        assert!(has(&qs, Surface::Breach, "domain", "example.com"));
        // A "large array": comfortably into the double digits.
        assert!(qs.len() >= 15, "expected a large batch, got {}", qs.len());
    }

    #[test]
    fn freemail_domain_is_not_searched_as_a_domain() {
        let qs = generate(TargetKind::Email, "bob@gmail.com", &BatchOptions::default());
        assert!(
            !qs.iter().any(|q| q.field == "domain"),
            "gmail.com must not become a domain search"
        );
        // But the email + handle pivots still generate.
        assert!(has(&qs, Surface::Breach, "email", "bob@gmail.com"));
        assert!(has(&qs, Surface::Breach, "username", "bob"));
    }

    #[test]
    fn name_seed_generates_q_plus_handles() {
        let qs = generate(TargetKind::FullName, "John Doe", &BatchOptions::default());
        // Free-text name search is breach-only.
        assert!(has(&qs, Surface::Breach, "q", "John Doe"));
        assert!(!qs.iter().any(|q| q.surface == Surface::Stealer && q.field == "q"));
        // Handle permutations on both surfaces.
        assert!(has(&qs, Surface::Breach, "username", "john.doe"));
        assert!(has(&qs, Surface::Stealer, "username", "jdoe"));
        assert!(qs.len() >= 12, "expected a large batch, got {}", qs.len());
    }

    #[test]
    fn middle_name_adds_blended_handles() {
        let qs = generate(TargetKind::FullName, "John Michael Doe", &BatchOptions::default());
        assert!(has(&qs, Surface::Breach, "username", "johnmichaeldoe"));
        assert!(has(&qs, Surface::Breach, "username", "jmdoe"));
    }

    #[test]
    fn phone_seed_expands_distinct_formats_breach_only() {
        let qs = generate(TargetKind::Phone, "+61 412 345 678", &BatchOptions::default());
        // Raw, digits-only, and AU E.164 forms are all present and distinct.
        assert!(has(&qs, Surface::Breach, "phone", "+61 412 345 678"));
        assert!(has(&qs, Surface::Breach, "phone", "61412345678"));
        assert!(has(&qs, Surface::Breach, "phone", "+61412345678"));
        // Never stealer.
        assert_eq!(count_surface(&qs, Surface::Stealer), 0);
    }

    #[test]
    fn domain_and_ip_seeds_are_breach_only_singletons_by_default() {
        let dom = generate(TargetKind::Domain, "Example.COM", &BatchOptions::default());
        assert_eq!(dom.len(), 1);
        assert!(has(&dom, Surface::Breach, "domain", "example.com")); // lowercased

        let ip = generate(TargetKind::IpAddress, "8.8.8.8", &BatchOptions::default());
        assert_eq!(ip.len(), 1);
        assert!(has(&ip, Surface::Breach, "ip", "8.8.8.8"));
    }

    #[test]
    fn synthesize_emails_opt_crosses_handles_with_providers() {
        let opts = BatchOptions {
            synthesize_emails: true,
            ..BatchOptions::default()
        };
        let qs = generate(TargetKind::Domain, "acme.io", &opts);
        assert!(has(&qs, Surface::Breach, "email", "admin@acme.io"));
        assert!(has(&qs, Surface::Stealer, "email", "info@acme.io"));

        let names = generate(TargetKind::FullName, "John Doe", &opts);
        assert!(names.iter().any(|q| q.field == "email" && q.value.ends_with("@gmail.com")));
    }

    #[test]
    fn include_stealer_false_drops_every_stealer_query() {
        let opts = BatchOptions {
            include_stealer: false,
            ..BatchOptions::default()
        };
        let qs = generate(TargetKind::Email, "john.doe@example.com", &opts);
        assert_eq!(count_surface(&qs, Surface::Stealer), 0);
        assert!(count_surface(&qs, Surface::Breach) > 0);
    }

    #[test]
    fn no_permute_keeps_only_direct_selectors() {
        let opts = BatchOptions {
            permute_handles: false,
            ..BatchOptions::default()
        };
        let qs = generate(TargetKind::Email, "john.doe@example.com", &opts);
        // Direct email + local-part username (+ stealer) + domain, but no
        // permutation-origin handles.
        assert!(!qs.iter().any(|q| q.origin == Origin::Handle));
        assert!(has(&qs, Surface::Breach, "username", "john.doe"));
    }

    #[test]
    fn max_queries_truncates_after_dedup_preserving_priority() {
        let opts = BatchOptions {
            max_queries: 5,
            ..BatchOptions::default()
        };
        let qs = generate(TargetKind::Email, "john.doe@example.com", &opts);
        assert_eq!(qs.len(), 5);
        // The seed's own email query is highest priority and survives the cap.
        assert_eq!(qs[0].origin, Origin::Seed);
        assert!(has(&qs, Surface::Breach, "email", "john.doe@example.com"));
    }

    #[test]
    fn output_is_deterministic_and_duplicate_free() {
        let a = generate(TargetKind::Email, "john.doe@example.com", &BatchOptions::default());
        let b = generate(TargetKind::Email, "john.doe@example.com", &BatchOptions::default());
        assert_eq!(a, b, "same input must yield identical output");
        // No exact (surface, field, value) duplicate survives.
        let mut seen = HashSet::new();
        for q in &a {
            assert!(
                seen.insert((q.surface, q.field, q.value.clone())),
                "duplicate query leaked: {q:?}"
            );
        }
    }

    #[test]
    fn opaque_handle_does_not_spuriously_permute() {
        // A single atomic token can't be recombined — it yields just itself, so
        // the only username query is the seed (deduped against the permutation).
        let qs = generate(TargetKind::Username, "xz", &BatchOptions::default());
        let usernames: Vec<&str> = qs
            .iter()
            .filter(|q| q.surface == Surface::Breach && q.field == "username")
            .map(|q| q.value.as_str())
            .collect();
        assert_eq!(usernames, vec!["xz"]);
    }

    #[test]
    fn blank_and_unindexed_kinds_yield_nothing() {
        assert!(generate(TargetKind::Email, "   ", &BatchOptions::default()).is_empty());
        assert!(generate(TargetKind::Url, "https://x.com", &BatchOptions::default()).is_empty());
    }

    #[test]
    fn seed_field_matches_shared_selector_vocabulary() {
        // The seed query's field must come from the single-sourced
        // `oathnet::selector_field`, not a private re-encoding.
        for (kind, value) in [
            (TargetKind::Email, "a@b.com"),
            (TargetKind::Username, "alice"),
            (TargetKind::FullName, "John Doe"),
            (TargetKind::Phone, "+61412345678"),
            (TargetKind::IpAddress, "8.8.8.8"),
            (TargetKind::Domain, "acme.io"),
        ] {
            let qs = generate(kind, value, &BatchOptions::default());
            let seed = qs
                .iter()
                .find(|q| q.origin == Origin::Seed)
                .expect("every indexed kind emits a seed query");
            assert_eq!(Some(seed.field), oathnet::selector_field(kind));
        }
    }

    #[test]
    fn surface_paths_match_oathnet_constants() {
        assert_eq!(Surface::Breach.path(), oathnet::paths::BREACH);
        assert_eq!(Surface::Stealer.path(), oathnet::paths::STEALER);
    }

    // ── Invariants the module docs promise, checked across every indexed kind ──

    /// Every kind OathNet indexes, with a representative seed and the most
    /// expansive options, so the structural invariants are exercised broadly.
    fn all_kind_cases() -> [(TargetKind, &'static str); 6] {
        [
            (TargetKind::Email, "jane.doe@example.com"),
            (TargetKind::Username, "jane.doe"),
            (TargetKind::FullName, "Jane Q Doe"),
            (TargetKind::Phone, "+61 412 345 678"),
            (TargetKind::IpAddress, "8.8.8.8"),
            (TargetKind::Domain, "acme.io"),
        ]
    }

    #[test]
    fn every_query_is_well_formed() {
        const FIELDS: &[&str] = &["email", "username", "phone", "domain", "ip", "q"];
        let opts = BatchOptions {
            synthesize_emails: true,
            ..BatchOptions::default()
        };
        for (kind, value) in all_kind_cases() {
            let qs = generate(kind, value, &opts);
            assert!(!qs.is_empty(), "{kind:?} produced no queries");
            for q in &qs {
                assert!(
                    FIELDS.contains(&q.field),
                    "{kind:?} produced an unknown field {:?}",
                    q.field
                );
                assert_eq!(q.value, q.value.trim(), "value not trimmed: {:?}", q.value);
                assert!(!q.value.is_empty(), "empty value for {kind:?}");
            }
        }
    }

    #[test]
    fn seed_queries_precede_every_derived_query() {
        for (kind, value) in all_kind_cases() {
            let qs = generate(kind, value, &BatchOptions::default());
            let last_seed = qs.iter().rposition(|q| q.origin == Origin::Seed);
            let first_derived = qs.iter().position(|q| q.origin != Origin::Seed);
            if let (Some(ls), Some(fd)) = (last_seed, first_derived) {
                assert!(ls < fd, "a seed query followed a derived one for {kind:?}");
            }
        }
    }

    #[test]
    fn every_stealer_query_mirrors_a_breach_query() {
        // `add` always pushes breach first, then (when indexable) stealer — so a
        // stealer query must always have a breach twin on the same field+value.
        let opts = BatchOptions {
            synthesize_emails: true,
            ..BatchOptions::default()
        };
        for (kind, value) in all_kind_cases() {
            let qs = generate(kind, value, &opts);
            for s in qs.iter().filter(|q| q.surface == Surface::Stealer) {
                assert!(
                    qs.iter().any(|b| b.surface == Surface::Breach
                        && b.field == s.field
                        && b.value == s.value),
                    "stealer query without a breach twin: {s:?}"
                );
            }
        }
    }

    // ── Edge cases ───────────────────────────────────────────────────────────

    #[test]
    fn malformed_emails_do_not_panic_or_emit_junk_domains() {
        // No '@': only the email selector applies — no local/domain derivation.
        let q1 = generate(TargetKind::Email, "not-an-email", &BatchOptions::default());
        assert!(q1.iter().all(|q| q.field == "email"));

        // Double '@' leaves a stray '@' in the host — must NOT become a domain query.
        let q2 = generate(TargetKind::Email, "a@@b.com", &BatchOptions::default());
        assert!(
            q2.iter().all(|q| q.field != "domain"),
            "a stray-@ host must not be searched as a domain"
        );

        // Empty local part: no username derivation, no panic.
        let q3 = generate(TargetKind::Email, "@example.com", &BatchOptions::default());
        assert!(q3.iter().any(|q| q.field == "email"));

        // A host with no dot is not a real domain.
        let q4 = generate(TargetKind::Email, "x@localhost", &BatchOptions::default());
        assert!(q4.iter().all(|q| q.field != "domain"));
    }

    #[test]
    fn non_ascii_name_yields_ascii_handles_only() {
        // Non-ASCII chars act as separators (handles are ASCII), so the name
        // still yields ASCII handle permutations — accents are dropped, not
        // transliterated (documented limitation), and nothing panics.
        let qs = generate(TargetKind::FullName, "Renée Dubois", &BatchOptions::default());
        assert!(qs.iter().any(|q| q.field == "username"));
        // Only the free-text `q` query may carry the original non-ASCII value.
        assert!(qs.iter().all(|q| q.field == "q" || q.value.is_ascii()));
    }

    #[test]
    fn max_queries_boundaries() {
        let seed = "jane.doe@example.com";
        let n = generate(TargetKind::Email, seed, &BatchOptions::default()).len();
        let cap = |m| {
            generate(
                TargetKind::Email,
                seed,
                &BatchOptions {
                    max_queries: m,
                    ..BatchOptions::default()
                },
            )
        };
        assert_eq!(cap(0).len(), n, "0 means no cap");
        assert_eq!(cap(n + 100).len(), n, "a cap above the plan size is a no-op");
        let one = cap(1);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].origin, Origin::Seed, "the survivor is the seed query");
    }

    #[test]
    fn leading_and_trailing_whitespace_is_trimmed() {
        let qs = generate(TargetKind::Email, "  jane@example.com  ", &BatchOptions::default());
        assert!(has(&qs, Surface::Breach, "email", "jane@example.com"));
        assert!(qs.iter().all(|q| q.value == q.value.trim()));
    }
}
