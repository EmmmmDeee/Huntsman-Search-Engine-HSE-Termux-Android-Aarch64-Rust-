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
//! The generator is **pure** (no IO, no quota) so the full plan can be previewed
//! for free and is exhaustively unit-testable; the CLI layer is what actually
//! dispatches it (and is what spends OathNet credits). Output is deterministic:
//! the seed's own queries come first, then derived ones in a fixed order, with
//! exact `(surface, field, lowercased-value)` duplicates collapsed.

use std::collections::HashSet;

use crate::core::scan::TargetKind;
use crate::util::oathnet::paths;

/// An OathNet search surface a generated query targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Surface {
    /// Breach corpus (`/service/v2/breach/search`).
    Breach,
    /// Stealer-log corpus (`/service/v2/stealer/search`).
    Stealer,
}

impl Surface {
    /// The `util::oathnet` path constant this surface dispatches against.
    #[must_use]
    pub fn path(self) -> &'static str {
        match self {
            Self::Breach => paths::BREACH,
            Self::Stealer => paths::STEALER,
        }
    }

    /// Short human/JSON label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Breach => "breach",
            Self::Stealer => "stealer",
        }
    }
}

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
    pub surface: Surface,
    /// OathNet selector field (`email`, `username`, `phone`, `domain`, `ip`, `q`).
    pub field: &'static str,
    pub value: String,
    pub origin: Origin,
}

/// Knobs controlling how aggressively the seed is expanded.
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

/// True for selectors the stealer corpus indexes (it is keyed on login
/// credentials). Phone/name/domain/IP are breach-only, matching the
/// `oathnet_pro` module's per-surface routing.
fn stealer_indexable(field: &str) -> bool {
    matches!(field, "email" | "username")
}

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
/// `value`. Blank values are dropped.
fn add(out: &mut Vec<BatchQuery>, opts: &BatchOptions, field: &'static str, value: &str, origin: Origin) {
    push_one(out, Surface::Breach, field, value, origin);
    if opts.include_stealer && stealer_indexable(field) {
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

fn gen_email(out: &mut Vec<BatchQuery>, opts: &BatchOptions, v: &str) {
    add(out, opts, "email", v, Origin::Seed);
    if let Some((local, domain)) = v.split_once('@') {
        let local = local.trim();
        let domain = domain.trim().to_ascii_lowercase();
        if local.len() >= 2 {
            add(out, opts, "username", local, Origin::EmailLocalPart);
            if opts.permute_handles {
                for h in handle_permutations(&name_tokens(local)) {
                    add(out, opts, "username", &h, Origin::Handle);
                }
            }
        }
        // A domain search on a free provider is noise; everything else is a
        // legitimate org-wide pivot.
        if !domain.is_empty() && !is_freemail(&domain) {
            add_breach(out, "domain", &domain, Origin::EmailDomain);
        }
    }
}

fn gen_username(out: &mut Vec<BatchQuery>, opts: &BatchOptions, v: &str) {
    add(out, opts, "username", v, Origin::Seed);
    if opts.permute_handles {
        for h in handle_permutations(&name_tokens(v)) {
            add(out, opts, "username", &h, Origin::Handle);
        }
    }
    if opts.synthesize_emails {
        for d in FREEMAIL {
            add(out, opts, "email", &format!("{v}@{d}"), Origin::EmailCandidate);
        }
    }
}

fn gen_name(out: &mut Vec<BatchQuery>, opts: &BatchOptions, v: &str) {
    // Free-text name search is breach-only (the stealer corpus has no name index).
    add_breach(out, "q", v, Origin::Seed);
    if !opts.permute_handles {
        return;
    }
    let handles = handle_permutations(&name_tokens(v));
    for h in &handles {
        add(out, opts, "username", h, Origin::Handle);
    }
    if opts.synthesize_emails {
        for h in &handles {
            for d in FREEMAIL {
                add(out, opts, "email", &format!("{h}@{d}"), Origin::EmailCandidate);
            }
        }
    }
}

fn gen_domain(out: &mut Vec<BatchQuery>, opts: &BatchOptions, v: &str) {
    let d = v.trim().to_ascii_lowercase();
    add_breach(out, "domain", &d, Origin::Seed);
    if opts.synthesize_emails && !is_freemail(&d) {
        for role in ROLE_LOCALPARTS {
            add(out, opts, "email", &format!("{role}@{d}"), Origin::EmailCandidate);
        }
    }
}

/// Generate the full, de-duplicated batch of OathNet queries for `value`
/// interpreted as `kind`. Returns an empty vec for a blank value or a kind
/// OathNet does not index.
#[must_use]
pub fn generate(kind: TargetKind, value: &str, opts: &BatchOptions) -> Vec<BatchQuery> {
    let mut out = Vec::new();
    let v = value.trim();
    if v.is_empty() {
        return out;
    }
    match kind {
        TargetKind::Email => gen_email(&mut out, opts, v),
        TargetKind::Username => gen_username(&mut out, opts, v),
        TargetKind::FullName => gen_name(&mut out, opts, v),
        TargetKind::Phone => {
            for (fmt, origin) in phone_formats(v) {
                add_breach(&mut out, "phone", &fmt, origin);
            }
        }
        TargetKind::IpAddress => add_breach(&mut out, "ip", v, Origin::Seed),
        TargetKind::Domain => gen_domain(&mut out, opts, v),
        // OathNet has no index for the remaining kinds (URL, ASN, coords, …).
        _ => {}
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
    fn surface_paths_match_oathnet_constants() {
        assert_eq!(Surface::Breach.path(), paths::BREACH);
        assert_eq!(Surface::Stealer.path(), paths::STEALER);
    }
}
