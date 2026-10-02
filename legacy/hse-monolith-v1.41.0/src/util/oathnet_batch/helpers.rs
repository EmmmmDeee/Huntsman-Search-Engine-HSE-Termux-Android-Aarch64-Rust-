//! Pure helper functions: token splitting, handle permutation, phone
//! normalisation, and the free-mail check.

use std::collections::HashSet;

use super::types::Origin;

/// The handful of providers to **synthesise candidate emails against** when
/// `synthesize_emails` is set (`{handle}@{provider}`). Deliberately a SMALL
/// curated set, NOT the full freemail list (`util::domains::FREEMAIL`, ~60): each
/// provider multiplies the breach-query fan-out per handle, so this is the
/// high-yield head of the distribution, kept tight to bound the query budget.
/// Detection ("is this a freemail domain?") is a separate concern — see
/// [`is_freemail`], which delegates to the comprehensive canonical list.
pub(super) const SYNTH_EMAIL_PROVIDERS: &[&str] = &[
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "icloud.com",
    "proton.me",
    "aol.com",
];

/// Role local-parts crossed with a seed domain when `synthesize_emails` is set.
pub(super) const ROLE_LOCALPARTS: &[&str] = &["admin", "info", "contact", "support", "sales"];

/// True if `domain` is a consumer mailbox provider that must be SKIPPED as a
/// `domain` search (querying e.g. `gmail.com` as a domain returns the whole
/// provider corpus — noise, not signal). Delegates to the single authoritative
/// list in [`crate::util::domains::is_freemail`] (≈60 providers, incl. AU ISPs
/// and webmail) rather than re-curating a second copy here — detection wants
/// breadth, so the narrow synthesis set above would silently miss most providers.
pub(super) fn is_freemail(domain: &str) -> bool {
    crate::util::domains::is_freemail(&domain.trim().to_ascii_lowercase())
}

/// First character of a non-empty token (used for initials).
fn initial(token: &str) -> char {
    token.chars().next().unwrap_or('x')
}

/// Split a raw string into ASCII-lowercased alphabetic tokens of length ≥ 2.
/// Digits and punctuation are separators, so `"john.doe99"` → `["john","doe"]`.
pub(super) fn name_tokens(raw: &str) -> Vec<String> {
    raw.split(|c: char| !c.is_ascii_alphabetic())
        .filter(|t| t.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Generate the handle shapes real accounts use from a set of name tokens.
/// A single opaque token yields only itself (it can't be recombined); two or
/// more tokens fan out into first/last/initial combinations with the common
/// separators. Deterministic and de-duplicated, best-shapes-first.
pub(super) fn handle_permutations(tokens: &[String]) -> Vec<String> {
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
pub(super) fn phone_formats(raw: &str) -> Vec<(String, Origin)> {
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
