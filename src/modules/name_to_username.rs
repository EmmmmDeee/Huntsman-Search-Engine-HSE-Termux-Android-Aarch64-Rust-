//! Name-to-username derivation — generate plausible usernames from a
//! FullName target and emit them as Username entities for downstream
//! modules (keybase, proxycurl, github_user, username_search).
//!
//! No network calls. Pure string transformation. Priority 97 so
//! derived usernames are available in the seed round for expansion.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "name_to_username";
// Raised from 12 to fit the expanded real-world handle pattern set below.
// Still a hard, bounded cap (the seed round emits at most this many Username
// entities per name, which the visited-set then dedups) — keeps the username
// sweep within the per-scan budget on a 4 GB device. A digit-suffix brute
// (00–99 per base) was rejected: it would explode to ~900 candidates × 159
// sites and breach the memory/quota ceiling.
const MAX_DERIVATIONS: usize = 28;

/// First Unicode scalar of `s` as a `String` — char-safe replacement for the
/// previous `&s[..s.len().min(1)]`, which byte-sliced and PANICKED on any
/// non-ASCII name (e.g. `Çağla`, `Øyvind`, `José`): `len().min(1)` cut 1 byte
/// out of a multi-byte codepoint. Real OSINT targets routinely have non-ASCII
/// names, so this was a live crash, not a theoretical one.
fn first_char(s: &str) -> String {
    s.chars().next().map(String::from).unwrap_or_default()
}

pub struct NameToUsername;

#[async_trait]
impl Module for NameToUsername {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Derive plausible usernames from full name (first.last, flast, firstl, etc.)"
    }
    fn priority(&self) -> u8 {
        97
    }
    fn is_passive(&self) -> bool {
        true
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let parts = parse_name_parts(&target.value);
        if parts.is_empty() {
            return Ok(result);
        }

        let usernames = derive_usernames(&parts);
        for u in usernames.iter().take(MAX_DERIVATIONS) {
            let mut e = Entity::new(EntityKind::Username, u, 0.35, &ctx.scan_id);
            e.tag("derived");
            e.tag("name-derived");
            e.add_evidence(
                Evidence::new(SRC, format!("Username '{}' derived from name", u))
                    .with_attr("source_name", &target.value),
            );
            result.push(e);
        }
        Ok(result)
    }
}

struct NameParts {
    first: String,
    middle: Option<String>,
    last: String,
}

fn parse_name_parts(raw: &str) -> Vec<NameParts> {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_alphabetic() || c.is_whitespace() || *c == '-')
        .collect();
    let words: Vec<&str> = cleaned.split_whitespace().collect();
    if words.len() < 2 {
        return Vec::new();
    }
    let first = words[0].to_lowercase();
    let last = words[words.len() - 1].to_lowercase();
    let middle = if words.len() >= 3 {
        Some(words[1].to_lowercase())
    } else {
        None
    };
    vec![NameParts {
        first,
        middle,
        last,
    }]
}

fn derive_usernames(parts_list: &[NameParts]) -> Vec<String> {
    let mut out = Vec::with_capacity(MAX_DERIVATIONS);
    for p in parts_list {
        let f = &p.first;
        let l = &p.last;
        let fi = first_char(f); // char-safe initial
        let li = first_char(l);

        // ── Core first+last patterns ──────────────────────────────────────
        out.push(format!("{f}{l}")); // jordanmeyer
        out.push(format!("{f}.{l}")); // jordan.meyer
        out.push(format!("{f}_{l}")); // jordan_meyer
        out.push(format!("{f}-{l}")); // jordan-meyer (hyphenated handles)
        // ── Initial + last / first + initial ──────────────────────────────
        out.push(format!("{fi}{l}")); // jmeyer
        out.push(format!("{fi}.{l}")); // j.meyer
        out.push(format!("{fi}_{l}")); // j_meyer
        out.push(format!("{f}{li}")); // jordanm
        // ── Last-first orderings (common on AU/EU platforms) ──────────────
        out.push(format!("{l}{f}")); // meyerjordan
        out.push(format!("{l}.{f}")); // meyer.jordan
        out.push(format!("{l}{fi}")); // meyerj
        out.push(format!("{l}_{f}")); // meyer_jordan
        // ── Bare components (single-handle accounts) ──────────────────────
        out.push(f.clone()); // jordan
        out.push(l.clone()); // meyer
        // ── Digit-suffixed handles — the single highest-yield real-world
        //    pattern the old generator missed entirely. Bounded to a tiny
        //    curated set (birth-year-ish + the ubiquitous trailing 1), NOT a
        //    00–99 brute force, to stay within the per-scan budget.
        out.push(format!("{f}{l}1"));
        out.push(format!("{fi}{l}1"));
        for yy in ["7", "23", "92", "99"] {
            out.push(format!("{f}{l}{yy}"));
        }

        // ── Middle-name permutations ──────────────────────────────────────
        if let Some(ref m) = p.middle {
            let mi = first_char(m);
            out.push(format!("{f}{mi}{l}")); // jordanlmeyer
            out.push(format!("{fi}{mi}{l}")); // jlmeyer
            out.push(format!("{f}.{m}.{l}")); // jordan.leigh.meyer
            out.push(format!("{f}{m}{l}")); // jordanleighmeyer
        }
    }
    // Drop empties (defensive: empty first/last yields no useful handle),
    // then sort+dedup so the bounded `take(MAX_DERIVATIONS)` downstream keeps
    // a stable, high-value prefix.
    out.retain(|u| u.len() >= 2);
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_standard_patterns() {
        let parts = parse_name_parts("Jordan Meyer");
        let usernames = derive_usernames(&parts);
        assert!(usernames.contains(&"jordanmeyer".to_string()));
        assert!(usernames.contains(&"jordan.meyer".to_string()));
        assert!(usernames.contains(&"jordan_meyer".to_string()));
        assert!(usernames.contains(&"jmeyer".to_string()));
        assert!(usernames.contains(&"jordanm".to_string()));
        assert!(usernames.contains(&"meyerjordan".to_string()));
    }

    #[test]
    fn three_part_name_includes_middle() {
        let parts = parse_name_parts("Jordan Leigh Meyer");
        let usernames = derive_usernames(&parts);
        assert!(usernames.contains(&"jordanlmeyer".to_string()));
        assert!(usernames.contains(&"jlmeyer".to_string()));
    }

    #[test]
    fn non_ascii_name_does_not_panic() {
        // Regression: the old `&first[..len().min(1)]` byte-slice panicked on
        // multi-byte first chars. These must derive handles without crashing.
        for name in ["Çağla Yılmaz", "Øyvind Ådne", "José Müller", "Renée Noël"] {
            let parts = parse_name_parts(name);
            let usernames = derive_usernames(&parts); // must not panic
            assert!(!usernames.is_empty(), "{name} should yield handles");
        }
    }

    #[test]
    fn expanded_patterns_cover_real_world_handles() {
        let parts = parse_name_parts("Jordan Meyer");
        let u = derive_usernames(&parts);
        // hyphen, digit-suffix, last-first, bare, initial-dot forms.
        for want in ["jordan-meyer", "jordanmeyer1", "meyerj", "jordan", "j.meyer"] {
            assert!(u.contains(&want.to_string()), "missing real-world handle: {want}");
        }
    }

    #[test]
    fn first_char_is_char_safe() {
        assert_eq!(first_char("çağla"), "ç");
        assert_eq!(first_char("jordan"), "j");
        assert_eq!(first_char(""), "");
    }

    #[test]
    fn single_word_returns_empty() {
        assert!(parse_name_parts("Jordan").is_empty());
    }

    #[test]
    fn bounded_output() {
        let parts = parse_name_parts("A B C D E F");
        let usernames = derive_usernames(&parts);
        assert!(usernames.len() <= MAX_DERIVATIONS);
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = NameToUsername;
        assert!(m.is_passive());
        assert!(m.accepts(&Target::new(TargetKind::FullName, "Jordan Meyer")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }
}
