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
const MAX_DERIVATIONS: usize = 16;

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

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Username];
        KINDS
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
    // Split on whitespace, then fold each token to an ASCII handle stem
    // (diacritics → base letter, apostrophes/hyphens dropped): "José Müller" →
    // first "jose", last "muller"; "O'Brien-Walsh" → "obrienwalsh". Real handles
    // are ASCII, so deriving from the raw Unicode produced un-matchable garbage.
    let words: Vec<String> = raw
        .split_whitespace()
        .map(crate::util::str_util::fold_ascii_lower)
        .filter(|w| !w.is_empty())
        .collect();
    if words.len() < 2 {
        return Vec::new();
    }
    let first = words[0].clone();
    let last = words[words.len() - 1].clone();
    let middle = if words.len() >= 3 {
        Some(words[1].clone())
    } else {
        None
    };
    vec![NameParts {
        first,
        middle,
        last,
    }]
}

/// First ASCII char of a folded token (safe: folded tokens are pure ASCII).
fn initial(s: &str) -> &str {
    &s[..s.len().min(1)]
}

fn derive_usernames(parts_list: &[NameParts]) -> Vec<String> {
    let mut raw: Vec<String> = Vec::new();
    for p in parts_list {
        let f = &p.first;
        let l = &p.last;
        let fi = initial(f);
        let li = initial(l);
        // Ordered most→least common for real handles so the highest-value
        // candidates survive the MAX_DERIVATIONS cap.
        raw.extend([
            format!("{f}.{l}"),  // john.doe
            format!("{f}{l}"),   // johndoe
            format!("{fi}{l}"),  // jdoe
            format!("{f}_{l}"),  // john_doe
            format!("{f}{li}"),  // johnd
            format!("{fi}.{l}"), // j.doe
            format!("{l}.{f}"),  // doe.john
            format!("{l}{f}"),   // doejohn
            format!("{f}-{l}"),  // john-doe
            format!("{l}{fi}"),  // doej
            format!("{l}_{f}"),  // doe_john
            format!("{fi}{li}"), // jd
        ]);
        if let Some(ref m) = p.middle {
            let mi = initial(m);
            raw.extend([
                format!("{f}{mi}{l}"),   // johnmdoe
                format!("{fi}{mi}{l}"),  // jmdoe
                format!("{f}.{m}.{l}"),  // john.michael.doe
                format!("{fi}{mi}{li}"), // jmd
            ]);
        }
    }
    // Dedup preserving the priority order, drop trivially-short stubs, bound.
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(MAX_DERIVATIONS);
    for u in raw {
        if u.len() >= 2 && seen.insert(u.clone()) {
            out.push(u);
            if out.len() >= MAX_DERIVATIONS {
                break;
            }
        }
    }
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
    fn single_word_returns_empty() {
        assert!(parse_name_parts("Jordan").is_empty());
    }

    #[test]
    fn folds_diacritics_so_handles_are_ascii() {
        // "José Müller" must derive ASCII handles, not "josé…"/"müller…".
        let parts = parse_name_parts("José Müller");
        assert_eq!(parts[0].first, "jose");
        assert_eq!(parts[0].last, "muller");
        let usernames = derive_usernames(&parts);
        assert!(usernames.contains(&"jose.muller".to_string()));
        assert!(usernames.contains(&"josemuller".to_string()));
        assert!(usernames.contains(&"jmuller".to_string()));
        assert!(usernames.iter().all(|u| u.is_ascii()));
        // Apostrophes/hyphens fold away within a token.
        let ob = parse_name_parts("O'Brien-Walsh Casey");
        assert_eq!(ob[0].first, "obrienwalsh");
    }

    #[test]
    fn emits_namint_style_extra_patterns() {
        let usernames = derive_usernames(&parse_name_parts("John Doe"));
        for expected in ["j.doe", "doej", "jd", "doe_john", "john-doe", "doe.john"] {
            assert!(
                usernames.contains(&expected.to_string()),
                "missing pattern {expected}: {usernames:?}"
            );
        }
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
