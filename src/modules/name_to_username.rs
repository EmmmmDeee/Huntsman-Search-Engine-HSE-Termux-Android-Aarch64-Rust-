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
const MAX_DERIVATIONS: usize = 12;

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
        let fi = &f[..f.len().min(1)];

        out.push(format!("{f}{l}"));
        out.push(format!("{f}.{l}"));
        out.push(format!("{f}_{l}"));
        out.push(format!("{fi}{l}"));
        out.push(format!("{f}{}", &l[..l.len().min(1)]));
        out.push(format!("{l}{f}"));
        out.push(format!("{l}.{f}"));

        if let Some(ref m) = p.middle {
            let mi = &m[..m.len().min(1)];
            out.push(format!("{f}{mi}{l}"));
            out.push(format!("{fi}{mi}{l}"));
        }
    }
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
        let parts = parse_name_parts("Jane Leigh Public");
        let usernames = derive_usernames(&parts);
        assert!(usernames.contains(&"janelpublic".to_string()));
        assert!(usernames.contains(&"jlpublic".to_string()));
    }

    #[test]
    fn single_word_returns_empty() {
        assert!(parse_name_parts("Jane").is_empty());
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
