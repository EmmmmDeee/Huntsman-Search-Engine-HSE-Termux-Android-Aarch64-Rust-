//! `hse batch` — a plaintext list of bulk queries per provider.
//!
//! Derives the selectors (emails, usernames, phones, domains, IPs, names) a
//! breach or stealer-log site can be asked about — from one seed, fanned out
//! by the same generator `oathnet-batch` uses, or from everything a stored
//! scan found — and renders them in the syntax each provider's bulk (or
//! single) search page accepts, one query per line, for the operator to paste
//! by hand when an API key is not an option. The provider table is
//! [`sites::SITES`]; `hse batch --site` narrows it.
//!
//! The output names providers by design: it is an operator's working list,
//! not a client deliverable, so over HTTP it is served by the operator
//! download path that does not genericise provider names.

pub mod sites;

use std::collections::HashSet;

use serde::Serialize;

use crate::core::entity::{Entity, EntityKind};
use crate::core::scan::TargetKind;
use crate::util::oathnet::{
    FIELD_DOMAIN, FIELD_EMAIL, FIELD_IP, FIELD_PHONE, FIELD_QUERY, FIELD_USERNAME,
};
use crate::util::oathnet_batch::{self, BatchOptions};
use sites::{LineSyntax, Site};

/// The kinds of value a breach site can be asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectorKind {
    Email,
    Username,
    Phone,
    Domain,
    Ip,
    Name,
}

impl SelectorKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Username => "username",
            Self::Phone => "phone",
            Self::Domain => "domain",
            Self::Ip => "ip",
            Self::Name => "name",
        }
    }
}

/// One thing to ask a provider about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Selector {
    pub kind: SelectorKind,
    pub value: String,
}

fn push_unique(
    out: &mut Vec<Selector>,
    seen: &mut HashSet<(SelectorKind, String)>,
    kind: SelectorKind,
    value: &str,
) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    if seen.insert((kind, value.to_ascii_lowercase())) {
        out.push(Selector {
            kind,
            value: value.to_string(),
        });
    }
}

/// Selectors fanned out from one seed: the seed itself, its derived fields
/// (an email's local part → username, its domain → domain) and the value
/// permutations the shared generator produces, de-duplicated across the
/// generator's surfaces (breach and stealer emit the same value twice).
#[must_use]
pub fn selectors_from_seed(kind: TargetKind, value: &str, opts: &BatchOptions) -> Vec<Selector> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for q in oathnet_batch::generate(kind, value, opts) {
        let kind = match q.field {
            FIELD_EMAIL => SelectorKind::Email,
            FIELD_USERNAME => SelectorKind::Username,
            FIELD_PHONE => SelectorKind::Phone,
            FIELD_DOMAIN => SelectorKind::Domain,
            FIELD_IP => SelectorKind::Ip,
            FIELD_QUERY => SelectorKind::Name,
            _ => continue,
        };
        push_unique(&mut out, &mut seen, kind, &q.value);
    }
    out
}

/// Selectors from what a scan found: every entity of a kind a breach site
/// indexes, in confidence order, without further fan-out (the scan already
/// did the expanding).
#[must_use]
pub fn selectors_from_entities(entities: &[Entity]) -> Vec<Selector> {
    let mut ranked: Vec<&Entity> = entities.iter().collect();
    ranked.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.value.cmp(&b.value))
    });
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for e in ranked {
        let kind = match e.kind {
            EntityKind::Email => SelectorKind::Email,
            EntityKind::Username => SelectorKind::Username,
            EntityKind::Phone => SelectorKind::Phone,
            EntityKind::Domain => SelectorKind::Domain,
            EntityKind::IpAddress => SelectorKind::Ip,
            EntityKind::Person => SelectorKind::Name,
            _ => continue,
        };
        push_unique(&mut out, &mut seen, kind, &e.value);
    }
    out
}

/// One provider's rendered section.
#[derive(Debug, Clone, Serialize)]
pub struct Rendered {
    pub site: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    pub how: &'static str,
    pub lines: Vec<String>,
    /// Selectors the provider does not index and were left out.
    pub skipped: usize,
}

/// Spell one selector the way `site` wants it, or `None` if it does not index
/// that kind.
#[must_use]
pub fn line_for(site: &Site, s: &Selector) -> Option<String> {
    if !site.accepts.contains(&s.kind) {
        return None;
    }
    Some(match site.syntax {
        LineSyntax::Bare => s.value.clone(),
        LineSyntax::Prefixed(fields) => {
            let field = fields.iter().find(|(k, _)| *k == s.kind)?.1;
            // A field value with whitespace must be quoted (DeHashed's
            // documented `name:"John Smith"`); a single-token value is bare.
            // A value that itself contains a quote is also quoted, with the
            // inner quotes backslash-escaped, so the `field:"…"` never closes
            // early and stays a single valid term.
            if s.value.chars().any(char::is_whitespace) || s.value.contains('"') {
                format!("{field}:\"{}\"", s.value.replace('"', "\\\""))
            } else {
                format!("{field}:{}", s.value)
            }
        }
    })
}

/// Render every selector for one provider.
#[must_use]
pub fn render(site: &'static Site, selectors: &[Selector]) -> Rendered {
    let mut lines = Vec::new();
    let mut skipped = 0;
    for s in selectors {
        match line_for(site, s) {
            Some(l) => lines.push(l),
            None => skipped += 1,
        }
    }
    Rendered {
        site: site.id,
        name: site.name,
        url: site.url,
        how: site.how,
        lines,
        skipped,
    }
}

/// Plain text: one section per provider — a `#` header naming the provider,
/// where to paste and how, then one query per line — or, `bare`, just the
/// lines, sections separated by a blank line. `#` lines are comments to a
/// human and never a valid selector, so a whole section pastes cleanly into
/// a box that takes one line at a time.
#[must_use]
pub fn to_text(rendered: &[Rendered], bare: bool) -> String {
    let mut out = String::new();
    for (i, r) in rendered.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        if !bare {
            out.push_str(&format!(
                "# {} — {} query line(s)\n# {}\n# {}\n",
                r.name,
                r.lines.len(),
                r.url,
                r.how
            ));
        }
        for l in &r.lines {
            out.push_str(l);
            out.push('\n');
        }
    }
    out
}

/// Selectors from a stored scan (`latest` allowed): the resolved scan ID and
/// what it found, as [`selectors_from_entities`] orders them.
pub fn from_scan(raw: &str) -> crate::core::error::Result<(String, Vec<Selector>)> {
    let store = crate::storage::Store::open(&crate::default_db_path())?;
    let sid = crate::app::runtime::resolve_scan_id(&store, raw)?;
    let entities = store.entities_for_scan(&sid)?;
    Ok((sid, selectors_from_entities(&entities)))
}

#[cfg(test)]
mod tests;
