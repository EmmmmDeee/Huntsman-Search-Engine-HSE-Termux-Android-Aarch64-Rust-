//! RubyGems author/owner lookup. Free, no API key required.
//!
//! Endpoint: `GET https://rubygems.org/api/v1/owners/{handle}/gems.json`
//!
//! RubyGems is the canonical Ruby package repository, hosting millions of gems
//! (libraries). The owners endpoint returns all gems a handle owns, each
//! record carrying the `authors` field (comma-separated real names), a
//! `homepage_uri`, a `source_code_uri` (often GitHub), and other metadata.
//!
//! Why it earns a place in the keyless set: Ruby developers constitute a
//! distinct population from Python/JS/Perl ecosystems — Shopify engineers,
//! Rails contributors, and OSS library authors. A single lookup yields the
//! real name behind the handle, their personal site, and a GitHub pivot, all
//! from a single free request. Returns 404 on an unknown handle, so the miss
//! path is clean with zero retry cost.

#[cfg(test)]
mod tests;

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;

use super::profile_kit;
use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json_or_404;

const SRC: &str = "rubygems_user";

pub struct RubygemsUser;

#[derive(Deserialize)]
pub(super) struct RgGem {
    #[serde(default)]
    pub(super) name: Option<String>,
    /// Comma-separated list of author names, e.g. `"Alice Smith, Bob Jones"`.
    #[serde(default)]
    pub(super) authors: Option<String>,
    #[serde(default)]
    pub(super) homepage_uri: Option<String>,
    #[serde(default)]
    pub(super) source_code_uri: Option<String>,
}

/// Extract the GitHub `{user}` segment from a URL of the form
/// `https://github.com/{user}/{repo}` (exactly two path segments).
fn github_user_from_url(url: &str) -> Option<&str> {
    let path = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))?;
    let slash = path.find('/')?;
    let user = &path[..slash];
    if user.is_empty() || user.contains('?') || user.contains('#') {
        return None;
    }
    Some(user)
}

/// Pure gem-list → entity mapping; unit-testable without network I/O.
pub(super) fn build_entities(gems: Vec<RgGem>, handle: &str, scan_id: &str) -> Vec<Entity> {
    let mut result = ModuleResult::new();
    let mut seen_names: HashSet<String> = HashSet::new();
    let mut seen_urls: HashSet<String> = HashSet::new();
    let mut seen_gh: HashSet<String> = HashSet::new();
    let mut gem_names: Vec<String> = Vec::new();

    let profile_url = format!("https://rubygems.org/profiles/{handle}");
    let ev_base = || {
        Evidence::new(SRC, format!("RubyGems profile of '{handle}'"))
            .with_attr("profile_url", &profile_url)
    };

    // Confirmed-on-RubyGems username.
    let mut u = Entity::new(EntityKind::Username, handle, 0.85, scan_id);
    u.tag("rubygems");
    u.tag("public-profile");
    u.add_evidence(ev_base());
    result.push(u);

    // Profile URL.
    let mut pu = Entity::new(EntityKind::Url, &profile_url, 0.78, scan_id);
    pu.tag("rubygems");
    pu.add_evidence(ev_base());
    result.push(pu);

    // Scan EVERY owned gem: each can carry a distinct author (Person), homepage
    // (Url/Domain) and source-code host (GitHub Username) pivot, and the three
    // `seen_*` dedup sets already bound the DISTINCT entity fan-out — so a prior
    // `.take(30)` cap dropped real, un-recovered identity pivots (an author's
    // real name, a personal domain) from a prolific maintainer's later gems for
    // no fan-out benefit.
    let total_gems = gems.len();
    for gem in gems {
        let gem_name = gem.name.as_deref().unwrap_or("").to_string();
        if !gem_name.is_empty() {
            gem_names.push(gem_name.clone());
        }

        let gem_ev = || {
            Evidence::new(
                SRC,
                format!("RubyGems gem '{gem_name}' owned by '{handle}'"),
            )
            .with_attr("gem", &gem_name)
        };

        // Real names from `authors` (comma-separated).
        if let Some(authors_str) = gem.authors.as_deref() {
            for name in authors_str
                .split(',')
                .map(str::trim)
                .filter(|n| !n.is_empty())
            {
                let key = name.to_ascii_lowercase();
                if seen_names.insert(key)
                    && let Some(mut p) = profile_kit::person_from_name(name, 0.60, scan_id)
                {
                    p.tag("rubygems");
                    p.tag("derived");
                    p.add_evidence(gem_ev().with_attr("source_field", "authors"));
                    result.push(p);
                }
            }
        }

        // Homepage URI — personal site; skip obvious code-hosting hosts.
        if let Some(hp) = gem.homepage_uri.as_deref()
            && (hp.starts_with("http://") || hp.starts_with("https://"))
            && seen_urls.insert(hp.to_string())
        {
            for mut e in profile_kit::website_url_and_domain(hp, 0.68, 0.58, scan_id) {
                e.tag("rubygems");
                match e.kind {
                    EntityKind::Domain => {
                        e.tag("derived");
                        e.add_evidence(gem_ev().with_attr("source_field", "homepage_uri"));
                    }
                    _ => {
                        e.tag("personal-site");
                        e.add_evidence(gem_ev().with_attr("source_field", "homepage_uri"));
                    }
                }
                result.push(e);
            }
        }

        // Source code URI — usually GitHub; extract the GitHub username.
        if let Some(src_url) = gem.source_code_uri.as_deref()
            && (src_url.starts_with("http://") || src_url.starts_with("https://"))
            && let Some(gh_user) = github_user_from_url(src_url)
            && seen_gh.insert(gh_user.to_ascii_lowercase())
        {
            let mut g = Entity::new(EntityKind::Username, gh_user, 0.70, scan_id);
            g.tag("github");
            g.tag("rubygems-pivot");
            g.add_evidence(
                gem_ev()
                    .with_attr("source_field", "source_code_uri")
                    .with_attr("source_url", src_url),
            );
            result.push(g);
        }
    }

    // Append the gem-list coverage to the username entity evidence.
    if !gem_names.is_empty() && !result.entities.is_empty() {
        let coverage = gem_names
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let summary = if total_gems > 5 {
            format!("{coverage}, … ({total_gems} gems)")
        } else {
            coverage
        };
        // Add a supplemental evidence note to the username entity.
        let mut extra_ev = Evidence::new(SRC, format!("RubyGems gem coverage for '{handle}'"));
        extra_ev = extra_ev.with_attr("gems", &summary);
        result.entities[0].add_evidence(extra_ev);
    }

    result.entities
}

#[async_trait]
impl Module for RubygemsUser {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "RubyGems gem owner profile: real name, homepage, GitHub pivot (Ruby ecosystem, free)"
    }

    fn priority(&self) -> u8 {
        54
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Package-registry profile — T1593.003 for the Username itself. The
        // previous "name from authors field — T1589.002" comment fabricated
        // an Email-Addresses claim this module has no basis for: no
        // `EntityKind::Email` is ever constructed anywhere in
        // `build_entities` (the same category-label mix-up already found
        // and fixed in `bitbucket_user`). The real names extracted from
        // `authors` become `Person` entities, which is T1589.003 (Employee
        // Names) — declared here instead. The homepage/source-code-URI
        // pivots (`Url`/`Domain`/GitHub `Username`) mirror the same
        // uncredited-pivot shape already established for `npm_author`/
        // `crates_io` (no dedicated technique for a derived Url/Domain
        // link), so no further addition is needed for them.
        &["T1589.003", "T1593.003"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Url,
            EntityKind::Domain,
        ];
        K
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        // RubyGems handles: 1–40 chars, alphanumeric + hyphen + underscore + dot.
        if handle.is_empty()
            || handle.len() > 40
            || !handle
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://rubygems.org/api/v1/owners/{}/gems.json",
            crate::util::http::urlencode(handle)
        );
        let gems: Option<Vec<RgGem>> = fetch_json_or_404(&ctx.http, SRC, &url).await?;
        let gems = match gems {
            Some(g) if !g.is_empty() => g,
            _ => return Ok(ModuleResult::new()),
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(gems, handle, &ctx.scan_id);
        Ok(result)
    }
}
