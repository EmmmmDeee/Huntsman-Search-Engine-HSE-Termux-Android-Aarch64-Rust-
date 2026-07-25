//! Bitbucket Cloud user profile lookup. Free, no API key required.
//!
//! Endpoint: `GET https://api.bitbucket.org/2.0/users/{nickname}`
//!
//! Bitbucket Cloud (Atlassian) is one of the three largest code-hosting
//! platforms — tens of millions of developers, with especially deep penetration
//! in enterprise teams using Jira, Confluence, and the Atlassian toolchain.
//! The public v2 REST API returns the user's display name, self-reported
//! location, and personal website, with no authentication required for public
//! accounts. As an independent `code`-family source it provides genuine cross-
//! platform corroboration distinct from GitHub/GitLab/Codeberg, covering an
//! enterprise-oriented population that is meaningfully complementary.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::modules::profile_kit;
use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

const SRC: &str = "bitbucket_user";

#[derive(Deserialize, Default)]
pub(super) struct BbLink {
    #[serde(default)]
    pub(super) href: Option<String>,
}

#[derive(Deserialize, Default)]
pub(super) struct BbLinks {
    #[serde(default)]
    pub(super) html: Option<BbLink>,
}

#[derive(Deserialize)]
pub(super) struct BbUser {
    /// Current login handle (formerly `username`, now `nickname` in API v2).
    #[serde(default)]
    pub(super) nickname: String,
    /// Full display name — may be a real name or a pseudonym.
    #[serde(default)]
    pub(super) display_name: Option<String>,
    /// Indicates whether the account is `"active"`.
    #[serde(default)]
    pub(super) account_status: Option<String>,
    /// Self-reported location string.
    #[serde(default)]
    pub(super) location: Option<String>,
    /// Self-reported personal website.
    #[serde(default)]
    pub(super) website: Option<String>,
    /// Nested link object containing `html.href` (canonical profile URL).
    #[serde(default)]
    pub(super) links: Option<BbLinks>,
}

pub(super) fn build_entities(user: BbUser, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let handle = user.nickname.trim();
    if handle.is_empty() {
        return out;
    }
    // Inactive or suspended accounts are not useful as identity pivots.
    if let Some(ref status) = user.account_status
        && !status.eq_ignore_ascii_case("active")
    {
        return out;
    }
    // Resolve the canonical profile URL from the nested `links.html.href`
    // (trailing slash trimmed for dedup), falling back to the constructed form.
    let profile_url = profile_kit::profile_url(
        user.links
            .as_ref()
            .and_then(|l| l.html.as_ref())
            .and_then(|h| h.href.as_deref()),
        || format!("https://bitbucket.org/{handle}"),
    );

    let ev = || {
        Evidence::new(SRC, format!("Bitbucket Cloud profile of '{handle}'"))
            .with_attr("profile_url", &profile_url)
    };

    // Confirmed username on Bitbucket Cloud.
    let mut e = Entity::new(EntityKind::Username, handle, 0.86, scan_id);
    e.tag("bitbucket");
    e.tag("public-profile");
    e.add_evidence(ev());
    out.push(e);

    // Profile URL.
    let mut u = Entity::new(
        EntityKind::Url,
        &profile_url,
        confidence::HIGH_PLUSPLUS,
        scan_id,
    );
    u.tag("bitbucket");
    u.add_evidence(ev());
    out.push(u);

    // Display name → Person (multi-word only; single-token is likely a handle).
    if let Some(name) = user.display_name.as_deref()
        && let Some(mut p) = profile_kit::person_from_name(name, confidence::HIGH_PLUS, scan_id)
    {
        p.tag("bitbucket");
        p.add_evidence(ev().with_attr("source_field", "display_name"));
        out.push(p);
    }

    // Personal website URL and derived domain.
    if let Some(site) = user.website.as_deref() {
        for mut e in profile_kit::website_url_and_domain(site, confidence::HIGH_PLUS, 0.63, scan_id)
        {
            e.tag("bitbucket");
            if e.kind == EntityKind::Domain {
                e.tag("derived");
            }
            e.add_evidence(ev().with_attr("source_field", "website"));
            out.push(e);
        }
    }

    // Location → Address (self-asserted, low confidence).
    if let Some(loc) = user.location.as_deref()
        && let Some(mut a) = profile_kit::location_address(loc, 0.36, scan_id)
    {
        a.tag("bitbucket");
        a.tag("self-asserted");
        a.add_evidence(ev().with_attr("source_field", "location"));
        out.push(a);
        if let Some(mut c) = profile_kit::location_coordinates(loc, 0.26, scan_id) {
            c.tag("bitbucket");
            c.add_evidence(ev().with_attr("source_field", "location"));
            out.push(c);
        }
    }

    out
}

pub struct BitbucketUser;

#[async_trait]
impl Module for BitbucketUser {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "Bitbucket Cloud profile recon — harvests display name, website, and location via public API v2 (free)"
    }
    fn priority(&self) -> u8 {
        97
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
        // Code-repository profile — T1593.003; display_name → real identity — T1589.002.
        &["T1589.002", "T1593.003"]
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Url,
            EntityKind::Domain,
            EntityKind::Address,
            EntityKind::Coordinates,
        ];
        K
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        if handle.is_empty() || handle.len() > 64 {
            return Ok(ModuleResult::new());
        }
        let url = format!("https://api.bitbucket.org/2.0/users/{}", urlencode(handle));
        // 404 (`Ok(None)`) = genuine "no such user" clean miss; every other
        // failure (429/5xx/transport) propagates via `?` instead of a fake 404
        // (T2.117 — `fetch_json_or_404`'s split is pinned in `util::http::tests`).
        let Some(user) = fetch_json_or_404::<BbUser>(&ctx.http, SRC, &url).await? else {
            return Ok(ModuleResult::new());
        };
        if !user.nickname.eq_ignore_ascii_case(handle) {
            return Ok(ModuleResult::new());
        }
        let mut result = ModuleResult::new();
        result.entities = build_entities(user, &ctx.scan_id);
        Ok(result)
    }
}
