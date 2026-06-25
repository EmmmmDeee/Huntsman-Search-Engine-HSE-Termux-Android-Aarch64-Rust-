//! CPAN author profile lookup via MetaCPAN. Free, no API key required.
//!
//! Endpoint: `GET https://fastapi.metacpan.org/v1/author/{PAUSEID}`
//!
//! CPAN (Comprehensive Perl Archive Network) is the canonical Perl package
//! repository, active since 1993. Authors register a PAUSE ID (traditionally
//! uppercase) and upload modules; MetaCPAN indexes all CPAN content and
//! exposes a rich REST API. The author endpoint returns the author's real name,
//! public email list, personal websites, location, and biography. CPAN authors
//! overlap very little with GitHub/GitLab users — many are enterprise Perl
//! developers, system administrators, and bioinformatics researchers whose
//! primary identity anchor is their PAUSE ID. As a `code`-family source it
//! provides unique cross-platform corroboration for this population.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

const SRC: &str = "cpan_user";

/// A website entry in the MetaCPAN author response.
#[derive(Deserialize, Default)]
pub(super) struct CpanSite {
    /// The URL of the site.
    #[serde(default)]
    pub(super) url: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct CpanAuthor {
    /// CPAN/PAUSE login identifier (traditionally uppercase).
    #[serde(default)]
    pub(super) pauseid: String,
    /// Full display name — usually a real name.
    #[serde(default)]
    pub(super) name: Option<String>,
    /// Public email address list.
    #[serde(default)]
    pub(super) email: Vec<String>,
    /// Personal website / homepage entries.
    #[serde(default)]
    pub(super) website: Vec<CpanSite>,
    /// Self-reported location string.
    #[serde(default)]
    pub(super) location: Option<String>,
    /// Biography — may contain additional contact details.
    #[serde(default)]
    pub(super) biography: Option<String>,
}

pub(super) fn build_entities(author: CpanAuthor, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let handle = author.pauseid.trim();
    if handle.is_empty() {
        return out;
    }
    // PAUSE IDs are canonically uppercase; normalise once and reuse.
    let pause_id = handle.to_ascii_uppercase();

    let profile_url = format!("https://metacpan.org/author/{pause_id}");

    let ev = || {
        Evidence::new(SRC, format!("CPAN/MetaCPAN profile of '{handle}'"))
            .with_attr("profile_url", &profile_url)
    };

    // Confirmed PAUSE ID / CPAN username.
    let mut e = Entity::new(EntityKind::Username, &pause_id, 0.87, scan_id);
    e.tag("cpan");
    e.tag("public-profile");
    e.add_evidence(ev());
    out.push(e);

    // MetaCPAN profile URL.
    let mut u = Entity::new(EntityKind::Url, &profile_url, 0.80, scan_id);
    u.tag("cpan");
    u.add_evidence(ev());
    out.push(u);

    // Real name → Person (multi-word only).
    if let Some(ref name) = author.name
        && name.split_whitespace().count() >= 2
    {
        let mut p = Entity::new(EntityKind::Person, name.trim(), 0.72, scan_id);
        p.tag("cpan");
        p.add_evidence(
            Evidence::new(SRC, format!("Real name from CPAN profile of '{handle}'"))
                .with_attr("source_field", "name"),
        );
        out.push(p);
    }

    // Public email addresses (up to 3).
    for email in author.email.iter().filter(|e| e.contains('@')).take(3) {
        let mut em = Entity::new(EntityKind::Email, email.trim(), 0.80, scan_id);
        em.tag("cpan");
        em.add_evidence(
            Evidence::new(SRC, format!("Public email from CPAN profile of '{handle}'"))
                .with_attr("source_field", "email"),
        );
        out.push(em);
    }

    // Personal websites → URL + Domain.
    for site in author
        .website
        .iter()
        .filter_map(|s| s.url.as_deref())
        .take(3)
    {
        let site = site.trim();
        if !site.starts_with("http://") && !site.starts_with("https://") {
            continue;
        }
        let mut wu = Entity::new(EntityKind::Url, site, 0.70, scan_id);
        wu.tag("cpan");
        wu.add_evidence(ev().with_attr("source_field", "website"));
        out.push(wu);
        if let Some(host) = crate::util::url_util::host_from_url(site)
            && host.contains('.')
            && !matches!(
                host.as_str(),
                "metacpan.org" | "cpan.org" | "github.com" | "gitlab.com"
            )
        {
            let mut d = Entity::new(EntityKind::Domain, &host, 0.62, scan_id);
            d.tag("cpan");
            d.tag("derived");
            d.add_evidence(ev().with_attr("source_field", "website"));
            out.push(d);
        }
    }

    // Location → Address (self-asserted, low confidence).
    if let Some(ref loc) = author.location
        && !loc.trim().is_empty()
        && loc.len() <= 100
    {
        let mut a = Entity::new(EntityKind::Address, loc.trim(), 0.36, scan_id);
        a.tag("cpan");
        a.tag("self-asserted");
        a.add_evidence(ev().with_attr("source_field", "location"));
        out.push(a);
    }

    // Biography — extract email addresses.
    if let Some(bio) = author.biography.as_deref() {
        for email in crate::util::extract::emails(bio).into_iter().take(3) {
            let mut em = Entity::new(EntityKind::Email, &email, 0.68, scan_id);
            em.tag("cpan");
            em.tag("public-profile");
            em.add_evidence(
                Evidence::new(SRC, format!("Email in CPAN biography of '{handle}'"))
                    .with_attr("source_field", "biography"),
            );
            out.push(em);
        }
    }

    out
}

pub struct CpanUser;

#[async_trait]
impl Module for CpanUser {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "CPAN/MetaCPAN author profile: name, emails, websites, location (Perl ecosystem, free)"
    }
    fn priority(&self) -> u8 {
        55
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
        // Package-registry profile — T1593.003; name/email from author record — T1589.002.
        &["T1589.002", "T1593.003"]
    }
    fn produces(&self) -> &'static [EntityKind] {
        const K: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Url,
            EntityKind::Domain,
            EntityKind::Address,
        ];
        K
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        // PAUSE IDs: 2–9 ASCII alphanumeric chars (uppercase in canonical form).
        if handle.is_empty() || handle.len() > 9 {
            return Ok(ModuleResult::new());
        }
        let url = format!(
            "https://fastapi.metacpan.org/v1/author/{}",
            urlencode(&handle.to_ascii_uppercase())
        );
        let author: CpanAuthor = match fetch_json_or_404(&ctx.http, SRC, &url).await {
            Ok(Some(a)) => a,
            Ok(None) | Err(_) => return Ok(ModuleResult::new()),
        };
        if !author.pauseid.eq_ignore_ascii_case(handle) {
            return Ok(ModuleResult::new());
        }
        let mut result = ModuleResult::new();
        result.entities = build_entities(author, &ctx.scan_id);
        Ok(result)
    }
}
