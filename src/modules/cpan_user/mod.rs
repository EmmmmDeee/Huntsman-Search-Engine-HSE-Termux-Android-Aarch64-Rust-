//! CPAN author profile lookup via MetaCPAN. Free, no API key required.
//!
//! Endpoint: `GET https://fastapi.metacpan.org/v1/author/{PAUSEID}`
//!
//! CPAN (Comprehensive Perl Archive Network) is the canonical Perl package
//! repository, active since 1993. Authors register a PAUSE ID (traditionally
//! uppercase) and upload modules; MetaCPAN indexes all CPAN content and
//! exposes a rich REST API. The author endpoint returns the author's real name,
//! public email list, personal websites, blog, location, biography, and — the
//! high-value part — a `profile` array of linked social/code accounts (GitHub,
//! Stack Overflow, Twitter, Coderwall, …) that anchors the author across
//! platforms. CPAN authors
//! overlap very little with GitHub/GitLab users — many are enterprise Perl
//! developers, system administrators, and bioinformatics researchers whose
//! primary identity anchor is their PAUSE ID. As a `code`-family source it
//! provides unique cross-platform corroboration for this population.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use super::profile_kit;
use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

const SRC: &str = "cpan_user";

/// A linked-account entry in the MetaCPAN author `profile` array, e.g.
/// `{"name":"github","id":"rjbs"}` — the platform and the author's handle on it.
#[derive(Deserialize, Default)]
pub(super) struct CpanProfile {
    /// Platform name (`github`, `twitter`, `stackoverflow`, `coderwall`, …).
    #[serde(default)]
    pub(super) name: Option<String>,
    /// The author's identifier on that platform — a handle for most, a numeric
    /// user id for a few (`stackoverflow`, `linkedin`).
    #[serde(default)]
    pub(super) id: Option<String>,
}

/// A blog entry in the MetaCPAN author `blog` array.
#[derive(Deserialize, Default)]
pub(super) struct CpanBlog {
    /// The blog's URL.
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
    /// Public email address(es). MetaCPAN returns this as EITHER a single scalar
    /// string (`"cpan@example.org"` — the common case, confirmed live) OR an
    /// array of strings. Accept both: with a plain `Vec<String>` a scalar-email
    /// author fails the WHOLE author decode, silently breaking the module for
    /// most real authors (T-live: `RJBS`/`LEONT`/`MSTROUT` all return a scalar).
    #[serde(default, deserialize_with = "string_or_vec")]
    pub(super) email: Vec<String>,
    /// Personal website / homepage URLs. MetaCPAN returns this as an array of
    /// URL **strings** (`["http://rjbs.cloud/"]`), NOT an array of objects; the
    /// `string_or_vec` guard also tolerates a lone scalar.
    #[serde(default, deserialize_with = "string_or_vec")]
    pub(super) website: Vec<String>,
    /// Self-reported location — MetaCPAN stores it as a `[lat, lon]` coordinate
    /// pair (decimal degrees), NOT a place-name string. An `Option<String>` here
    /// made every author with a location fail to decode.
    #[serde(default)]
    pub(super) location: Option<Vec<f64>>,
    /// Biography — may contain additional contact details.
    #[serde(default)]
    pub(super) biography: Option<String>,
    /// Linked social/code accounts (github, twitter, stackoverflow, …) — the
    /// cross-platform identity pivots this module exists to surface.
    #[serde(default)]
    pub(super) profile: Vec<CpanProfile>,
    /// Blog / weblog entries the author lists.
    #[serde(default)]
    pub(super) blog: Vec<CpanBlog>,
}

/// Deserialize a field that upstream returns as EITHER a single string or an
/// array of strings into a `Vec<String>`. A missing/null value yields an empty
/// vec. **Pure** — used for MetaCPAN's polymorphic `email` field.
fn string_or_vec<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Option::<OneOrMany>::deserialize(deserializer)? {
        None => Vec::new(),
        Some(OneOrMany::One(s)) => vec![s],
        Some(OneOrMany::Many(v)) => v,
    })
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
    if let Some(name) = author.name.as_deref()
        && let Some(mut p) = profile_kit::person_from_name(name, 0.72, scan_id)
    {
        p.tag("cpan");
        p.add_evidence(
            Evidence::new(SRC, format!("Real name from CPAN profile of '{handle}'"))
                .with_attr("source_field", "name"),
        );
        out.push(p);
    }

    // Public email addresses — all of them (the author's own contact details).
    for email in author.email.iter().filter(|e| e.contains('@')) {
        let mut em = Entity::new(EntityKind::Email, email.trim(), 0.80, scan_id);
        em.tag("cpan");
        em.add_evidence(
            Evidence::new(SRC, format!("Public email from CPAN profile of '{handle}'"))
                .with_attr("source_field", "email"),
        );
        out.push(em);
    }

    // Personal websites → URL + Domain — all of them (the author's own sites).
    for site in author.website.iter().map(String::as_str) {
        for mut e in profile_kit::website_url_and_domain(site, 0.70, 0.62, scan_id) {
            e.tag("cpan");
            if e.kind == EntityKind::Domain {
                e.tag("derived");
            }
            e.add_evidence(ev().with_attr("source_field", "website"));
            out.push(e);
        }
    }

    // Linked social/code accounts (MetaCPAN `profile` array) — the cross-platform
    // identity pivots the module's own docs promise but previously dropped. Each
    // `{name: platform, id: handle}` becomes a bare Username tagged with the
    // platform, so it deduplicates with the platform-native modules
    // (`github_user`, `stackoverflow_user`, …) rather than sitting inert. A
    // purely-numeric id (a stackoverflow/linkedin *user number*, not a handle) is
    // NOT a username to pivot on, so it is skipped rather than seeded as junk
    // into `username_search`.
    for prof in &author.profile {
        let (Some(platform), Some(id)) = (
            prof.name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty()),
            prof.id.as_deref().map(str::trim).filter(|s| !s.is_empty()),
        ) else {
            continue;
        };
        if !id.chars().any(|c| c.is_ascii_alphabetic()) {
            continue;
        }
        let platform_lc = platform.to_ascii_lowercase();
        let mut acct = Entity::new(EntityKind::Username, id, 0.66, scan_id);
        acct.tag("cpan");
        acct.tag("cpan-pivot");
        acct.tag(&platform_lc);
        acct.add_evidence(
            Evidence::new(
                SRC,
                format!("Linked {platform} account from CPAN profile of '{handle}'"),
            )
            .with_attr("platform", &platform_lc)
            .with_attr("platform_handle", format!("{platform_lc}:{id}"))
            .with_attr("source_field", "profile"),
        );
        out.push(acct);
    }

    // Blog / weblog URL(s) → URL + Domain (the author's own publishing surface).
    for url in author.blog.iter().filter_map(|b| b.url.as_deref()) {
        for mut e in profile_kit::website_url_and_domain(url, 0.66, 0.58, scan_id) {
            e.tag("cpan");
            if e.kind == EntityKind::Domain {
                e.tag("derived");
            }
            e.add_evidence(ev().with_attr("source_field", "blog"));
            out.push(e);
        }
    }

    // Location → Coordinates (self-asserted). MetaCPAN gives an exact
    // `[lat, lon]` pair, so emit the coordinate directly — higher fidelity than
    // geocoding a place name. Gated to a valid, non-null-island fix.
    if let Some([lat, lon, ..]) = author.location.as_deref()
        && (-90.0..=90.0).contains(lat)
        && (-180.0..=180.0).contains(lon)
        && !(*lat == 0.0 && *lon == 0.0)
    {
        let coord_val = format!("{lat:.4},{lon:.4}");
        let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.40, scan_id);
        c.tag("cpan");
        c.tag("geoint");
        c.tag("self-asserted");
        c.add_evidence(
            ev().with_attr("source_field", "location")
                .with_attr("lat", format!("{lat}"))
                .with_attr("lon", format!("{lon}")),
        );
        out.push(c);
    }

    // Biography — extract email addresses.
    if let Some(bio) = author.biography.as_deref() {
        for mut em in profile_kit::bio_emails(bio, 0.68, scan_id) {
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
        "CPAN/MetaCPAN author recon — harvests name, emails, websites, blog, linked accounts, and location to pivot across the Perl ecosystem (free)"
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
            // Location is a [lat, lon] pair → emitted directly as Coordinates
            // (no place-name Address; the API gives no place string).
            EntityKind::Coordinates,
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
        // 404 (`Ok(None)`) = genuine "no such author" clean miss; every other
        // failure (429/5xx/transport) propagates via `?` instead of a fake 404
        // (T2.117 — `fetch_json_or_404`'s split is pinned in `util::http::tests`).
        let Some(author) = fetch_json_or_404::<CpanAuthor>(&ctx.http, SRC, &url).await? else {
            return Ok(ModuleResult::new());
        };
        if !author.pauseid.eq_ignore_ascii_case(handle) {
            return Ok(ModuleResult::new());
        }
        let mut result = ModuleResult::new();
        result.entities = build_entities(author, &ctx.scan_id);
        Ok(result)
    }
}
