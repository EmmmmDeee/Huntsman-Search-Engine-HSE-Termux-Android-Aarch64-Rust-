//! Stack Overflow / Stack Exchange user lookup. Free, no key required for
//! read-only endpoints — the official public API v2.3.
//!
//! Endpoint: `GET https://api.stackexchange.com/2.3/users?inname={username}&site=stackoverflow&filter=!9Z(-x.hbL`
//!
//! The `inname` filter returns users whose display name *contains* the query.
//! We pick the first exact-match (case-insensitive) on `display_name`. A 404
//! or empty `items` array is a clean miss. The API is throttled at ~300
//! anonymous req/day per IP, so the module exits immediately on a miss rather
//! than retrying.
//!
//! Why it earns a place in the keyless set: Stack Overflow is one of the
//! largest developer Q&A platforms — tens of millions of accounts. The profile
//! exposes `display_name`, `location`, `website_url`, and `link` (the profile
//! URL). As an independent `forum`-family source it contributes a distinct
//! corroboration pathway for AU-045 multi-service identity confirmation.

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

const SRC: &str = "stackoverflow_user";

pub struct StackoverflowUser;

#[derive(Deserialize)]
pub(super) struct SoResp {
    #[serde(default)]
    pub(super) items: Vec<SoUser>,
}

#[derive(Deserialize)]
pub(super) struct SoUser {
    pub(super) display_name: String,
    #[serde(default)]
    pub(super) location: Option<String>,
    #[serde(default)]
    pub(super) website_url: Option<String>,
    /// Canonical profile URL, e.g. `https://stackoverflow.com/users/12345/alice`.
    #[serde(default)]
    pub(super) link: Option<String>,
    #[serde(default)]
    pub(super) reputation: Option<i64>,
    #[serde(default)]
    pub(super) _creation_date: Option<i64>,
}

#[async_trait]
impl Module for StackoverflowUser {
    fn name(&self) -> &'static str {
        "stackoverflow_user"
    }

    fn description(&self) -> &'static str {
        "Stack Overflow account lookup (display name, location, website) via public API"
    }

    fn priority(&self) -> u8 {
        105
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Developer forum — T1593.001 Search Open Websites/Domains.
        // May also surface location information — T1591.001.
        &["T1591.001", "T1593.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Url,
            EntityKind::Domain,
            EntityKind::Address,
            EntityKind::Coordinates,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        if handle.is_empty() || handle.len() > 100 {
            return Ok(ModuleResult::new());
        }

        // Stack Exchange usernames can contain spaces; URL-encode for the query.
        let url = format!(
            "https://api.stackexchange.com/2.3/users?inname={}&site=stackoverflow&filter=!9Z(-x.hbL",
            crate::util::http::urlencode(handle)
        );
        let resp: Option<SoResp> = fetch_json_or_404(&ctx.http, SRC, &url).await?;
        let items = match resp {
            Some(r) => r.items,
            None => return Ok(ModuleResult::new()),
        };

        // Pick the first element whose display_name exactly matches (case-insensitive).
        let user = match items
            .into_iter()
            .find(|u| u.display_name.eq_ignore_ascii_case(handle))
        {
            Some(u) => u,
            None => return Ok(ModuleResult::new()),
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(user, &ctx.scan_id);
        Ok(result)
    }
}

/// Pure account→entity mapping.
pub(super) fn build_entities(user: SoUser, scan_id: &str) -> Vec<Entity> {
    let mut result = ModuleResult::new();

    // Confirmed-on-StackOverflow username.
    let mut u = Entity::new(EntityKind::Username, &user.display_name, 0.82, scan_id);
    u.tag("stackoverflow");
    u.tag("forum");
    let mut ev = Evidence::new(
        SRC,
        format!("Stack Overflow account '{}'", user.display_name),
    );
    if let Some(ref link) = user.link {
        ev = ev.with_attr("profile_url", link);
    }
    if let Some(rep) = user.reputation {
        ev = ev.with_attr("reputation", rep.to_string());
    }
    u.add_evidence(ev);
    result.push(u);

    // Display name → Person when it looks like a real name (≥2 words).
    if let Some(mut p) = profile_kit::person_from_name(&user.display_name, 0.55, scan_id) {
        p.tag("stackoverflow");
        p.tag("derived");
        p.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "Real name from Stack Overflow account '{}'",
                    user.display_name
                ),
            )
            .with_attr("so_username", &user.display_name),
        );
        result.push(p);
    }

    // Profile URL.
    if let Some(ref link) = user.link
        && link.starts_with("http")
    {
        let mut url_e = Entity::new(EntityKind::Url, link, 0.75, scan_id);
        url_e.tag("stackoverflow");
        url_e.add_evidence(Evidence::new(
            SRC,
            format!("Stack Overflow profile URL for '{}'", user.display_name),
        ));
        result.push(url_e);
    }

    // Personal website URL + Domain.
    if let Some(ref site) = user.website_url {
        for mut e in profile_kit::website_url_and_domain(site, 0.70, 0.62, scan_id) {
            e.tag("stackoverflow");
            match e.kind {
                EntityKind::Domain => {
                    e.tag("derived");
                    e.add_evidence(
                        Evidence::new(
                            SRC,
                            format!(
                                "Domain from Stack Overflow profile of '{}'",
                                user.display_name
                            ),
                        )
                        .with_attr("source_url", site.as_str())
                        .with_attr("so_username", &user.display_name),
                    );
                }
                _ => {
                    e.tag("personal-site");
                    e.add_evidence(
                        Evidence::new(
                            SRC,
                            format!(
                                "Personal site from Stack Overflow profile of '{}'",
                                user.display_name
                            ),
                        )
                        .with_attr("source_field", "website_url"),
                    );
                }
            }
            result.push(e);
        }
    }

    // Location → coarse Address.
    if let Some(ref loc) = user.location
        && let Some(mut a) = profile_kit::location_address(loc, 0.38, scan_id)
    {
        a.tag("stackoverflow");
        a.tag("self-asserted");
        a.tag("geo-hint");
        a.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "Self-reported location from Stack Overflow profile of '{}'",
                    user.display_name
                ),
            )
            .with_attr("source_field", "location")
            .with_attr("so_username", &user.display_name),
        );
        result.push(a);
        if let Some(mut c) = profile_kit::location_coordinates(loc, 0.28, scan_id) {
            c.tag("stackoverflow");
            c.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "Geocode of self-reported location for '{}'",
                        user.display_name
                    ),
                )
                .with_attr("source_field", "location"),
            );
            result.push(c);
        }
    }

    result.entities
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_user(
        display_name: &str,
        location: Option<&str>,
        website_url: Option<&str>,
        link: Option<&str>,
        reputation: Option<i64>,
    ) -> SoUser {
        SoUser {
            display_name: display_name.to_string(),
            location: location.map(str::to_string),
            website_url: website_url.map(str::to_string),
            link: link.map(str::to_string),
            reputation,
            _creation_date: Some(1_546_300_800),
        }
    }

    #[test]
    fn builds_username_entity_confirmed_on_so() {
        let user = make_user("alice", None, None, None, Some(1234));
        let ents = build_entities(user, "scan-so-001");
        let u = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "alice");
        assert!(u.is_some(), "must emit Username entity");
        assert!((u.unwrap().confidence - 0.82).abs() < 0.01);
        assert!(u.unwrap().has_tag("stackoverflow") && u.unwrap().has_tag("forum"));
    }

    #[test]
    fn emits_person_from_multi_word_display_name() {
        let user = make_user("Alice Developer", None, None, None, None);
        let ents = build_entities(user, "scan-so-002");
        let p = ents.iter().find(|e| e.kind == EntityKind::Person);
        assert!(p.is_some(), "must emit Person from multi-word display name");
        assert_eq!(p.unwrap().value, "Alice Developer");
    }

    #[test]
    fn no_person_for_single_word_name() {
        let user = make_user("alice", None, None, None, None);
        let ents = build_entities(user, "scan-so-003");
        assert!(
            ents.iter().all(|e| e.kind != EntityKind::Person),
            "single-token display name must not produce a Person entity"
        );
    }

    #[test]
    fn emits_website_url_and_domain() {
        let user = make_user(
            "alice",
            None,
            Some("https://alice.dev"),
            Some("https://stackoverflow.com/users/1/alice"),
            None,
        );
        let ents = build_entities(user, "scan-so-004");
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityKind::Url && e.value == "https://alice.dev"),
            "must emit website URL"
        );
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityKind::Domain && e.value == "alice.dev"),
            "must emit domain from website"
        );
    }

    #[test]
    fn emits_address_from_location() {
        let user = make_user("alice", Some("Berlin, DE"), None, None, None);
        let ents = build_entities(user, "scan-so-005");
        let a = ents.iter().find(|e| e.kind == EntityKind::Address);
        assert!(a.is_some(), "must emit Address from location");
        assert_eq!(a.unwrap().value, "Berlin, DE");
        assert!(a.unwrap().has_tag("self-asserted"));
    }

    #[test]
    fn no_entities_for_absent_optional_fields() {
        let user = make_user("quietuser", None, None, None, None);
        let ents = build_entities(user, "scan-so-006");
        assert_eq!(ents.len(), 1, "only Username when no optional fields");
        assert_eq!(ents[0].kind, EntityKind::Username);
    }
}
