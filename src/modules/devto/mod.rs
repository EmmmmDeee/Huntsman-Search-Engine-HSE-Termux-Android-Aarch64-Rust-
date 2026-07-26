//! Dev.to user lookup. Free, no key — the official public REST API.
//!
//! Endpoint: `GET https://dev.to/api/users/by_username?url={username}`
//! (documented at <https://developers.forem.com/api>). Returns the public
//! profile JSON for the account, or 404 for unknown handles:
//!
//! ```json
//! {"id":1,"username":"alice","name":"Alice Smith",
//!  "summary":"…bio…","twitter_username":"alicetw","github_username":"alice-gh",
//!  "website_url":"https://alice.dev","location":"Sydney, AU",
//!  "joined_at":"Jan 1, 2019"}
//! ```
//!
//! Why it earns its place in the keyless-API set: Dev.to (powered by Forem)
//! is one of the largest developer blogging platforms — millions of verified
//! accounts. The profile response includes self-reported `twitter_username`,
//! `github_username`, `website_url`, and `location`, providing direct
//! cross-platform pivots in a single round-trip. As a **social/forum** signal
//! independent of HN, Reddit, and Lobste.rs, it adds genuine cross-service
//! diversity to AU-045. Official, stable, keyless.

use async_trait::async_trait;
use serde::Deserialize;

use super::profile_kit;
use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json_or_404;

const SRC: &str = "devto";

pub struct DevTo;

#[derive(Deserialize)]
pub(super) struct DevUser {
    pub(super) username: String,
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) summary: Option<String>,
    #[serde(default)]
    pub(super) twitter_username: Option<String>,
    #[serde(default)]
    pub(super) github_username: Option<String>,
    #[serde(default)]
    pub(super) website_url: Option<String>,
    #[serde(default)]
    pub(super) location: Option<String>,
    #[serde(default)]
    pub(super) joined_at: Option<String>,
}

#[async_trait]
impl Module for DevTo {
    fn name(&self) -> &'static str {
        "devto"
    }

    fn description(&self) -> &'static str {
        "Dev.to account recon — enumerates name, bio, location, and GitHub/Twitter pivots via the public API"
    }

    fn priority(&self) -> u8 {
        103
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Developer profile — may surface email/real-name from bio.
        // T1589.002 for bio emails; T1593.001 for the platform account itself.
        &["T1589.002", "T1593.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Email,
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
        // Dev.to usernames: letters, digits, underscores, hyphens; 2–50 chars.
        if !crate::util::str_util::is_handle(handle, 2, 50) {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://dev.to/api/users/by_username?url={}",
            crate::util::http::urlencode(handle)
        );
        let user: Option<DevUser> = fetch_json_or_404(&ctx.http, SRC, &url).await?;
        let Some(user) = user else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(user, &ctx.scan_id);
        Ok(result)
    }
}

/// Pure account→entity mapping. Separated from `process()` so every branch is
/// unit-testable without I/O.
pub(super) fn build_entities(user: DevUser, scan_id: &str) -> Vec<Entity> {
    let mut result = ModuleResult::new();

    // Confirmed-on-dev.to username.
    let mut u = Entity::new(
        EntityKind::Username,
        &user.username,
        confidence::EXPERT,
        scan_id,
    );
    u.tag("devto");
    let mut ev = Evidence::new(SRC, format!("Dev.to account '{}'", user.username))
        .with_attr("profile_url", format!("https://dev.to/{}", user.username));
    if let Some(ref ts) = user.joined_at {
        ev = ev.with_attr("joined_at", ts);
    }
    u.add_evidence(ev);
    result.push(u);

    // Real name → Person (only when ≥ 2 whitespace-separated tokens and not a
    // placeholder handle-alike).
    if let Some(ref name) = user.name
        && let Some(mut p) = profile_kit::person_from_name(name, 0.68, scan_id)
    {
        p.tag("devto");
        p.tag("derived");
        p.add_evidence(
            Evidence::new(
                SRC,
                format!("Real name from Dev.to account '{}'", user.username),
            )
            .with_attr("devto_username", &user.username),
        );
        result.push(p);
    }

    // Cross-platform username pivots — direct profile fields.
    if let Some(ref gh) = user.github_username
        && !gh.is_empty()
    {
        let mut g = Entity::new(EntityKind::Username, gh, 0.82, scan_id);
        g.tag("github");
        g.tag("devto-pivot");
        g.add_evidence(
            Evidence::new(
                SRC,
                format!("GitHub username from Dev.to profile of '{}'", user.username),
            )
            .with_attr("source_field", "github_username")
            .with_attr("devto_user", &user.username),
        );
        result.push(g);
    }

    if let Some(ref tw) = user.twitter_username
        && !tw.is_empty()
    {
        let tw_clean = tw.trim_start_matches('@');
        if !tw_clean.is_empty() {
            let mut t = Entity::new(EntityKind::Username, tw_clean, 0.78, scan_id);
            t.tag("twitter");
            t.tag("devto-pivot");
            t.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "Twitter/X username from Dev.to profile of '{}'",
                        user.username
                    ),
                )
                .with_attr("source_field", "twitter_username")
                .with_attr("devto_user", &user.username),
            );
            result.push(t);
        }
    }

    // Personal website URL + Domain extraction.
    if let Some(ref site) = user.website_url {
        for mut e in profile_kit::website_url_and_domain(site, 0.72, confidence::HIGH, scan_id) {
            e.tag("devto");
            match e.kind {
                EntityKind::Domain => {
                    e.tag("derived");
                    e.add_evidence(
                        Evidence::new(
                            SRC,
                            format!("Domain from Dev.to profile of '{}'", user.username),
                        )
                        .with_attr("source_url", site.as_str())
                        .with_attr("devto_user", &user.username),
                    );
                }
                _ => {
                    e.tag("personal-site");
                    e.add_evidence(
                        Evidence::new(
                            SRC,
                            format!("Personal site from Dev.to profile of '{}'", user.username),
                        )
                        .with_attr("source_field", "website_url"),
                    );
                }
            }
            result.push(e);
        }
    }

    // Location → coarse Address (geo-hint, not a precise address).
    if let Some(ref loc) = user.location
        && let Some(mut a) = profile_kit::location_address(loc, 0.35, scan_id)
    {
        a.tag("devto");
        a.tag("self-asserted");
        a.tag("geo-hint");
        a.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "Self-reported location from Dev.to profile of '{}'",
                    user.username
                ),
            )
            .with_attr("source_field", "location")
            .with_attr("devto_user", &user.username),
        );
        result.push(a);
        if let Some(mut c) = profile_kit::location_coordinates(loc, 0.25, scan_id) {
            c.tag("devto");
            c.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Geocode of self-reported location for '{}'", user.username),
                )
                .with_attr("source_field", "location"),
            );
            result.push(c);
        }
    }

    // Bio/summary: extract emails and URLs.
    if let Some(bio) = user.summary.as_deref() {
        for email in crate::util::extract::emails(bio) {
            let mut e = Entity::new(EntityKind::Email, &email, 0.72, scan_id);
            e.tag("devto");
            e.tag("public-profile");
            e.add_evidence(
                Evidence::new(SRC, format!("Email in Dev.to bio of '{}'", user.username))
                    .with_attr("source", "devto_bio"),
            );
            result.push(e);
        }
        for link in crate::util::extract::urls(bio) {
            let link = link.as_str();
            let mut url_e = Entity::new(EntityKind::Url, link, confidence::MEDIUM_PLUS, scan_id);
            url_e.tag("devto");
            url_e.add_evidence(
                Evidence::new(SRC, format!("Link in Dev.to bio of '{}'", user.username))
                    .with_attr("source", "devto_bio"),
            );
            result.push(url_e);
        }
    }

    result.entities
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_user(
        username: &str,
        name: Option<&str>,
        github: Option<&str>,
        twitter: Option<&str>,
        website: Option<&str>,
        location: Option<&str>,
    ) -> DevUser {
        DevUser {
            username: username.to_string(),
            name: name.map(str::to_string),
            summary: None,
            twitter_username: twitter.map(str::to_string),
            github_username: github.map(str::to_string),
            website_url: website.map(str::to_string),
            location: location.map(str::to_string),
            joined_at: Some("Jan 1, 2020".to_string()),
        }
    }

    #[test]
    fn builds_username_entity_confirmed_on_devto() {
        let user = make_user("devuser", None, None, None, None, None);
        let ents = build_entities(user, "scan-dt-001");
        let u = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "devuser");
        assert!(u.is_some(), "must emit Username entity");
        assert!((u.expect("should succeed").confidence - confidence::EXPERT).abs() < 0.01);
        assert!(u.expect("should succeed").has_tag("devto"));
    }

    #[test]
    fn emits_person_from_full_name() {
        let user = make_user("devuser", Some("Alice Developer"), None, None, None, None);
        let ents = build_entities(user, "scan-dt-002");
        let p = ents.iter().find(|e| e.kind == EntityKind::Person);
        assert!(p.is_some(), "must emit Person from multi-word name");
        assert_eq!(p.expect("should succeed").value, "Alice Developer");
    }

    #[test]
    fn no_person_from_single_word_name() {
        let user = make_user("devuser", Some("devuser"), None, None, None, None);
        let ents = build_entities(user, "scan-dt-003");
        assert!(
            ents.iter().all(|e| e.kind != EntityKind::Person),
            "single-token name must not produce a Person entity"
        );
    }

    #[test]
    fn emits_github_and_twitter_pivots() {
        let user = make_user(
            "devuser",
            None,
            Some("devuser-gh"),
            Some("devtw"),
            None,
            None,
        );
        let ents = build_entities(user, "scan-dt-004");
        let gh = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "devuser-gh");
        assert!(
            gh.is_some() && gh.expect("should succeed").has_tag("github"),
            "must emit GitHub pivot"
        );
        let tw = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "devtw");
        assert!(
            tw.is_some() && tw.expect("should succeed").has_tag("twitter"),
            "must emit Twitter pivot"
        );
    }

    #[test]
    fn emits_website_url_and_domain() {
        let user = make_user(
            "devuser",
            None,
            None,
            None,
            Some("https://devuser.io"),
            None,
        );
        let ents = build_entities(user, "scan-dt-005");
        assert!(
            ents.iter().any(|e| e.kind == EntityKind::Url),
            "must emit website URL"
        );
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityKind::Domain && e.value == "devuser.io"),
            "must emit domain from website"
        );
    }

    #[test]
    fn emits_address_from_location() {
        let user = make_user("devuser", None, None, None, None, Some("Sydney, AU"));
        let ents = build_entities(user, "scan-dt-006");
        let a = ents.iter().find(|e| e.kind == EntityKind::Address);
        assert!(a.is_some(), "must emit Address from location field");
        assert!(a.expect("should succeed").has_tag("self-asserted"));
    }

    #[test]
    fn strips_at_from_twitter_username() {
        let user = make_user("devuser", None, None, Some("@twitterhandle"), None, None);
        let ents = build_entities(user, "scan-dt-007");
        let tw = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.has_tag("twitter"));
        assert_eq!(
            tw.map(|e| e.value.as_str()),
            Some("twitterhandle"),
            "must strip leading @ from twitter_username"
        );
    }
}
