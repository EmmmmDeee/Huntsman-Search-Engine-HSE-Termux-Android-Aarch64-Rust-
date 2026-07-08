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

/// Build the Stack Exchange `users?inname=` search URL for `handle`.
///
/// No custom `filter` is sent: the previously hard-coded `filter=!9Z(-x.hbL` is
/// now rejected by the API with HTTP 400 `"Invalid filter specified"`, which live
/// end-to-end testing (a real username seed) caught — it had silently broken
/// EVERY Stack Overflow lookup. The API's default filter already returns every
/// field this module reads (`display_name`, `location`, `website_url`, `link`,
/// `reputation`, `creation_date`), verified live, so omitting the parameter is
/// both correct and drift-proof (a custom encoded filter can be invalidated by an
/// API revision; the default cannot). Usernames may contain spaces, so the query
/// is URL-encoded.
fn users_by_name_url(handle: &str) -> String {
    format!(
        "https://api.stackexchange.com/2.3/users?inname={}&site=stackoverflow",
        crate::util::http::urlencode(handle)
    )
}

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
    /// Unix epoch (UTC) the account was created — surfaced as `account_created`,
    /// an account-age temporal signal (older accounts corroborate identity and
    /// anchor breach/activity timelines).
    #[serde(default)]
    pub(super) creation_date: Option<i64>,
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
        // Developer forum — T1593.001 Social Media is the genuinely correct
        // base technique here (Stack Overflow really is a forum/social
        // platform, unlike the code-hosting siblings mis-declared Social
        // that need T1593.003 substituted in). This override correctly
        // ADDED T1591.001 for the location-derived Address/Coordinates,
        // but REPLACED the whole default array instead of substituting
        // just the one technique, silently dropping T1589.003 (Employee
        // Names) even though `build_entities` genuinely constructs a
        // Person from the multi-word `display_name` below — the same
        // under-declared-coverage gap already fixed for the sibling
        // "profile lookup" modules. No Email/Organisation fields exist on
        // `SoUser`, so T1589.002/T1591.002 do not apply.
        &["T1589.003", "T1591.001", "T1593.001"]
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

        let url = users_by_name_url(handle);
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
    if let Some(created) = user.creation_date.and_then(crate::util::timefmt::ymd_utc) {
        ev = ev.with_attr("account_created", created);
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

    #[test]
    fn users_url_omits_the_invalid_custom_filter() {
        // Regression for the API drift live testing caught: the old hard-coded
        // `filter=!9Z(-x.hbL` now 400s ("Invalid filter specified"), breaking every
        // lookup. The default filter returns all needed fields, so no filter is sent.
        let url = users_by_name_url("jon skeet");
        assert!(
            !url.contains("filter="),
            "no custom filter — the default returns every field we read: {url}"
        );
        // Spaces are form-encoded (`+`); the point is the query is present + escaped.
        assert!(
            url.contains("inname=jon+skeet") && url.contains("site=stackoverflow"),
            "url: {url}"
        );
    }

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
            creation_date: Some(1_546_300_800), // 2019-01-01T00:00:00Z
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
    fn username_evidence_surfaces_account_creation_date() {
        // creation_date was deserialized but dropped; it must now appear as the
        // `account_created` evidence attr (UTC date) — an account-age signal.
        let user = make_user("alice", None, None, None, Some(1234));
        let ents = build_entities(user, "scan-so-created");
        let u = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "alice")
            .expect("Username entity");
        assert_eq!(
            u.evidence[0]
                .attributes
                .get("account_created")
                .map(String::as_str),
            Some("2019-01-01"),
            "the deserialized creation_date must surface as a UTC date"
        );
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

    #[test]
    fn attack_techniques_covers_every_entity_kind_this_module_produces() {
        // build_entities constructs a Person from the multi-word
        // display_name in addition to the Address/Coordinates/Username
        // the override already credits — the same under-declared-coverage
        // gap already fixed for the sibling "profile lookup" modules
        // (github_user/dockerhub_user/codewars_user/mastodon_user/
        // sourceforge_user/bitbucket_user/rubygems_user/gitlab_user/
        // cpan_user/gitea_user/codeberg_user/huggingface_user/hexpm_user/
        // devto/crates_io/npm_author). No Email/Organisation fields exist
        // on `SoUser`, so no other technique applies; the Domain/personal-
        // site Url pivot from `website_url` gets no separate technique,
        // matching established sibling convention.
        let techniques = StackoverflowUser.attack_techniques();
        assert!(
            techniques.contains(&"T1589.003"),
            "Employee Names: Person from the multi-word `display_name`"
        );
        assert!(
            techniques.contains(&"T1591.001"),
            "Determine Physical Locations: Address/Coordinates from `location`"
        );
        assert!(
            techniques.contains(&"T1593.001"),
            "Social Media: Stack Overflow genuinely is a developer forum"
        );
        for id in techniques {
            assert!(
                crate::core::attack::technique(id).is_some(),
                "declared technique {id} must exist in the Reconnaissance catalogue"
            );
        }
    }
}
