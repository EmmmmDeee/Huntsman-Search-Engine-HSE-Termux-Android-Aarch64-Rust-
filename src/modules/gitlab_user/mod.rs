//! GitLab user lookup. Free, no key — the official public REST API.
//!
//! Endpoint: `GET https://gitlab.com/api/v4/users?username={username}`
//! Returns a JSON array (0 or 1 element for an exact username query). The
//! UNAUTHENTICATED response is the basic public view (confirmed live):
//!
//! ```json
//! [{"id":1,"username":"alice","name":"Alice Smith","state":"active",
//!   "avatar_url":"https://…","web_url":"https://gitlab.com/alice",
//!   "public_email":"alice@example.com"}]
//! ```
//!
//! The richer fields (`bio`, `location`, `organization`, `twitter`, `linkedin`,
//! `website_url`, `created_at`) are NOT returned without an authentication token
//! — the struct keeps them (`#[serde(default)]`) so a keyed deployment still
//! populates them, but a keyless scan realistically gets username + name +
//! `public_email`. That public email is the high-value pivot this module now
//! surfaces (it was previously dropped).
//!
//! Why it earns a place in the keyless-API set: GitLab is a major code-hosting
//! platform independent of GitHub — a confirmed account here is in the **code**
//! source family (separate from GitHub, npmjs, crates.io), adding genuine
//! cross-service diversity to AU-045 multi-service identity confirmation and the
//! AU-062 multi-pathway corroboration rule. Official, stable, keyless.

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

const SRC: &str = "gitlab_user";

pub struct GitlabUser;

#[derive(Deserialize)]
pub(super) struct GlUser {
    pub(super) username: String,
    #[serde(default)]
    pub(super) name: Option<String>,
    /// The account's PUBLIC email — the one rich field the unauthenticated
    /// `/users?username=` endpoint actually returns (confirmed live), and a
    /// direct, high-confidence contact pivot the module previously dropped.
    #[serde(default)]
    pub(super) public_email: Option<String>,
    #[serde(default)]
    pub(super) bio: Option<String>,
    #[serde(default)]
    pub(super) website_url: Option<String>,
    #[serde(default)]
    pub(super) location: Option<String>,
    #[serde(default)]
    pub(super) organization: Option<String>,
    #[serde(default)]
    pub(super) twitter: Option<String>,
    #[serde(default)]
    pub(super) linkedin: Option<String>,
    #[serde(default)]
    pub(super) created_at: Option<String>,
}

#[async_trait]
impl Module for GitlabUser {
    fn name(&self) -> &'static str {
        "gitlab_user"
    }

    fn description(&self) -> &'static str {
        "GitLab account lookup (name, bio, Twitter/LinkedIn pivots, org, location) via public API"
    }

    fn priority(&self) -> u8 {
        106
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Code repository — T1593.003 Search Code Repositories.
        // Also T1589.002 for any email discovered in bio.
        &["T1589.002", "T1593.003"]
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
            EntityKind::Organisation,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        // GitLab usernames: 1–255 chars, letters/digits/dots/underscores/hyphens.
        // No leading/trailing special chars in practice.
        if handle.is_empty() || handle.len() > 255 {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://gitlab.com/api/v4/users?username={}",
            crate::util::http::urlencode(handle)
        );
        // The API returns an array; an empty array means no match (treated as 404).
        let users: Option<Vec<GlUser>> = fetch_json_or_404(&ctx.http, SRC, &url).await?;
        let user = match users.and_then(|mut v| {
            // Pick the element whose username exactly matches (case-insensitive).
            let pos = v
                .iter()
                .position(|u| u.username.eq_ignore_ascii_case(handle))?;
            Some(v.swap_remove(pos))
        }) {
            Some(u) => u,
            None => return Ok(ModuleResult::new()),
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(user, &ctx.scan_id);
        Ok(result)
    }
}

/// Pure account→entity mapping. Separated from `process()` so every branch
/// is unit-testable without I/O.
pub(super) fn build_entities(user: GlUser, scan_id: &str) -> Vec<Entity> {
    let mut result = ModuleResult::new();

    // Confirmed-on-GitLab username.
    let mut u = Entity::new(EntityKind::Username, &user.username, 0.90, scan_id);
    u.tag("gitlab");
    u.tag("code");
    let mut ev = Evidence::new(SRC, format!("GitLab account '{}'", user.username)).with_attr(
        "profile_url",
        format!("https://gitlab.com/{}", user.username),
    );
    if let Some(ref ts) = user.created_at {
        ev = ev.with_attr("created_at", ts);
    }
    u.add_evidence(ev);
    result.push(u);

    // Public email — the account owner's self-published contact address (the one
    // rich field the keyless endpoint returns). A confirmed, directly-pivotable
    // Email, so it carries high confidence.
    if let Some(email) = user
        .public_email
        .as_deref()
        .map(str::trim)
        .filter(|e| e.contains('@') && e.len() >= 5)
    {
        let mut em = Entity::new(EntityKind::Email, email, 0.85, scan_id);
        em.tag("gitlab");
        em.tag("public-profile");
        em.add_evidence(
            Evidence::new(
                SRC,
                format!("Public email from GitLab profile of '{}'", user.username),
            )
            .with_attr("source_field", "public_email")
            .with_attr("gitlab_user", &user.username),
        );
        result.push(em);
    }

    // Real name → Person (non-placeholder, ≥ 2 tokens).
    if let Some(name) = user.name.as_deref()
        && let Some(mut p) = profile_kit::person_from_name(name, 0.72, scan_id)
    {
        p.tag("gitlab");
        p.tag("derived");
        p.add_evidence(
            Evidence::new(
                SRC,
                format!("Real name from GitLab account '{}'", user.username),
            )
            .with_attr("gitlab_username", &user.username),
        );
        result.push(p);
    }

    // Organisation (self-reported).
    if let Some(ref org) = user.organization
        && !org.trim().is_empty()
        && org.len() <= 200
    {
        let mut o = Entity::new(EntityKind::Organisation, org.trim(), 0.45, scan_id);
        o.tag("gitlab");
        o.tag("self-asserted");
        o.add_evidence(
            Evidence::new(
                SRC,
                format!("Organisation from GitLab profile of '{}'", user.username),
            )
            .with_attr("source_field", "organization")
            .with_attr("gitlab_user", &user.username),
        );
        result.push(o);
    }

    // Twitter/X username pivot.
    if let Some(ref tw) = user.twitter
        && !tw.is_empty()
    {
        let tw_clean = tw.trim_start_matches('@');
        if !tw_clean.is_empty() {
            let mut t = Entity::new(EntityKind::Username, tw_clean, 0.80, scan_id);
            t.tag("twitter");
            t.tag("gitlab-pivot");
            t.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Twitter/X from GitLab profile of '{}'", user.username),
                )
                .with_attr("source_field", "twitter")
                .with_attr("gitlab_user", &user.username),
            );
            result.push(t);
        }
    }

    // LinkedIn username/URL pivot.
    if let Some(ref li) = user.linkedin
        && !li.is_empty()
    {
        // GitLab stores either a bare username or a full linkedin.com URL.
        let li_val = li.trim();
        let li_url = if li_val.starts_with("http://") || li_val.starts_with("https://") {
            li_val.to_string()
        } else {
            format!(
                "https://www.linkedin.com/in/{}",
                crate::util::http::urlencode(li_val)
            )
        };
        let mut url_e = Entity::new(EntityKind::Url, &li_url, 0.70, scan_id);
        url_e.tag("linkedin");
        url_e.tag("gitlab-pivot");
        url_e.add_evidence(
            Evidence::new(
                SRC,
                format!("LinkedIn from GitLab profile of '{}'", user.username),
            )
            .with_attr("source_field", "linkedin")
            .with_attr("gitlab_user", &user.username),
        );
        result.push(url_e);
    }

    // Website URL + Domain. The Url and Domain carry distinct evidence, so the
    // kit's stable [Url, Domain] ordering is decorated per-kind.
    if let Some(site) = user.website_url.as_deref() {
        for mut e in profile_kit::website_url_and_domain(site, 0.72, 0.65, scan_id) {
            match e.kind {
                EntityKind::Domain => {
                    e.tag("gitlab");
                    e.tag("derived");
                    e.add_evidence(
                        Evidence::new(
                            SRC,
                            format!("Domain from GitLab profile of '{}'", user.username),
                        )
                        .with_attr("source_url", site)
                        .with_attr("gitlab_user", &user.username),
                    );
                }
                _ => {
                    e.tag("gitlab");
                    e.tag("personal-site");
                    e.add_evidence(
                        Evidence::new(
                            SRC,
                            format!("Personal site from GitLab profile of '{}'", user.username),
                        )
                        .with_attr("source_field", "website_url"),
                    );
                }
            }
            result.push(e);
        }
    }

    // Location → coarse Address.
    if let Some(loc) = user.location.as_deref()
        && let Some(mut a) = profile_kit::location_address(loc, 0.38, scan_id)
    {
        a.tag("gitlab");
        a.tag("self-asserted");
        a.tag("geo-hint");
        a.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "Self-reported location from GitLab profile of '{}'",
                    user.username
                ),
            )
            .with_attr("source_field", "location")
            .with_attr("gitlab_user", &user.username),
        );
        result.push(a);
        if let Some(mut c) = profile_kit::location_coordinates(loc, 0.28, scan_id) {
            c.tag("gitlab");
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

    // Bio: extract emails.
    if let Some(bio) = user.bio.as_deref() {
        for mut e in profile_kit::bio_emails(bio, 0.72, scan_id) {
            e.tag("gitlab");
            e.tag("public-profile");
            e.add_evidence(
                Evidence::new(SRC, format!("Email in GitLab bio of '{}'", user.username))
                    .with_attr("source", "gitlab_bio"),
            );
            result.push(e);
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
        twitter: Option<&str>,
        website: Option<&str>,
        location: Option<&str>,
        org: Option<&str>,
    ) -> GlUser {
        GlUser {
            username: username.to_string(),
            name: name.map(str::to_string),
            public_email: None,
            bio: None,
            website_url: website.map(str::to_string),
            location: location.map(str::to_string),
            organization: org.map(str::to_string),
            twitter: twitter.map(str::to_string),
            linkedin: None,
            created_at: Some("2019-01-01T00:00:00Z".to_string()),
        }
    }

    #[test]
    fn builds_username_entity_confirmed_on_gitlab() {
        let user = make_user("gluser", None, None, None, None, None);
        let ents = build_entities(user, "scan-gl-001");
        let u = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "gluser");
        assert!(u.is_some(), "must emit Username entity");
        assert!((u.unwrap().confidence - 0.90).abs() < 0.01);
        assert!(u.unwrap().has_tag("gitlab") && u.unwrap().has_tag("code"));
    }

    #[test]
    fn emits_person_from_full_name() {
        let user = make_user("gluser", Some("Alice Coder"), None, None, None, None);
        let ents = build_entities(user, "scan-gl-002");
        let p = ents.iter().find(|e| e.kind == EntityKind::Person);
        assert!(p.is_some(), "must emit Person from multi-word name");
        assert_eq!(p.unwrap().value, "Alice Coder");
    }

    #[test]
    fn emits_twitter_pivot_stripping_at() {
        let user = make_user("gluser", None, Some("@alicetw"), None, None, None);
        let ents = build_entities(user, "scan-gl-003");
        let tw = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.has_tag("twitter"));
        assert_eq!(tw.map(|e| e.value.as_str()), Some("alicetw"));
    }

    #[test]
    fn emits_website_url_and_domain() {
        let user = make_user("gluser", None, None, Some("https://alice.dev"), None, None);
        let ents = build_entities(user, "scan-gl-004");
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityKind::Url && e.value == "https://alice.dev")
        );
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityKind::Domain && e.value == "alice.dev")
        );
    }

    #[test]
    fn emits_address_from_location() {
        let user = make_user("gluser", None, None, None, Some("Berlin, DE"), None);
        let ents = build_entities(user, "scan-gl-005");
        let a = ents.iter().find(|e| e.kind == EntityKind::Address);
        assert!(a.is_some());
        assert_eq!(a.unwrap().value, "Berlin, DE");
        assert!(a.unwrap().has_tag("self-asserted"));
    }

    #[test]
    fn emits_organisation_from_org_field() {
        let user = make_user("gluser", None, None, None, None, Some("Acme Corp"));
        let ents = build_entities(user, "scan-gl-006");
        let o = ents.iter().find(|e| e.kind == EntityKind::Organisation);
        assert!(o.is_some(), "must emit Organisation from org field");
        assert_eq!(o.unwrap().value, "Acme Corp");
    }

    #[test]
    fn no_entities_for_absent_optional_fields() {
        let user = make_user("quietuser", None, None, None, None, None);
        let ents = build_entities(user, "scan-gl-007");
        assert_eq!(ents.len(), 1, "only Username when no optional fields");
        assert_eq!(ents[0].kind, EntityKind::Username);
    }

    #[test]
    fn emits_public_email_the_keyless_endpoint_actually_returns() {
        // `public_email` is the one rich field the unauthenticated
        // /users?username= response carries (confirmed live) — it must surface as
        // a high-confidence Email, not be dropped.
        let mut user = make_user("gluser", None, None, None, None, None);
        user.public_email = Some("dev@example.com".to_string());
        let ents = build_entities(user, "scan-gl-email");
        let em = ents
            .iter()
            .find(|e| e.kind == EntityKind::Email && e.value == "dev@example.com")
            .expect("public_email → Email entity");
        assert!(em.has_tag("gitlab") && em.has_tag("public-profile"));
        assert!((em.confidence - 0.85).abs() < 0.01);
        // A blank / malformed public_email is not surfaced.
        let mut u2 = make_user("gluser", None, None, None, None, None);
        u2.public_email = Some(String::new());
        assert!(
            build_entities(u2, "s")
                .iter()
                .all(|e| e.kind != EntityKind::Email)
        );
    }
}
