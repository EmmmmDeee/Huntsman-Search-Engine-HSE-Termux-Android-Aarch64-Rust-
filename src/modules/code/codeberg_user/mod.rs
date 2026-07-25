//! Codeberg user lookup. Free, no key — the Forgejo/Gitea compatible
//! public REST API served by Codeberg.org (a German non-profit).
//!
//! Endpoint: `GET https://codeberg.org/api/v1/users/{username}`
//! Returns a JSON user object or 404 for unknown handles.
//!
//! ```json
//! {"id":1,"login":"alice","full_name":"Alice Dev",
//!  "description":"FOSS developer","location":"Berlin, DE",
//!  "website":"https://alice.dev","html_url":"https://codeberg.org/alice",
//!  "created":"2021-03-15T00:00:00Z"}
//! ```
//!
//! Why it earns a place in the keyless set: Codeberg is the largest
//! privacy-respecting, non-commercial code-hosting platform in Europe —
//! tens of thousands of FOSS developers host their work here exclusively
//! or additionally. Many security researchers, privacy advocates, and
//! European developers who minimise GitHub/GitLab exposure maintain an
//! active Codeberg presence. As a distinct `code`-family source it adds
//! genuine cross-service diversity for AU-045 multi-service identity
//! corroboration. The Forgejo API is stable, public, and rate-limit-free
//! for non-authenticated read queries on public data. Official, keyless.

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
use crate::util::http::fetch_json_or_404;

const SRC: &str = "codeberg_user";

pub struct CodebergUser;

#[derive(Deserialize)]
pub(super) struct CbUser {
    pub(super) login: String,
    #[serde(default)]
    pub(super) full_name: Option<String>,
    /// Public email the user chose to show. Same top-level `email` field the
    /// sibling `gitea_user` (identical Forgejo API) harvests — previously
    /// dropped here, so a real published address was silently lost.
    #[serde(default)]
    pub(super) email: Option<String>,
    #[serde(default)]
    pub(super) description: Option<String>,
    #[serde(default)]
    pub(super) location: Option<String>,
    #[serde(default)]
    pub(super) website: Option<String>,
    #[serde(default)]
    pub(super) html_url: Option<String>,
    #[serde(default)]
    pub(super) created: Option<String>,
}

#[async_trait]
impl Module for CodebergUser {
    fn name(&self) -> &'static str {
        "codeberg_user"
    }

    fn description(&self) -> &'static str {
        "Codeberg account recon — enumerates name, bio, website, and location via the public Forgejo API"
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
        // Code repository — T1593.003 Search Code Repositories.
        // Bio may surface email — T1589.002.
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
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        // Forgejo/Gitea usernames: 1–40 chars, letters/digits/hyphens.
        if handle.is_empty() || handle.len() > 40 {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://codeberg.org/api/v1/users/{}",
            crate::util::http::urlencode(handle)
        );
        let user: Option<CbUser> = fetch_json_or_404(&ctx.http, SRC, &url).await?;
        let user = match user.filter(|u| u.login.eq_ignore_ascii_case(handle)) {
            Some(u) => u,
            None => return Ok(ModuleResult::new()),
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(user, &ctx.scan_id);
        Ok(result)
    }
}

/// Pure account→entity mapping.
pub(super) fn build_entities(user: CbUser, scan_id: &str) -> Vec<Entity> {
    let mut result = ModuleResult::new();

    let profile_url = user.html_url.as_deref().unwrap_or_default().to_string();

    let mut ev = Evidence::new(SRC, format!("Codeberg account '{}'", user.login)).with_attr(
        "profile_url",
        if profile_url.is_empty() {
            format!("https://codeberg.org/{}", user.login)
        } else {
            profile_url.clone()
        },
    );
    if let Some(ref ts) = user.created {
        ev = ev.with_attr("created_at", ts);
    }

    // Confirmed-on-Codeberg username.
    let mut u = Entity::new(
        EntityKind::Username,
        &user.login,
        confidence::EXPERT,
        scan_id,
    );
    u.tag("codeberg");
    u.tag("code");
    u.add_evidence(ev.clone());
    result.push(u);

    // Profile URL.
    let purl = if profile_url.starts_with("http") {
        profile_url.clone()
    } else {
        format!("https://codeberg.org/{}", user.login)
    };
    let mut url_e = Entity::new(EntityKind::Url, &purl, 0.78, scan_id);
    url_e.tag("codeberg");
    url_e.add_evidence(Evidence::new(
        SRC,
        format!("Codeberg profile URL for '{}'", user.login),
    ));
    result.push(url_e);

    // Real name → Person (≥2 tokens, non-placeholder).
    if let Some(name) = user.full_name.as_deref()
        && let Some(mut p) = profile_kit::person_from_name(name, 0.72, scan_id)
    {
        p.tag("codeberg");
        p.tag("derived");
        p.add_evidence(
            Evidence::new(
                SRC,
                format!("Real name from Codeberg account '{}'", user.login),
            )
            .with_attr("codeberg_username", &user.login),
        );
        result.push(p);
    }

    // Public email — the top-level `email` field (the sibling gitea_user
    // harvests it; it was dropped here). Skip forge no-reply masking
    // addresses (`user@noreply.codeberg.org`) — those are privacy
    // placeholders, not a real contact pivot.
    if let Some(email) = user.email.as_deref() {
        let email = email.trim();
        if email.contains('@') && !crate::util::domains::is_noreply_email_domain(email) {
            let mut em = Entity::new(EntityKind::Email, email, 0.78, scan_id);
            em.tag("codeberg");
            em.tag("public-profile");
            em.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Public email from Codeberg profile of '{}'", user.login),
                )
                .with_attr("source_field", "email"),
            );
            result.push(em);
        }
    }

    // Personal website URL + Domain. The Url and Domain carry distinct evidence,
    // so the kit's stable [Url, Domain] ordering is decorated per-kind.
    if let Some(site) = user.website.as_deref() {
        for mut e in profile_kit::website_url_and_domain(site, 0.72, confidence::HIGH, scan_id) {
            match e.kind {
                EntityKind::Domain => {
                    e.tag("codeberg");
                    e.tag("derived");
                    e.add_evidence(
                        Evidence::new(
                            SRC,
                            format!("Domain from Codeberg profile of '{}'", user.login),
                        )
                        .with_attr("source_url", site)
                        .with_attr("codeberg_user", &user.login),
                    );
                }
                _ => {
                    e.tag("codeberg");
                    e.tag("personal-site");
                    e.add_evidence(
                        Evidence::new(
                            SRC,
                            format!("Personal site from Codeberg profile of '{}'", user.login),
                        )
                        .with_attr("source_field", "website"),
                    );
                }
            }
            result.push(e);
        }
    }

    // Location → Address.
    if let Some(loc) = user.location.as_deref()
        && let Some(mut a) = profile_kit::location_address(loc, 0.38, scan_id)
    {
        a.tag("codeberg");
        a.tag("self-asserted");
        a.tag("geo-hint");
        a.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "Self-reported location from Codeberg profile of '{}'",
                    user.login
                ),
            )
            .with_attr("source_field", "location")
            .with_attr("codeberg_user", &user.login),
        );
        result.push(a);
        if let Some(mut c) = profile_kit::location_coordinates(loc, 0.28, scan_id) {
            c.tag("codeberg");
            c.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Geocode of self-reported location for '{}'", user.login),
                )
                .with_attr("source_field", "location"),
            );
            result.push(c);
        }
    }

    // Bio/description — extract emails.
    if let Some(bio) = user.description.as_deref() {
        for mut e in profile_kit::bio_emails(bio, confidence::HIGH_PLUS, scan_id) {
            e.tag("codeberg");
            e.tag("public-profile");
            e.add_evidence(
                Evidence::new(SRC, format!("Email in Codeberg bio of '{}'", user.login))
                    .with_attr("source", "codeberg_bio"),
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
        login: &str,
        full_name: Option<&str>,
        description: Option<&str>,
        website: Option<&str>,
        location: Option<&str>,
    ) -> CbUser {
        CbUser {
            login: login.to_string(),
            full_name: full_name.map(str::to_string),
            email: None,
            description: description.map(str::to_string),
            location: location.map(str::to_string),
            website: website.map(str::to_string),
            html_url: Some(format!("https://codeberg.org/{login}")),
            created: Some("2021-03-15T00:00:00Z".to_string()),
        }
    }

    #[test]
    fn emits_public_email_from_top_level_field() {
        // The top-level `email` field the sibling gitea_user harvests but this
        // module used to drop.
        let mut user = make_user("alice", None, None, None, None);
        user.email = Some("alice@personal.dev".to_string());
        let ents = build_entities(user, "scan-cb-email");
        let em = ents.iter().find(|e| e.kind == EntityKind::Email);
        assert!(
            em.is_some(),
            "must emit Email from the top-level email field"
        );
        assert_eq!(em.unwrap().value, "alice@personal.dev");
        assert!(em.unwrap().has_tag("codeberg"));
    }

    #[test]
    fn skips_forge_noreply_masking_email() {
        // A `@noreply.codeberg.org` masking address is a privacy placeholder,
        // not a real contact — it must NOT become an Email finding (and both
        // Forgejo siblings must agree on this).
        let mut user = make_user("alice", None, None, None, None);
        user.email = Some("alice@noreply.codeberg.org".to_string());
        let ents = build_entities(user, "scan-cb-noreply");
        assert!(
            ents.iter().all(|e| e.kind != EntityKind::Email),
            "a forge no-reply masking address must not seed an Email finding"
        );
    }

    #[test]
    fn deserialises_real_codeberg_shape_including_top_level_email() {
        // Regression for the dropped field: the pre-fix `CbUser` had no `email`,
        // so a real published address in the top-level field was lost.
        let body = r#"{
            "login": "alice",
            "full_name": "Alice Dev",
            "email": "alice@alice.dev",
            "description": "FOSS developer",
            "website": "https://alice.dev",
            "html_url": "https://codeberg.org/alice",
            "created": "2021-03-15T00:00:00Z"
        }"#;
        let user: CbUser = serde_json::from_str(body).expect("real codeberg body must deserialise");
        assert_eq!(user.email.as_deref(), Some("alice@alice.dev"));
        let ents = build_entities(user, "scan-cb-real");
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityKind::Email && e.value == "alice@alice.dev"),
            "the real published email must be recovered from the top-level field"
        );
    }

    #[test]
    fn builds_username_entity_confirmed_on_codeberg() {
        let user = make_user("alice", None, None, None, None);
        let ents = build_entities(user, "scan-cb-001");
        let u = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "alice");
        assert!(u.is_some(), "must emit Username entity");
        assert!((u.unwrap().confidence - confidence::EXPERT).abs() < 0.01);
        assert!(u.unwrap().has_tag("codeberg") && u.unwrap().has_tag("code"));
    }

    #[test]
    fn emits_person_from_full_name() {
        let user = make_user("alice", Some("Alice Developer"), None, None, None);
        let ents = build_entities(user, "scan-cb-002");
        let p = ents.iter().find(|e| e.kind == EntityKind::Person);
        assert!(p.is_some(), "must emit Person from multi-word full name");
        assert_eq!(p.unwrap().value, "Alice Developer");
    }

    #[test]
    fn emits_website_url_and_domain() {
        let user = make_user("alice", None, None, Some("https://alice.dev"), None);
        let ents = build_entities(user, "scan-cb-003");
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
        let user = make_user("alice", None, None, None, Some("Berlin, DE"));
        let ents = build_entities(user, "scan-cb-004");
        let a = ents.iter().find(|e| e.kind == EntityKind::Address);
        assert!(a.is_some(), "must emit Address from location");
        assert_eq!(a.unwrap().value, "Berlin, DE");
        assert!(a.unwrap().has_tag("self-asserted"));
    }

    #[test]
    fn emits_email_from_bio() {
        let user = make_user(
            "alice",
            None,
            Some("Contact me at alice@example.com"),
            None,
            None,
        );
        let ents = build_entities(user, "scan-cb-005");
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityKind::Email && e.value == "alice@example.com"),
            "must extract email from bio"
        );
    }

    #[test]
    fn no_person_from_single_token_name() {
        let user = make_user("alice", Some("alice"), None, None, None);
        let ents = build_entities(user, "scan-cb-006");
        assert!(
            ents.iter().all(|e| e.kind != EntityKind::Person),
            "single-token full_name must not emit a Person"
        );
    }
}
