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

use super::profile_kit;
use crate::core::{
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
        "Codeberg account lookup (name, bio, website, location) via public Forgejo API"
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
    let mut u = Entity::new(EntityKind::Username, &user.login, 0.88, scan_id);
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

    // Personal website URL + Domain. The Url and Domain carry distinct evidence,
    // so the kit's stable [Url, Domain] ordering is decorated per-kind.
    if let Some(site) = user.website.as_deref() {
        for mut e in profile_kit::website_url_and_domain(site, 0.72, 0.65, scan_id) {
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
    }

    // Bio/description — extract emails.
    if let Some(bio) = user.description.as_deref() {
        for mut e in profile_kit::bio_emails(bio, 0.70, scan_id, 5) {
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
            description: description.map(str::to_string),
            location: location.map(str::to_string),
            website: website.map(str::to_string),
            html_url: Some(format!("https://codeberg.org/{login}")),
            created: Some("2021-03-15T00:00:00Z".to_string()),
        }
    }

    #[test]
    fn builds_username_entity_confirmed_on_codeberg() {
        let user = make_user("alice", None, None, None, None);
        let ents = build_entities(user, "scan-cb-001");
        let u = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "alice");
        assert!(u.is_some(), "must emit Username entity");
        assert!((u.unwrap().confidence - 0.88).abs() < 0.01);
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
