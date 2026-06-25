//! Lobste.rs user lookup. Free, no key — the official public JSON API.
//!
//! Endpoint: `GET https://lobste.rs/~{username}.json`
//! Returns the public account JSON, or a 404 for unknown handles:
//!
//! ```json
//! {"username":"pg","created_at":"2012-05-01T00:00:00Z","karma":1234,
//!  "about":"…html…","is_moderator":false,
//!  "github_username":"pgraham","twitter_username":"pg",
//!  "invited_by_user":"founder"}
//! ```
//!
//! Why it earns its place in the keyless-API set: Lobste.rs is a curated
//! developer link-aggregation forum distinct from Hacker News and Reddit —
//! independent membership (invite-only), separate karma, separate submissions.
//! A handle confirmed here is an independent **forum**-family signal, so it
//! contributes genuine cross-service diversity to AU-045 multi-service identity
//! confirmation. Critically, the `github_username` and `twitter_username` fields
//! provide direct cross-platform username pivots with no extra round-trip.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::extract::URL_RE;
use crate::util::http::fetch_json_or_404;

const SRC: &str = "lobsters";

pub struct Lobsters;

#[derive(Deserialize)]
pub(super) struct LobstersUser {
    pub(super) username: String,
    #[serde(default)]
    pub(super) created_at: Option<String>,
    #[serde(default)]
    pub(super) karma: Option<i64>,
    #[serde(default)]
    pub(super) about: Option<String>,
    #[serde(default)]
    pub(super) is_moderator: Option<bool>,
    #[serde(default)]
    pub(super) github_username: Option<String>,
    #[serde(default)]
    pub(super) twitter_username: Option<String>,
    #[serde(default)]
    pub(super) invited_by_user: Option<String>,
}

#[async_trait]
impl Module for Lobsters {
    fn name(&self) -> &'static str {
        "lobsters"
    }

    fn description(&self) -> &'static str {
        "Lobste.rs account lookup (karma, bio, GitHub/Twitter cross-links) via public JSON API"
    }

    fn priority(&self) -> u8 {
        104
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Forum profile — no real-name Person entity (only Username + optional
        // bio email/URL). T1589.002 for emails found in bio; T1593.001 for the
        // platform account itself.
        &["T1589.002", "T1593.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Email,
            EntityKind::Url,
            EntityKind::Domain,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let handle = target.value.trim();
        // Lobste.rs usernames: 2–24 chars of [A-Za-z0-9_-].
        if !crate::util::str_util::is_handle(handle, 2, 24) {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://lobste.rs/~{handle}.json");
        let user: Option<LobstersUser> = fetch_json_or_404(&ctx.http, SRC, &url).await?;
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
pub(super) fn build_entities(user: LobstersUser, scan_id: &str) -> Vec<Entity> {
    let mut result = ModuleResult::new();

    let mut u = Entity::new(EntityKind::Username, &user.username, 0.90, scan_id);
    u.tag("lobsters");
    if user.is_moderator == Some(true) {
        u.tag("moderator");
    }
    let mut ev = Evidence::new(SRC, format!("Lobste.rs account '{}'", user.username)).with_attr(
        "profile_url",
        format!("https://lobste.rs/~{}", user.username),
    );
    if let Some(k) = user.karma {
        ev = ev.with_attr("karma", k.to_string());
    }
    if let Some(ref ts) = user.created_at {
        ev = ev.with_attr("created_at", ts);
    }
    if let Some(ref inviter) = user.invited_by_user {
        ev = ev.with_attr("invited_by", inviter);
    }
    u.add_evidence(ev);
    result.push(u);

    // Cross-platform username pivots — direct field, high confidence.
    if let Some(ref gh) = user.github_username
        && !gh.is_empty()
    {
        let mut g = Entity::new(EntityKind::Username, gh, 0.82, scan_id);
        g.tag("github");
        g.tag("lobsters-pivot");
        g.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "GitHub username from Lobste.rs profile of '{}'",
                    user.username
                ),
            )
            .with_attr("source_field", "github_username")
            .with_attr("lobsters_user", &user.username),
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
            t.tag("lobsters-pivot");
            t.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "Twitter/X username from Lobste.rs profile of '{}'",
                        user.username
                    ),
                )
                .with_attr("source_field", "twitter_username")
                .with_attr("lobsters_user", &user.username),
            );
            result.push(t);
        }
    }

    // Bio: extract emails and URLs.
    if let Some(about) = user.about.as_deref() {
        for email in crate::util::extract::emails(about).into_iter().take(5) {
            let mut e = Entity::new(EntityKind::Email, &email, 0.75, scan_id);
            e.tag("lobsters");
            e.tag("public-profile");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Email in Lobste.rs bio of '{}'", user.username),
                )
                .with_attr("source", "lobsters_bio"),
            );
            result.push(e);
        }

        let mut seen_urls: std::collections::HashSet<String> = std::collections::HashSet::new();
        for m in URL_RE.find_iter(about).take(5) {
            let link = m.as_str().trim_end_matches(['.', ',', ')']);
            if !seen_urls.insert(link.to_string()) {
                continue;
            }
            let mut url_e = Entity::new(EntityKind::Url, link, 0.70, scan_id);
            url_e.tag("lobsters");
            url_e.tag("personal-site");
            url_e.add_evidence(
                Evidence::new(SRC, format!("Link in Lobste.rs bio of '{}'", user.username))
                    .with_attr("source", "lobsters_bio"),
            );
            result.push(url_e);

            if let Some(host) = crate::util::url_util::host_from_url(link)
                && host.contains('.')
                && host != "lobste.rs"
            {
                let mut d = Entity::new(EntityKind::Domain, &host, 0.65, scan_id);
                d.tag("lobsters");
                d.tag("derived");
                d.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Domain from Lobste.rs bio of '{}'", user.username),
                    )
                    .with_attr("source_url", link)
                    .with_attr("lobsters_user", &user.username),
                );
                result.push(d);
            }
        }
    }

    result.entities
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_user(
        username: &str,
        karma: i64,
        github: Option<&str>,
        twitter: Option<&str>,
        about: Option<&str>,
    ) -> LobstersUser {
        LobstersUser {
            username: username.to_string(),
            created_at: Some("2015-03-01T00:00:00Z".to_string()),
            karma: Some(karma),
            about: about.map(str::to_string),
            is_moderator: Some(false),
            github_username: github.map(str::to_string),
            twitter_username: twitter.map(str::to_string),
            invited_by_user: None,
        }
    }

    #[test]
    fn builds_username_entity_with_correct_confidence() {
        let user = make_user("devuser", 500, None, None, None);
        let entities = build_entities(user, "scan-lob-001");
        let u = entities
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "devuser");
        assert!(u.is_some(), "must emit Username entity for the account");
        assert!((u.unwrap().confidence - 0.90).abs() < 0.01);
    }

    #[test]
    fn emits_github_username_pivot() {
        let user = make_user("devuser", 500, Some("devuser-gh"), None, None);
        let entities = build_entities(user, "scan-lob-002");
        let gh = entities
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "devuser-gh");
        assert!(gh.is_some(), "must emit GitHub username pivot");
        assert!(
            gh.unwrap().has_tag("github"),
            "pivot entity must carry 'github' tag"
        );
    }

    #[test]
    fn emits_twitter_username_pivot_stripping_at_prefix() {
        let user = make_user("devuser", 200, None, Some("@twitterhandle"), None);
        let entities = build_entities(user, "scan-lob-003");
        let tw = entities
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "twitterhandle");
        assert!(tw.is_some(), "must strip @ and emit Twitter username");
    }

    #[test]
    fn extracts_email_and_url_from_bio() {
        let about = "contact me at dev@example.com or visit https://example.com/about";
        let user = make_user("devuser", 100, None, None, Some(about));
        let entities = build_entities(user, "scan-lob-004");
        assert!(
            entities
                .iter()
                .any(|e| e.kind == EntityKind::Email && e.value == "dev@example.com"),
            "must extract email from bio"
        );
        assert!(
            entities.iter().any(|e| e.kind == EntityKind::Url),
            "must extract URL from bio"
        );
        assert!(
            entities
                .iter()
                .any(|e| e.kind == EntityKind::Domain && e.value == "example.com"),
            "must emit Domain entity from bio URL"
        );
    }

    #[test]
    fn no_entities_for_empty_optional_fields() {
        let user = make_user("quietuser", 10, None, None, None);
        let entities = build_entities(user, "scan-lob-005");
        assert_eq!(
            entities.len(),
            1,
            "only the Username entity when no pivots or bio"
        );
        assert_eq!(entities[0].kind, EntityKind::Username);
    }
}
