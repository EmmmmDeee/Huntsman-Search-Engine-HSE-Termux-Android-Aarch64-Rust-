//! Bluesky / AT Protocol user lookup. Free, no key — the official public
//! AppView API served by Bluesky Social.
//!
//! Endpoints tried in order:
//!   `GET https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={handle}.bsky.social`
//!   `GET https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={handle}`
//!
//! The first covers the common `alice.bsky.social` handle space. The second
//! catches custom-domain handles (e.g. `alice.dev`) — an AT Protocol feature
//! that lets users anchor their identity to a domain they control; when a user
//! has a custom-domain handle the domain is a high-confidence entity.
//!
//! Why it earns a place in the keyless set: Bluesky crossed 20 M+ registered
//! users in 2024 and continues fast growth — it is an independent social
//! platform with a distinct user population from Twitter/X and Mastodon. The
//! profile surfaces `displayName`, `description` (bio), and the `handle`
//! itself (which may be a personal domain — a rare direct domain pivot). As
//! an independent `social`-family source it contributes a distinct
//! corroboration pathway for AU-045 multi-service identity confirmation.
//! Official, stable, keyless, CORS-open.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json_or_404;

const SRC: &str = "bluesky_user";
const API: &str = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile";

pub struct BlueskyUser;

#[derive(Deserialize)]
pub(super) struct BskyProfile {
    /// The user's current handle, e.g. `alice.bsky.social` or `alice.dev`.
    pub(super) handle: String,
    #[serde(rename = "displayName", default)]
    pub(super) display_name: Option<String>,
    #[serde(default)]
    pub(super) description: Option<String>,
    /// Canonical decentralised identifier, e.g. `did:plc:…`.
    #[serde(default)]
    pub(super) did: Option<String>,
}

#[async_trait]
impl Module for BlueskyUser {
    fn name(&self) -> &'static str {
        "bluesky_user"
    }

    fn description(&self) -> &'static str {
        "Bluesky account lookup (display name, bio, custom-domain handle) via public AppView API"
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
        // Open social platform — T1593.001 Search Open Websites/Domains.
        // Bio may expose email — T1589.002.
        &["T1589.002", "T1593.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Username,
            EntityKind::Person,
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
        if handle.is_empty() || handle.len() > 253 {
            return Ok(ModuleResult::new());
        }

        // Try `{handle}.bsky.social` first (most common), then bare `{handle}`
        // for custom-domain accounts.
        let bsky_handle = format!("{handle}.bsky.social");
        let url1 = format!("{API}?actor={}", crate::util::http::urlencode(&bsky_handle));
        let url2 = format!("{API}?actor={}", crate::util::http::urlencode(handle));

        let profile: Option<BskyProfile> = fetch_json_or_404(&ctx.http, SRC, &url1).await?;
        let profile = if profile.is_some() {
            profile
        } else {
            fetch_json_or_404(&ctx.http, SRC, &url2).await?
        };

        let Some(profile) = profile else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(profile, &ctx.scan_id);
        Ok(result)
    }
}

/// Pure profile→entity mapping. Separated so every branch is unit-testable.
pub(super) fn build_entities(profile: BskyProfile, scan_id: &str) -> Vec<Entity> {
    let mut result = ModuleResult::new();

    // The handle's bsky.social suffix is stripped so the bare username
    // deduplicates with the same handle discovered by other modules.
    let bare_handle = profile
        .handle
        .strip_suffix(".bsky.social")
        .unwrap_or(&profile.handle);

    let mut ev = Evidence::new(SRC, format!("Bluesky account '{}'", profile.handle))
        .with_attr("bsky_handle", &profile.handle);
    if let Some(ref did) = profile.did {
        ev = ev.with_attr("did", did);
    }

    // Confirmed-on-Bluesky username.
    let mut u = Entity::new(EntityKind::Username, bare_handle, 0.85, scan_id);
    u.tag("bluesky");
    u.tag("social");
    u.add_evidence(ev.clone());
    result.push(u);

    // Custom-domain handle → Domain entity. An AT Protocol custom-domain
    // handle means the user controls that domain's DNS TXT record — a
    // high-confidence domain attribution.
    if profile.handle.contains('.') && !profile.handle.ends_with(".bsky.social") {
        // The whole handle IS the domain (e.g. `alice.dev`).
        let domain = profile.handle.trim_end_matches('.');
        if domain.contains('.') {
            let mut d = Entity::new(EntityKind::Domain, domain, 0.82, scan_id);
            d.tag("bluesky");
            d.tag("custom-handle");
            d.add_evidence(
                ev.clone()
                    .with_attr("attribution", "AT Protocol custom-domain handle"),
            );
            result.push(d);
        }
    }

    // Profile URL on bsky.app.
    let profile_url = format!("https://bsky.app/profile/{}", profile.handle);
    let mut url_e = Entity::new(EntityKind::Url, &profile_url, 0.75, scan_id);
    url_e.tag("bluesky");
    url_e.add_evidence(Evidence::new(
        SRC,
        format!("Bluesky profile URL for '{}'", profile.handle),
    ));
    result.push(url_e);

    // Real name → Person (≥2 whitespace-separated tokens, non-placeholder).
    if let Some(ref name) = profile.display_name
        && name.split_whitespace().count() >= 2
        && !crate::core::validation::is_placeholder_entity(&EntityKind::Person, name)
    {
        let mut p = Entity::new(EntityKind::Person, name.trim(), 0.60, scan_id);
        p.tag("bluesky");
        p.tag("derived");
        p.add_evidence(
            Evidence::new(
                SRC,
                format!("Display name from Bluesky account '{}'", profile.handle),
            )
            .with_attr("bsky_handle", &profile.handle),
        );
        result.push(p);
    }

    // Bio — extract emails and URLs.
    if let Some(bio) = profile.description.as_deref() {
        for email in crate::util::extract::emails(bio).into_iter().take(5) {
            let mut e = Entity::new(EntityKind::Email, &email, 0.70, scan_id);
            e.tag("bluesky");
            e.tag("public-profile");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Email in Bluesky bio of '{}'", profile.handle),
                )
                .with_attr("source", "bluesky_bio"),
            );
            result.push(e);
        }
        let mut seen_urls: std::collections::HashSet<String> = std::collections::HashSet::new();
        for m in crate::util::extract::URL_RE.find_iter(bio).take(5) {
            let link = m.as_str().trim_end_matches(['.', ',', ')']);
            if !seen_urls.insert(link.to_string()) {
                continue;
            }
            // Skip the bsky.app URL we already emitted.
            if link.contains("bsky.app") {
                continue;
            }
            let mut url_e = Entity::new(EntityKind::Url, link, 0.62, scan_id);
            url_e.tag("bluesky");
            url_e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Link in Bluesky bio of '{}'", profile.handle),
                )
                .with_attr("source", "bluesky_bio"),
            );
            result.push(url_e);

            if let Some(host) = crate::util::url_util::host_from_url(link)
                && host.contains('.')
                && !matches!(
                    host.as_str(),
                    "bsky.app"
                        | "bsky.social"
                        | "twitter.com"
                        | "x.com"
                        | "github.com"
                        | "instagram.com"
                        | "linkedin.com"
                )
            {
                let mut d = Entity::new(EntityKind::Domain, &host, 0.55, scan_id);
                d.tag("bluesky");
                d.tag("derived");
                d.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Domain from Bluesky bio of '{}'", profile.handle),
                    )
                    .with_attr("source_url", link),
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

    fn make_profile(
        handle: &str,
        display_name: Option<&str>,
        description: Option<&str>,
    ) -> BskyProfile {
        BskyProfile {
            handle: handle.to_string(),
            display_name: display_name.map(str::to_string),
            description: description.map(str::to_string),
            did: Some("did:plc:abc123".to_string()),
        }
    }

    #[test]
    fn builds_username_strips_bsky_social_suffix() {
        let p = make_profile("alice.bsky.social", None, None);
        let ents = build_entities(p, "scan-bsky-001");
        let u = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "alice");
        assert!(u.is_some(), "must strip .bsky.social and emit bare username");
        assert!((u.unwrap().confidence - 0.85).abs() < 0.01);
        assert!(u.unwrap().has_tag("bluesky"));
    }

    #[test]
    fn custom_domain_handle_emits_domain_entity() {
        let p = make_profile("alice.dev", None, None);
        let ents = build_entities(p, "scan-bsky-002");
        let d = ents
            .iter()
            .find(|e| e.kind == EntityKind::Domain && e.value == "alice.dev");
        assert!(d.is_some(), "custom-domain handle must emit a Domain entity");
        assert!(d.unwrap().has_tag("custom-handle"));
        // Confidence should be high (controls DNS TXT for AT Protocol)
        assert!(d.unwrap().confidence >= 0.80);
    }

    #[test]
    fn emits_person_from_multi_word_display_name() {
        let p = make_profile("alice.bsky.social", Some("Alice Example"), None);
        let ents = build_entities(p, "scan-bsky-003");
        let person = ents.iter().find(|e| e.kind == EntityKind::Person);
        assert!(person.is_some(), "must emit Person from multi-word display name");
        assert_eq!(person.unwrap().value, "Alice Example");
    }

    #[test]
    fn no_person_for_single_word_name() {
        let p = make_profile("alice.bsky.social", Some("alice"), None);
        let ents = build_entities(p, "scan-bsky-004");
        assert!(
            ents.iter().all(|e| e.kind != EntityKind::Person),
            "single-token display name must not produce a Person entity"
        );
    }

    #[test]
    fn emits_email_and_url_from_bio() {
        let p = make_profile(
            "alice.bsky.social",
            None,
            Some("Contact: alice@example.com | Blog: https://alice.dev/blog"),
        );
        let ents = build_entities(p, "scan-bsky-005");
        assert!(
            ents.iter().any(|e| e.kind == EntityKind::Email && e.value == "alice@example.com"),
            "must extract email from bio"
        );
        assert!(
            ents.iter().any(|e| e.kind == EntityKind::Url && e.value.contains("alice.dev/blog")),
            "must extract URL from bio"
        );
        assert!(
            ents.iter().any(|e| e.kind == EntityKind::Domain && e.value == "alice.dev"),
            "must extract domain from bio URL"
        );
    }

    #[test]
    fn emits_profile_url() {
        let p = make_profile("alice.bsky.social", None, None);
        let ents = build_entities(p, "scan-bsky-006");
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityKind::Url
                    && e.value == "https://bsky.app/profile/alice.bsky.social"),
            "must emit canonical bsky.app profile URL"
        );
    }

    #[test]
    fn no_entities_beyond_username_and_profile_url_for_empty_profile() {
        let p = make_profile("quiet.bsky.social", None, None);
        let ents = build_entities(p, "scan-bsky-007");
        assert_eq!(ents.len(), 2, "username + profile URL only when no optional fields");
    }
}
