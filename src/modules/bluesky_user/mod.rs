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
//! corroboration pathway for AU-045 multi-service identity confirmation. The
//! profile's `createdAt` further dates the account (an `account-age` signal the
//! keyed stacks rarely expose). Official, stable, keyless, CORS-open.

use async_trait::async_trait;
use serde::Deserialize;

use super::profile_kit;
use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json_or_absent;

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
    /// Account creation timestamp (ISO-8601), e.g. `2023-04-01T00:00:00.000Z`.
    /// Dates the account — an age signal the keyed stacks rarely expose.
    #[serde(rename = "createdAt", default)]
    pub(super) created_at: Option<String>,
}

#[async_trait]
impl Module for BlueskyUser {
    fn name(&self) -> &'static str {
        "bluesky_user"
    }

    fn description(&self) -> &'static str {
        "Bluesky account recon — unmasks display name, bio, and custom-domain handle via the public AppView API"
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

        // Only issue requests that CAN succeed. An AT Protocol handle is a series
        // of DNS labels; `getProfile` rejects a structurally-invalid `actor` with
        // HTTP 400 "Invalid AT identifier". `fetch_json_or_absent` swallows that
        // 400 as a clean miss (so it never trips the breaker), but the round-trip
        // is still pure waste on every scan — and both candidate forms are
        // guaranteed to fail for many usernames:
        //   * url1 `{handle}.bsky.social` needs `handle` to be ONE valid DNS label
        //     (so `_ryno_23`, with an underscore, can never form a valid handle).
        //   * url2 bare `{handle}` is only a valid actor when `handle` is itself a
        //     dotted custom-domain handle (`alice.dev`); a plain `alice` bare is
        //     never a valid handle, so probing it always 400s.
        // Gating each request on its own local validity check removes those doomed
        // round-trips — the common plain-username path drops from two requests to
        // one, and a non-handle-shaped username (underscores, etc.) issues none.
        let mut profile: Option<BskyProfile> = None;
        if is_valid_dns_label(handle) {
            let bsky_handle = format!("{handle}.bsky.social");
            let url1 = format!("{API}?actor={}", crate::util::http::urlencode(&bsky_handle));
            // `fetch_json_or_absent`: Bluesky answers a non-existent (or invalid)
            // handle with HTTP 400, not 404, so treat 400 as a clean negative —
            // otherwise a name scan probing several missing handles would trip the
            // engine breaker and suppress Bluesky for the real handles too.
            profile = fetch_json_or_absent(&ctx.http, SRC, &url1).await?;
        }
        if profile.is_none() && is_custom_domain_handle(handle) {
            let url2 = format!("{API}?actor={}", crate::util::http::urlencode(handle));
            profile = fetch_json_or_absent(&ctx.http, SRC, &url2).await?;
        }

        let Some(profile) = profile else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(profile, &ctx.scan_id);
        Ok(result)
    }
}

/// True if `s` is a single valid DNS label per the AT Protocol handle grammar:
/// 1–63 chars, ASCII alphanumerics and hyphens only, not starting or ending with
/// a hyphen. **Pure.** Underscores (common in usernames — `_ryno_23`) are NOT
/// permitted, so such a username can never form a valid `{s}.bsky.social` handle
/// and the `.bsky.social` probe is skipped rather than issued and 400'd.
fn is_valid_dns_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

/// True if `s` is a plausible dotted custom-domain AT handle (`alice.dev`): it
/// contains a dot and EVERY dot-separated label is a valid DNS label. **Pure.**
/// A plain single-token username (`alice`) is not a valid bare `actor`, so the
/// bare-handle probe is issued only for domain-shaped inputs.
fn is_custom_domain_handle(s: &str) -> bool {
    s.contains('.') && s.split('.').all(is_valid_dns_label)
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
    // The `createdAt` field dates the account — a creation-age signal carried as
    // its UTC date (the leading `YYYY-MM-DD` of the ISO-8601 timestamp).
    let created_date = profile
        .created_at
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|ts| ts.get(..10).unwrap_or(ts).to_string());
    if let Some(ref date) = created_date {
        ev = ev.with_attr("created_at", date);
    }

    // Confirmed-on-Bluesky username.
    let mut u = Entity::new(EntityKind::Username, bare_handle, 0.85, scan_id);
    u.tag("bluesky");
    u.tag("social");
    if created_date.is_some() {
        u.tag("account-age");
    }
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
        && let Some(mut p) = profile_kit::person_from_name(name, 0.60, scan_id)
    {
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
        for email in crate::util::extract::emails(bio) {
            let mut e = Entity::new(EntityKind::Email, &email, 0.70, scan_id);
            e.tag("bluesky");
            e.tag("public-profile");
            e.add_evidence(
                Evidence::new(SRC, format!("Email in Bluesky bio of '{}'", profile.handle))
                    .with_attr("source", "bluesky_bio"),
            );
            result.push(e);
        }
        for link in crate::util::extract::urls(bio) {
            let link = link.as_str();
            // Skip the bsky.app URL we already emitted.
            if link.contains("bsky.app") {
                continue;
            }
            let mut url_e = Entity::new(EntityKind::Url, link, 0.62, scan_id);
            url_e.tag("bluesky");
            url_e.add_evidence(
                Evidence::new(SRC, format!("Link in Bluesky bio of '{}'", profile.handle))
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
            created_at: None,
        }
    }

    #[test]
    fn builds_username_strips_bsky_social_suffix() {
        let p = make_profile("alice.bsky.social", None, None);
        let ents = build_entities(p, "scan-bsky-001");
        let u = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "alice");
        assert!(
            u.is_some(),
            "must strip .bsky.social and emit bare username"
        );
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
        assert!(
            d.is_some(),
            "custom-domain handle must emit a Domain entity"
        );
        assert!(d.unwrap().has_tag("custom-handle"));
        // Confidence should be high (controls DNS TXT for AT Protocol)
        assert!(d.unwrap().confidence >= 0.80);
    }

    #[test]
    fn emits_person_from_multi_word_display_name() {
        let p = make_profile("alice.bsky.social", Some("Alice Example"), None);
        let ents = build_entities(p, "scan-bsky-003");
        let person = ents.iter().find(|e| e.kind == EntityKind::Person);
        assert!(
            person.is_some(),
            "must emit Person from multi-word display name"
        );
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
            ents.iter()
                .any(|e| e.kind == EntityKind::Email && e.value == "alice@example.com"),
            "must extract email from bio"
        );
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityKind::Url && e.value.contains("alice.dev/blog")),
            "must extract URL from bio"
        );
        assert!(
            ents.iter()
                .any(|e| e.kind == EntityKind::Domain && e.value == "alice.dev"),
            "must extract domain from bio URL"
        );
    }

    #[test]
    fn emits_profile_url() {
        let p = make_profile("alice.bsky.social", None, None);
        let ents = build_entities(p, "scan-bsky-006");
        assert!(
            ents.iter().any(|e| e.kind == EntityKind::Url
                && e.value == "https://bsky.app/profile/alice.bsky.social"),
            "must emit canonical bsky.app profile URL"
        );
    }

    #[test]
    fn no_entities_beyond_username_and_profile_url_for_empty_profile() {
        let p = make_profile("quiet.bsky.social", None, None);
        let ents = build_entities(p, "scan-bsky-007");
        assert_eq!(
            ents.len(),
            2,
            "username + profile URL only when no optional fields"
        );
    }

    #[test]
    fn created_at_dates_the_account_as_age_evidence() {
        let mut p = make_profile("alice.bsky.social", None, None);
        p.created_at = Some("2023-04-01T00:00:00.000Z".to_string());
        let ents = build_entities(p, "scan-bsky-008");
        let u = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "alice")
            .expect("username entity");
        // The account-age tag flags it as a creation-date signal,
        assert!(
            u.has_tag("account-age"),
            "created account must be tagged account-age"
        );
        // and the ISO timestamp is reduced to its UTC date in evidence.
        assert!(
            u.evidence.iter().any(|ev| ev
                .attributes
                .get("created_at")
                .is_some_and(|v| v.as_str() == "2023-04-01")),
            "creation date must be carried as `created_at` evidence (YYYY-MM-DD)"
        );
    }

    #[test]
    fn no_account_age_tag_without_created_at() {
        let p = make_profile("alice.bsky.social", None, None);
        let ents = build_entities(p, "scan-bsky-009");
        let u = ents
            .iter()
            .find(|e| e.kind == EntityKind::Username && e.value == "alice")
            .expect("username entity");
        assert!(
            !u.has_tag("account-age"),
            "no account-age tag when createdAt is absent"
        );
    }

    #[test]
    fn plain_username_is_a_valid_bsky_social_label_but_not_a_bare_handle() {
        // `alice` → try `alice.bsky.social` (valid label) but NOT bare `alice`
        // (not domain-shaped), so the doomed second request is skipped.
        assert!(is_valid_dns_label("alice"));
        assert!(is_valid_dns_label("rhino23"));
        assert!(!is_custom_domain_handle("alice"));
    }

    #[test]
    fn underscore_username_forms_no_valid_handle_at_all() {
        // The exact case from a live scan: `_ryno_23.bsky.social` is rejected by
        // getProfile as an "Invalid AT identifier" (underscores aren't DNS-label
        // legal). Neither probe should be issued for it.
        assert!(!is_valid_dns_label("_ryno_23"));
        assert!(!is_custom_domain_handle("_ryno_23"));
        assert!(!is_valid_dns_label("ryno_23"));
        assert!(!is_valid_dns_label("under_score"));
    }

    #[test]
    fn custom_domain_handle_is_probed_bare_not_as_bsky_social() {
        // `alice.dev` → NOT a single label (has a dot), so the `.bsky.social`
        // probe is skipped; it IS a valid custom-domain handle, so the bare
        // request is issued.
        assert!(!is_valid_dns_label("alice.dev"));
        assert!(is_custom_domain_handle("alice.dev"));
        assert!(is_custom_domain_handle("a.b.example.com"));
    }

    #[test]
    fn dns_label_rejects_hyphen_edges_and_overlong_input() {
        assert!(!is_valid_dns_label("-lead"));
        assert!(!is_valid_dns_label("trail-"));
        assert!(is_valid_dns_label("mid-dle"));
        assert!(!is_valid_dns_label(""));
        assert!(!is_valid_dns_label(&"a".repeat(64)));
        assert!(is_valid_dns_label(&"a".repeat(63)));
    }

    #[test]
    fn custom_domain_handle_rejects_an_invalid_label_segment() {
        // A dot alone isn't enough — every segment must be a valid label.
        assert!(!is_custom_domain_handle("bad_label.dev"));
        assert!(!is_custom_domain_handle("ok.-bad"));
        assert!(!is_custom_domain_handle(".leadingdot"));
    }
}
