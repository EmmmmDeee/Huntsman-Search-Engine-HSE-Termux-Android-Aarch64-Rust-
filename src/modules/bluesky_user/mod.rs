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
//!
//! # Where the handle grammar lives
//! Deciding whether `alice.bsky.social`, `bnewbold.bsky.team` or `alice.dev` is
//! a name a platform issued or a domain the subject proved control of is
//! knowledge about *the protocol and its operators*, not about this endpoint, so
//! it lives in [`crate::util::atproto`] and is shared with [`plc_directory`].
//! This module reports the handle in force; `plc_directory` reports every handle
//! the account ever held. Both grade the same handle through one
//! [`handle_domain_confidence`] and stamp one [`DOMAIN_HANDLE_CAVEAT`], because
//! two sources disagreeing about a single fact is precisely what the noisy-OR
//! agreement model cannot see.
//!
//! [`plc_directory`]: crate::modules::plc_directory

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
use crate::util::atproto::{
    DOMAIN_HANDLE_ATTRIBUTION, DOMAIN_HANDLE_CAVEAT, bare_handle, handle_domain_confidence,
    is_dns_label, is_handle, platform_handle_suffix,
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
        // Also emits `Other("bluesky-did")`, which cannot appear in a `const`
        // slice (it owns a `String`); the canonical pivots are the username,
        // derived person, bio email/URL, and custom-domain handle.
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
        if is_dns_label(handle) {
            let bsky_handle = format!("{handle}.bsky.social");
            let url1 = format!("{API}?actor={}", crate::util::http::urlencode(&bsky_handle));
            // `fetch_json_or_absent`: Bluesky answers a non-existent (or invalid)
            // handle with HTTP 400, not 404, so treat 400 as a clean negative —
            // otherwise a name scan probing several missing handles would trip the
            // engine breaker and suppress Bluesky for the real handles too.
            profile = fetch_json_or_absent(&ctx.http, SRC, &url1).await?;
        }
        if profile.is_none() && is_handle(handle) {
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

/// Pure profile→entity mapping. Separated so every branch is unit-testable.
pub(super) fn build_entities(profile: BskyProfile, scan_id: &str) -> Vec<Entity> {
    let mut result = ModuleResult::new();

    // A platform-issued handle collapses to the username inside it, so the bare
    // name deduplicates with the same handle discovered by other modules.
    // `crate::util::atproto` knows the whole platform namespace — `.bsky.team`,
    // `.brid.gy` and `.translate.goog` alongside `.bsky.social` — so a staff or
    // bridged account no longer keeps a suffix that stops it from meeting itself.
    let bare = bare_handle(&profile.handle);

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
    let mut u = Entity::new(
        EntityKind::Username,
        bare,
        confidence::HIGH_PLUSPLUS_PLUS,
        scan_id,
    );
    u.tag("bluesky");
    u.tag("social");
    if created_date.is_some() {
        u.tag("account-age");
    }
    u.add_evidence(ev.clone());
    result.push(u);

    // Canonical AT Protocol DID → its own pivotable entity, `Other(_)` (not
    // `Username`, matching the precedent set by nostr's pubkey): a raw DID fed
    // into username-enumeration modules (github_user, reddit_user, …) would
    // produce noisy, doomed lookups. `Other(_)` is never re-dispatched as a
    // scan target, so it is a searchable, correlatable identity with no scan
    // noise.
    if let Some(ref did) = profile.did
        && !did.is_empty()
    {
        let mut d = Entity::new(
            EntityKind::Other("bluesky-did".into()),
            did,
            confidence::HIGH_PLUSPLUS_PLUS,
            scan_id,
        );
        d.tag("bluesky");
        d.tag("did");
        d.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "Canonical AT Protocol DID for Bluesky account '{}'",
                    profile.handle
                ),
            )
            .with_attr("did", did),
        );
        result.push(d);
    }

    // Custom-domain handle → Domain entity. AT Protocol verifies one by DNS TXT
    // record or `/.well-known`, so the account holder demonstrably controlled the
    // domain. A handle the *platform* issued proves nothing of the sort —
    // emitting `alice.bsky.social` or `alice.translate.goog` as a domain would
    // attribute Bluesky's (or Google's) infrastructure to an individual, so the
    // shared namespace list gates it and label depth grades the rest.
    let domain = profile.handle.trim_end_matches('.');
    if platform_handle_suffix(domain).is_none() && domain.contains('.') {
        let mut d = Entity::new(
            EntityKind::Domain,
            domain,
            // The profile API reports only the handle in force, hence `current`.
            handle_domain_confidence(true, domain),
            scan_id,
        );
        d.tag("bluesky");
        d.tag("custom-handle");
        d.tag("verified-control");
        d.add_evidence(
            ev.clone()
                .with_attr("attribution", DOMAIN_HANDLE_ATTRIBUTION)
                .with_attr("coverage", DOMAIN_HANDLE_CAVEAT),
        );
        result.push(d);
    }

    // Profile URL on bsky.app.
    let profile_url = format!("https://bsky.app/profile/{}", profile.handle);
    let mut url_e = Entity::new(
        EntityKind::Url,
        &profile_url,
        confidence::VERY_HIGH,
        scan_id,
    );
    url_e.tag("bluesky");
    url_e.add_evidence(Evidence::new(
        SRC,
        format!("Bluesky profile URL for '{}'", profile.handle),
    ));
    result.push(url_e);

    // Real name → Person (≥2 whitespace-separated tokens, non-placeholder).
    if let Some(ref name) = profile.display_name
        && let Some(mut p) = profile_kit::person_from_name(name, confidence::MEDIUM_PLUS, scan_id)
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
            let mut e = Entity::new(EntityKind::Email, &email, confidence::HIGH_PLUS, scan_id);
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
            let mut url_e = Entity::new(EntityKind::Url, link, confidence::NOTABLE, scan_id);
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
                let mut d =
                    Entity::new(EntityKind::Domain, &host, confidence::MEDIUM_HIGH, scan_id);
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
        assert!(
            (u.expect("should succeed").confidence - confidence::HIGH_PLUSPLUS_PLUS).abs() < 0.01
        );
        assert!(u.expect("should succeed").has_tag("bluesky"));
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
        assert_eq!(person.expect("should succeed").value, "Alice Example");
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
    fn did_is_promoted_to_its_own_other_kind_entity() {
        let p = make_profile("alice.bsky.social", None, None);
        let ents = build_entities(p, "scan-bsky-010");
        let d = ents.iter().find(|e| {
            e.kind == EntityKind::Other("bluesky-did".into()) && e.value == "did:plc:abc123"
        });
        assert!(
            d.is_some(),
            "DID must be promoted to its own Other(\"bluesky-did\") entity, not just folded into evidence"
        );
        assert!(d.expect("should succeed").has_tag("bluesky"));
        assert!(d.expect("should succeed").has_tag("did"));
        // Must not be emitted as Username — a raw DID fed into username
        // enumeration modules would produce noisy, doomed lookups.
        assert!(
            !ents
                .iter()
                .any(|e| e.kind == EntityKind::Username && e.value == "did:plc:abc123"),
            "DID must never be emitted as a Username entity"
        );
    }

    #[test]
    fn no_did_entity_when_did_absent() {
        let mut p = make_profile("alice.bsky.social", None, None);
        p.did = None;
        let ents = build_entities(p, "scan-bsky-011");
        assert!(
            ents.iter()
                .all(|e| e.kind != EntityKind::Other("bluesky-did".into())),
            "no DID entity when did is absent from the profile"
        );
    }

    #[test]
    fn no_entities_beyond_username_and_profile_url_for_empty_profile() {
        let p = make_profile("quiet.bsky.social", None, None);
        let ents = build_entities(p, "scan-bsky-007");
        assert_eq!(
            ents.len(),
            3,
            "username + did + profile URL only when no optional fields"
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
    fn a_platform_handle_outside_bsky_social_still_collapses_to_the_bare_name() {
        // Staff (`.bsky.team`) and bridged (`.brid.gy`, `.translate.goog`)
        // accounts carry names the platform issued, exactly like `.bsky.social`.
        // While only `.bsky.social` was stripped here, `bnewbold.bsky.team` was
        // emitted whole and so could never meet the `bnewbold` that
        // `plc_directory` and the rest of the social band emit for the same
        // person. The shared namespace list is what closes that.
        for (handle, bare) in [
            ("bnewbold.bsky.team", "bnewbold"),
            ("someone.brid.gy", "someone"),
            ("retr0-id.translate.goog", "retr0-id"),
        ] {
            let ents = build_entities(make_profile(handle, None, None), "scan-bsky-012");
            assert!(
                ents.iter()
                    .any(|e| e.kind == EntityKind::Username && e.value == bare),
                "{handle} must collapse to the bare username {bare}"
            );
        }
    }

    #[test]
    fn a_platform_issued_handle_never_becomes_a_domain() {
        // Emitting one of these as the subject's Domain would attribute
        // Bluesky's, Bridgy's or Google's infrastructure to an individual — the
        // confident wrong finding the shared namespace list exists to prevent.
        for handle in [
            "alice.bsky.social",
            "bnewbold.bsky.team",
            "someone.brid.gy",
            "retr0-id.translate.goog",
        ] {
            let ents = build_entities(make_profile(handle, None, None), "scan-bsky-013");
            assert!(
                ents.iter().all(|e| e.kind != EntityKind::Domain),
                "{handle} is a platform-issued name and must not become a Domain"
            );
        }
    }

    #[test]
    fn a_domain_handle_carries_what_it_proves_and_what_it_does_not() {
        let ents = build_entities(make_profile("alice.dev", None, None), "scan-bsky-002");
        let d = ents
            .iter()
            .find(|e| e.kind == EntityKind::Domain && e.value == "alice.dev")
            .expect("a custom-domain handle must emit a Domain entity");
        assert!(d.has_tag("custom-handle"));
        // Graded by the shared function rather than by a literal, so this module
        // and `plc_directory` cannot hand noisy-OR two different grades for one
        // fact.
        assert!(
            (d.confidence - handle_domain_confidence(true, "alice.dev")).abs() < f64::EPSILON,
            "domain confidence must come from the shared grading, not a local constant"
        );
        let ev = d.evidence.first().expect("domain evidence");
        assert_eq!(
            ev.attributes.get("attribution").map(String::as_str),
            Some(DOMAIN_HANDLE_ATTRIBUTION),
            "the dossier must state what a domain handle demonstrates"
        );
        assert_eq!(
            ev.attributes.get("coverage").map(String::as_str),
            Some(DOMAIN_HANDLE_CAVEAT),
            "and what it does not — verified control is not registration ownership"
        );
    }

    #[test]
    fn a_handle_issued_out_of_someone_elses_domain_is_graded_below_an_apex_one() {
        // The platform list cannot enumerate every provider that hands out
        // subdomain handles, so label depth covers the tail: the domain is still
        // reported, and it does not arrive with an apex handle's authority.
        let ents = build_entities(
            make_profile("alice.pds.example.org", None, None),
            "scan-bsky-014",
        );
        let d = ents
            .iter()
            .find(|e| e.kind == EntityKind::Domain && e.value == "alice.pds.example.org")
            .expect("a non-platform handle is still infrastructure worth reporting");
        assert!(
            d.confidence < handle_domain_confidence(true, "alice.dev"),
            "a subdomain handle must not grade as a registrable domain the subject obtained"
        );
    }

    #[test]
    fn only_probes_that_can_succeed_are_issued() {
        // The gate in `process`, stated as the pairing it enforces. `alice` can
        // only ever be `alice.bsky.social`; `alice.dev` can only ever be itself;
        // and `_ryno_23` — the exact case from a live scan — is neither shape, so
        // no request is issued for it at all rather than two guaranteed 400s.
        assert!(is_dns_label("alice") && !is_handle("alice"));
        assert!(!is_dns_label("alice.dev") && is_handle("alice.dev"));
        assert!(!is_dns_label("_ryno_23") && !is_handle("_ryno_23"));
    }
}
