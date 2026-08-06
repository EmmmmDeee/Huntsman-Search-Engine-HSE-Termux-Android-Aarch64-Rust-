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

#[cfg(test)]
mod tests;

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
