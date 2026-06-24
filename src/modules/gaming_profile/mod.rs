//! Free gaming-platform profile lookups over each platform's own public,
//! keyless API — no SeekNow key, real first-party sources.
//!
//! This is the free, self-owned emulation of SeekNow's paid `gaming/roblox`
//! and `gaming/minecraft` endpoints. Where `see_know` pays see-know.eu for
//! those lookups, this module queries the platforms directly:
//!
//! * **Roblox** — `POST users.roblox.com/v1/usernames/users` (exact username →
//!   user id) then `GET users.roblox.com/v1/users/{id}` (full public profile:
//!   account creation date, description, display name, verified badge, ban
//!   status). Both are public and keyless.
//! * **Minecraft (Java)** — `GET api.mojang.com/users/profiles/minecraft/{name}`
//!   (exact username → account UUID). A Java account is paid, so a hit is a
//!   meaningful "this exact handle owns a real Minecraft account" signal.
//!
//! ## Why no candidate quarantine (unlike `comb_search`)
//!
//! Both endpoints resolve the username **exactly** — Roblox's batch resolver
//! and Mojang's profile lookup return only the account whose canonical handle
//! equals the query, never a substring co-hit. So a match is a precise platform
//! existence fact, emitted at platform-presence confidence without demotion,
//! mirroring [`crate::modules::github_user`]. (COMB, by contrast, matches
//! substrings, so its username path is candidate-quarantined.) Whether a
//! gaming account belongs to the same human as another platform's same-named
//! account stays the correlator's job. No mock, no simulation — the data is
//! fetched live from each platform's own API.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::{RequestBuilderExt, fetch_json, fetch_json_or_404, json_decode, urlencode};

const SRC: &str = "gaming_profile";

/// Confidence for a Roblox account that resolves EXACTLY from the target
/// handle. A unique-handle platform match with a live public profile — on par
/// with `github_user`'s profile confidence, a notch below it because gaming
/// handles collide across people more often than dev handles.
const ROBLOX_CONF: f64 = 0.90;

/// Confidence for a Minecraft (Java) account that resolves EXACTLY from the
/// target handle. Slightly below Roblox: Mojang confirms only existence + UUID,
/// not a rich profile, though a Java account being paid makes the hit solid.
const MINECRAFT_CONF: f64 = 0.85;

/// Max characters of a Roblox bio carried as evidence — bounds graph/log size
/// while preserving the lead.
const DESC_CAP: usize = 200;

pub struct GamingProfile;

#[derive(serde::Deserialize)]
struct RobloxUsernameResp {
    #[serde(default)]
    data: Vec<RobloxUserStub>,
}

#[derive(serde::Deserialize)]
struct RobloxUserStub {
    id: u64,
    #[serde(default)]
    name: String,
    #[serde(default, rename = "displayName")]
    display_name: String,
    #[serde(default, rename = "hasVerifiedBadge")]
    has_verified_badge: bool,
}

#[derive(serde::Deserialize)]
struct RobloxProfile {
    #[serde(default)]
    description: String,
    #[serde(default)]
    created: String,
    #[serde(default, rename = "isBanned")]
    is_banned: bool,
    #[serde(default, rename = "hasVerifiedBadge")]
    has_verified_badge: bool,
}

#[derive(serde::Deserialize)]
struct MojangProfile {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
}

#[async_trait]
impl Module for GamingProfile {
    fn name(&self) -> &'static str {
        "gaming_profile"
    }

    fn description(&self) -> &'static str {
        "Free gaming-platform profile lookup (Roblox, Minecraft) via each platform's public API"
    }

    fn priority(&self) -> u8 {
        // Free social tier, alongside hacker_news (106) / reddit_user (105).
        106
    }

    fn accepts(&self, t: &Target) -> bool {
        // Gaming handles are usernames; a name/email/domain is not a gaming
        // identity, and the engine already surfaces a person's discovered
        // usernames as their own typed targets for this module to consume.
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        // Gaming presence is social-media presence; the Social-category default
        // ATT&CK technique (Search Open Websites/Domains) is exactly right, so
        // `attack_techniques()` is intentionally left to derive from it.
        ModuleCategory::Social
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Username, EntityKind::Url];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Roblox is a two-stage round-trip (resolve then profile); the 3 s
        // default would clip the second hop on a slow mobile network.
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let v = target.value.trim();
        if !accepts_value(v) {
            return Ok(result);
        }

        // Two platforms queried concurrently; each is best-effort — a failure
        // or miss on one never sinks the other or the module.
        let (roblox, minecraft) = tokio::join!(roblox_lookup(ctx, v), minecraft_lookup(ctx, v));
        result.extend(roblox);
        result.extend(minecraft);

        Ok(result)
    }
}

/// Resolve a Roblox account for `username` and, on a hit, mint its profile
/// Username + profile-URL entities. Best-effort: any transport/parse failure
/// yields an empty batch rather than erroring the whole module.
async fn roblox_lookup(ctx: &ModuleContext, username: &str) -> Vec<Entity> {
    let mut out = Vec::new();

    // 1. Exact username → user id. This batch resolver returns `{"data":[]}`
    //    for a non-existent handle (never a 404), so a POST is unavoidable.
    let req = serde_json::json!({ "usernames": [username], "excludeBannedUsers": false });
    let resp = match ctx
        .http
        .post("https://users.roblox.com/v1/usernames/users")
        .json(&req)
        .send_tagged(SRC)
        .await
    {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::debug!(status = %r.status(), "roblox username resolve non-success");
            return out;
        }
        Err(e) => {
            tracing::debug!(error = %e, "roblox username resolve failed");
            return out;
        }
    };
    let batch: RobloxUsernameResp = match json_decode(SRC, resp).await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, "roblox username resolve decode failed");
            return out;
        }
    };
    let Some(stub) = pick_exact_roblox(&batch.data, username) else {
        return out; // no Roblox account owns this exact handle
    };
    let roblox_id = stub.id;
    let canonical = stub.name.clone();

    // 2. Full public profile. A real id is always 200, so `fetch_json` (which
    //    also carries the per-host circuit breaker); degrade to stub-only on
    //    any failure rather than dropping the confirmed account.
    let profile_url = format!("https://users.roblox.com/v1/users/{roblox_id}");
    let profile: Option<RobloxProfile> = fetch_json::<RobloxProfile>(&ctx.http, SRC, &profile_url)
        .await
        .ok();

    let human_url = format!("https://www.roblox.com/users/{roblox_id}/profile");
    let verified =
        stub.has_verified_badge || profile.as_ref().is_some_and(|p| p.has_verified_badge);
    let banned = profile.as_ref().is_some_and(|p| p.is_banned);

    let mut ev = Evidence::new(
        SRC,
        format!("Roblox account `{canonical}` (id {roblox_id})"),
    )
    .with_attr("roblox_id", roblox_id.to_string())
    .with_attr("profile_url", human_url.as_str())
    .with_attr("source", "roblox-api");
    if !stub.display_name.is_empty() && !stub.display_name.eq_ignore_ascii_case(&canonical) {
        ev = ev.with_attr("display_name", stub.display_name.as_str());
    }
    if let Some(p) = profile.as_ref() {
        if !p.created.is_empty() {
            ev = ev.with_attr("created", p.created.as_str());
        }
        let desc = p.description.trim();
        if !desc.is_empty() {
            let snippet: String = desc.chars().take(DESC_CAP).collect();
            ev = ev.with_attr("description", snippet);
        }
    }
    ev = ev.with_attr("verified_badge", verified.to_string());
    if banned {
        ev = ev.with_attr("banned", "true");
    }

    let mut u = Entity::new(
        EntityKind::Username,
        canonical.as_str(),
        ROBLOX_CONF,
        &ctx.scan_id,
    );
    u.tag("gaming");
    u.tag("roblox");
    u.tag(tags::SOCIAL_PROFILE);
    if verified {
        u.tag("verified");
    }
    if banned {
        u.tag("banned");
    }
    u.add_evidence(ev);
    out.push(u);

    let mut url_e = Entity::new(
        EntityKind::Url,
        human_url.as_str(),
        ROBLOX_CONF,
        &ctx.scan_id,
    );
    url_e.tag("gaming");
    url_e.tag("roblox");
    url_e.tag(tags::SOCIAL_PROFILE);
    url_e.add_evidence(
        Evidence::new(SRC, format!("Roblox profile page for `{canonical}`"))
            .with_attr("roblox_id", roblox_id.to_string()),
    );
    out.push(url_e);

    out
}

/// Resolve a Minecraft (Java) account for `username`. Mojang returns 404 for a
/// non-existent handle (mapped to `None`); a hit yields the account UUID.
async fn minecraft_lookup(ctx: &ModuleContext, username: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let url = format!(
        "https://api.mojang.com/users/profiles/minecraft/{}",
        urlencode(username)
    );
    let profile = match fetch_json_or_404::<MojangProfile>(&ctx.http, SRC, &url).await {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(error = %e, "mojang lookup failed");
            return out;
        }
    };
    let Some(profile) = profile else {
        return out; // no such Java account
    };
    // Mojang returns only the EXACT player and a 32-hex UUID; reject anything
    // that doesn't satisfy both (defends against an unexpected upstream shape).
    if !profile.name.eq_ignore_ascii_case(username) || profile.id.len() != 32 {
        return out;
    }
    let uuid = dash_uuid(&profile.id).unwrap_or_else(|| profile.id.clone());

    let mut u = Entity::new(
        EntityKind::Username,
        profile.name.as_str(),
        MINECRAFT_CONF,
        &ctx.scan_id,
    );
    u.tag("gaming");
    u.tag("minecraft");
    u.tag(tags::SOCIAL_PROFILE);
    u.add_evidence(
        Evidence::new(
            SRC,
            format!("Minecraft (Java) account `{}` exists", profile.name),
        )
        .with_attr("minecraft_uuid", uuid.as_str())
        .with_attr("source", "mojang-api"),
    );
    out.push(u);
    out
}

/// Value-level admission: a gaming handle is 3–20 chars, ASCII alphanumeric or
/// underscore, with at least one letter. Rejecting all-digit / all-underscore
/// seeds keeps a numeric breach id or shapeless token from hammering the APIs.
fn accepts_value(v: &str) -> bool {
    let len = v.chars().count();
    (3..=20).contains(&len)
        && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && v.chars().any(|c| c.is_ascii_alphabetic())
}

/// The stub whose canonical handle equals `target` (case-insensitive). Roblox's
/// batch resolver only ever returns exact matches, but this pins that contract.
fn pick_exact_roblox<'a>(data: &'a [RobloxUserStub], target: &str) -> Option<&'a RobloxUserStub> {
    data.iter().find(|s| s.name.eq_ignore_ascii_case(target))
}

/// Format Mojang's undashed 32-hex UUID as a canonical 8-4-4-4-12 UUID. Returns
/// `None` for any input that isn't exactly 32 hex digits.
fn dash_uuid(s: &str) -> Option<String> {
    if s.len() != 32 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!(
        "{}-{}-{}-{}-{}",
        &s[0..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..32]
    ))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
