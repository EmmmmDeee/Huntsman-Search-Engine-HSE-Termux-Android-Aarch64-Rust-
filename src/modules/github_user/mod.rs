//! GitHub user profile lookup. Free, no key (uses the public REST API).
//!
//! Endpoint: `GET https://api.github.com/users/{login}`.
//!
//! Public profile data: real name (if exposed), public email (if
//! exposed and explicitly published), company, location, blog, bio,
//! public-repo / follower / following counts, account creation date.
//!
//! Emits one Email entity *only when* the user has explicitly published
//! one on their profile (GitHub's privacy default is to hide it). When
//! present, that link is high-value — it confirms an
//! account-to-real-email mapping.
//!
//! Rate-limited at 60 req/hour for unauthenticated use; on 403/429 we
//! surface a module_error so the user sees the cap was hit.

mod fetch;
mod helpers;
mod types;

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use super::profile_kit;
use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use types::GhUser;

const SRC: &str = "github_user";

pub struct GithubUser;

#[async_trait]
impl Module for GithubUser {
    fn name(&self) -> &'static str {
        "github_user"
    }

    fn description(&self) -> &'static str {
        "GitHub profile recon — harvests repos, bio, and social metadata to pivot a username outward"
    }

    fn priority(&self) -> u8 {
        107
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A code-hosting profile — ATT&CK Code Repositories (T1593.003), not
        // the Social-Media default (T1593.001) its category implies — but
        // this REPLACED the whole default array instead of substituting just
        // that one technique, silently dropping T1589.003 (Employee Names)
        // even though a real name → Person is emitted below, and omitting
        // techniques for the Email/Organisation/Address/Coordinates/
        // Credential entities this module also produces (`produces()` lists
        // all of them). The `attack:<ID>` tag every admitted entity carries
        // is sourced directly from this list (core::engine::dispatch), so
        // the gap wasn't cosmetic — every Person/Email/Organisation/Address/
        // Coordinates/Credential this module emits carried NO matching
        // provenance tag. Declare the precise set instead.
        &[
            "T1589.001", // Credentials — published SSH public keys
            "T1589.002", // Email Addresses — published profile/gist/commit emails
            "T1589.003", // Employee Names — Person from the profile's real name
            "T1591.001", // Determine Physical Locations — Address/Coordinates from location
            "T1591.002", // Business Relationships — Organisation from company/orgs
            "T1593.003", // Code Repositories — Username via the GitHub profile itself
        ]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Username,
            EntityKind::Domain,
            EntityKind::Url,
            EntityKind::Organisation,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Credential,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let login = target.value.trim();
        // GitHub login rules: alphanumeric and hyphens, max 39 chars,
        // not starting/ending with a hyphen. Saves a wasted HTTP round-
        // trip for non-conforming inputs.
        if login.is_empty()
            || login.len() > 39
            || !login.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            || login.starts_with('-')
            || login.ends_with('-')
        {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://api.github.com/users/{login}");
        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header(
                "X-GitHub-Api-Version",
                crate::modules::github_api::API_VERSION,
            )
            .send_tagged(SRC)
            .await?;

        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            return Err(crate::util::http::http_status_error(SRC, resp).await);
        }

        // json_scanned: GitHub user profiles include bio and blog fields —
        // free-form user text that may contain embedded API keys.
        let user: GhUser = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| crate::core::error::Error::module(SRC, e))?;

        let mut result = ModuleResult::new();
        result.entities = build_entities(&user, &ctx.scan_id);

        // SSH public keys → evidence on the username entity.
        fetch::fetch_ssh_keys(login, ctx, &mut result).await;

        // Public events → extract active working hours.
        fetch::fetch_events(login, ctx, &mut result).await;

        // GitHub organisations this user belongs to → Organisation entities.
        let token = ctx.key_opt("HUNTSMAN_GITHUB_TOKEN");
        let org_logins = fetch::fetch_orgs(ctx, login, token).await;
        for org_login in org_logins {
            let mut org = Entity::new(
                EntityKind::Organisation,
                &org_login,
                confidence::HIGH_PLUS,
                &ctx.scan_id,
            );
            org.tag("github-org");
            org.add_evidence(
                Evidence::new(
                    SRC,
                    format!("@{login} is a member of GitHub org {org_login}"),
                )
                .with_attr("github_login", login)
                .with_attr("org_login", &org_login),
            );
            result.push(org);
        }

        // Public gists → tag profile entity, then scan content for emails and
        // leaked API keys (send_tagged inside fetch_gist_content routes every
        // response body through the found_keys scanner automatically).
        let gist_ids = fetch::fetch_gists(ctx, login, token).await;
        if !gist_ids.is_empty()
            && let Some(first) = result.entities.first_mut()
        {
            first.tag("has-gists");
        }
        fetch::fetch_gist_content(&gist_ids, login, ctx, &mut result).await;

        Ok(result)
    }

    fn max_timeout_ms(&self) -> u64 {
        5_000
    }
}

/// Pure account→entity mapping, mirroring `gitlab_user`/`gitea_user`'s own
/// `build_entities`. Separated from `process()` so every branch is
/// unit-testable without I/O; the profile fetch and the later
/// SSH-keys/events/orgs/gists passes (which need live HTTP) stay in `process`.
fn build_entities(user: &GhUser, scan_id: &str) -> Vec<Entity> {
    let mut result = Vec::new();
    result.extend(username_and_bio_twitter_entities(user, scan_id));
    result.extend(separate_twitter_handle_entity(user, scan_id));
    result.extend(person_entity(user, scan_id));
    result.extend(email_entity(user, scan_id));
    result.extend(company_entity(user, scan_id));
    result.extend(location_entities(user, scan_id));
    result.extend(blog_entities(user, scan_id));
    result
}

/// The confirmed-on-GitHub Username entity carrying the profile metadata
/// (name/company/blog/bio/counts) as evidence, plus — when the profile links
/// a Twitter/X handle — a first-class Username pivot for it. Twitter emission
/// is entangled with the profile evidence here (it also sets a tag +
/// attribute on the username entity itself), which is why it isn't its own
/// helper alongside `separate_twitter_handle_entity` below.
fn username_and_bio_twitter_entities(user: &GhUser, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let mut u_entity = Entity::new(
        EntityKind::Username,
        &user.login,
        confidence::VERY_HIGH_PLUSPLUS,
        scan_id,
    );
    u_entity.tag("github");
    let profile_url = user.html_url.as_deref().map_or_else(
        || format!("https://github.com/{}", user.login),
        String::from,
    );
    let mut ev = [
        ("name", user.name.as_deref().map(String::from)),
        ("company", user.company.as_deref().map(String::from)),
        (
            "blog",
            user.blog
                .as_deref()
                .filter(|b| !b.is_empty())
                .map(String::from),
        ),
        (
            "bio",
            user.bio
                .as_deref()
                .filter(|b| !b.is_empty())
                .map(String::from),
        ),
        ("created_at", user.created_at.as_deref().map(String::from)),
        ("public_repos", user.public_repos.map(|n| n.to_string())),
        ("public_gists", user.public_gists.map(|n| n.to_string())),
        ("followers", user.followers.map(|n| n.to_string())),
        ("following", user.following.map(|n| n.to_string())),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.map(|v| (key, v)))
    .fold(
        Evidence::new(SRC, format!("GitHub profile @{}", user.login))
            .with_attr("github_id", user.id.to_string())
            .with_attr("profile_url", profile_url),
        |ev, (key, v)| ev.with_attr(key, v),
    );
    // Location and Twitter also drive entity tags, so they stay explicit.
    if let Some(l) = user.location.as_deref() {
        ev = ev.with_attr("location", l);
        if !l.trim().is_empty() {
            u_entity.tag("has-location");
        }
    }
    if let Some(tw) = user.twitter_username.as_deref()
        && !tw.is_empty()
    {
        ev = ev.with_attr("twitter", tw);
        u_entity.tag("twitter-linked");
        // Emit the Twitter handle as a first-class Username so it becomes a
        // pivot target for username_search / social_probe in the next round.
        // Confidence confidence::HIGH_PLUS: self-asserted on a confirmed GitHub profile.
        let mut tw_entity = Entity::new(EntityKind::Username, tw, confidence::HIGH_PLUS, scan_id);
        tw_entity.tag("twitter");
        tw_entity.tag("social-profile");
        tw_entity.add_evidence(
            Evidence::new(
                SRC,
                format!("Twitter handle from GitHub profile @{}", user.login),
            )
            .with_attr("twitter", tw)
            .with_attr("github_login", &user.login)
            .with_attr("source", "github_profile"),
        );
        out.push(tw_entity);
    }
    u_entity.add_evidence(ev);
    out.push(u_entity);
    out
}

/// Twitter username → separate Username entity for cross-platform correlation.
fn separate_twitter_handle_entity(user: &GhUser, scan_id: &str) -> Option<Entity> {
    let tw = user
        .twitter_username
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())?;
    let handle = tw.trim_start_matches('@');
    if handle.is_empty() {
        return None;
    }
    let mut tw_e = Entity::new(EntityKind::Username, handle, confidence::HIGH_PLUS, scan_id);
    tw_e.tag("twitter");
    tw_e.tag("derived");
    tw_e.add_evidence(
        Evidence::new(
            SRC,
            format!("Twitter handle from GitHub profile @{}", user.login),
        )
        .with_attr("github_login", &user.login),
    );
    Some(tw_e)
}

/// Real name → Person entity, when present. Delegates the multi-word-name
/// gate and placeholder check to [`profile_kit::person_from_name`] (a
/// single-token "name" like a handle, or a placeholder like `"N/A"`, is
/// never emitted as a Person — the shared toolkit's rationale applies here
/// exactly as it does to the other profile modules that already use it).
fn person_entity(user: &GhUser, scan_id: &str) -> Option<Entity> {
    let name = user.name.as_deref()?;
    let mut p = profile_kit::person_from_name(name, confidence::VERY_HIGH, scan_id)?;
    p.tag("derived");
    p.add_evidence(
        Evidence::new(
            SRC,
            format!("Real name from GitHub profile @{}", user.login),
        )
        .with_attr("source", "github_profile")
        .with_attr("github_login", &user.login),
    );
    Some(p)
}

/// Public email → Email entity, when explicitly published.
fn email_entity(user: &GhUser, scan_id: &str) -> Option<Entity> {
    let email = user.email.as_deref()?;
    if !crate::util::extract::looks_like_email(email) {
        return None;
    }
    let mut e = Entity::new(
        EntityKind::Email,
        email,
        confidence::VERY_HIGH_PLUS,
        scan_id,
    );
    e.tag("public-profile");
    e.add_evidence(
        Evidence::new(
            SRC,
            format!("Email published on GitHub profile @{}", user.login),
        )
        .with_attr("github_login", &user.login)
        .with_attr("profile_url", format!("https://github.com/{}", user.login)),
    );
    Some(e)
}

/// Company → Organisation entity, when present.
fn company_entity(user: &GhUser, scan_id: &str) -> Option<Entity> {
    let company = user.company.as_deref()?;
    let company = company.trim().trim_start_matches('@');
    if company.len() < 2 {
        return None;
    }
    let mut o = Entity::new(EntityKind::Organisation, company, confidence::HIGH, scan_id);
    o.tag("github");
    o.tag("derived");
    o.add_evidence(
        Evidence::new(SRC, format!("Company from GitHub profile @{}", user.login))
            .with_attr("github_login", &user.login),
    );
    Some(o)
}

/// Location → Address + optional inline Coordinates. Delegates the entity
/// construction to [`profile_kit::location_address`] /
/// [`profile_kit::location_coordinates`] (which additionally reject a >100
/// char value as a bio mis-mapped to the location field — a gap this module
/// didn't previously guard against); the GitHub-specific AU-state tagging
/// stays layered on top.
fn location_entities(user: &GhUser, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let Some(location) = user.location.as_deref() else {
        return out;
    };
    let location = location.trim();
    let Some(mut a) = profile_kit::location_address(location, confidence::MEDIUM_HIGH, scan_id)
    else {
        return out;
    };
    a.tag("github");
    a.tag("geoint");
    a.tag("self-reported");
    if let Some(sc) = crate::util::address_au::single_state_code(location) {
        a.tag(format!("au-state:{sc}"));
        a.tag("country:AU");
    }
    a.add_evidence(
        Evidence::new(SRC, format!("Location from GitHub profile @{}", user.login))
            .with_attr("github_login", &user.login),
    );
    out.push(a);

    if let Some(mut c) =
        profile_kit::location_coordinates(location, confidence::MEDIUM_LIGHT, scan_id)
    {
        c.tag("github");
        if let Some(sc) = crate::util::address_au::single_state_code(location) {
            c.tag(format!("au-state:{sc}"));
            c.tag("country:AU");
        }
        let coord_val = c.value.clone();
        c.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "Inline geocode of GitHub location '{}' → {coord_val}",
                    user.login
                ),
            )
            .with_attr("github_login", &user.login),
        );
        out.push(c);
    }
    out
}

/// Blog URL → Url entity, plus a derived Domain entity when the host isn't a
/// known platform host. Delegates to
/// [`profile_kit::website_url_and_domain`], whose [`profile_kit::PLATFORM_HOSTS`]
/// exclusion list is the shared, complete set every profile module now
/// checks — wider than this module's own previous `github.com`/`github.io`
/// pair (which in practice rarely matched anyway: a real GitHub Pages blog
/// carries a username subdomain like `alice.github.io`, not the bare host).
fn blog_entities(user: &GhUser, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let Some(blog) = user.blog.as_deref().filter(|b| !b.trim().is_empty()) else {
        return out;
    };
    let blog = blog.trim();
    for mut e in profile_kit::website_url_and_domain(
        blog,
        confidence::HIGH_PLUSPLUS,
        confidence::ATTRIBUTED,
        scan_id,
    ) {
        match e.kind {
            EntityKind::Domain => {
                e.tag("derived");
                e.tag("personal-site");
                e.add_evidence(
                    Evidence::new(SRC, format!("Blog domain from @{}", user.login))
                        .with_attr("blog_url", blog)
                        .with_attr("github_login", &user.login),
                );
            }
            _ => {
                e.tag("personal-site");
                e.add_evidence(
                    Evidence::new(
                        "github_user",
                        format!("Personal site linked from GitHub profile @{}", user.login),
                    )
                    .with_attr("github_login", &user.login),
                );
            }
        }
        out.push(e);
    }
    out
}
