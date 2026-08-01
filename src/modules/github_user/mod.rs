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
            return Err(crate::util::http::http_status_error("github_user", resp).await);
        }

        // json_scanned: GitHub user profiles include bio and blog fields —
        // free-form user text that may contain embedded API keys.
        let user: GhUser = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| crate::core::error::Error::module(SRC, e))?;

        let mut result = ModuleResult::new();

        // Username entity with GitHub profile metadata.
        let mut u_entity = Entity::new(
            EntityKind::Username,
            &user.login,
            confidence::VERY_HIGH_PLUSPLUS,
            &ctx.scan_id,
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
            let mut tw_entity = Entity::new(
                EntityKind::Username,
                tw,
                confidence::HIGH_PLUS,
                &ctx.scan_id,
            );
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
            result.push(tw_entity);
        }
        u_entity.add_evidence(ev);
        result.push(u_entity);

        // Twitter username → separate Username entity for cross-platform correlation.
        if let Some(tw) = user
            .twitter_username
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
        {
            let handle = tw.trim_start_matches('@');
            if !handle.is_empty() {
                let mut tw_e = Entity::new(
                    EntityKind::Username,
                    handle,
                    confidence::HIGH_PLUS,
                    &ctx.scan_id,
                );
                tw_e.tag("twitter");
                tw_e.tag("derived");
                tw_e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Twitter handle from GitHub profile @{}", user.login),
                    )
                    .with_attr("github_login", &user.login),
                );
                result.push(tw_e);
            }
        }

        // Real name → Person entity, when present.
        if let Some(name) = user.name.as_deref()
            && !name.trim().is_empty()
        {
            let mut p = Entity::new(
                EntityKind::Person,
                name.trim(),
                confidence::VERY_HIGH,
                &ctx.scan_id,
            );
            p.tag("derived");
            p.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Real name from GitHub profile @{}", user.login),
                )
                .with_attr("source", "github_profile")
                .with_attr("github_login", &user.login),
            );
            result.push(p);
        }

        // Public email → Email entity, when explicitly published.
        if let Some(email) = user.email.as_deref()
            && crate::util::extract::looks_like_email(email)
        {
            let mut e = Entity::new(
                EntityKind::Email,
                email,
                confidence::VERY_HIGH_PLUS,
                &ctx.scan_id,
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
            result.push(e);
        }

        // Company → Organisation entity, when present.
        if let Some(company) = user.company.as_deref() {
            let company = company.trim().trim_start_matches('@');
            if company.len() >= 2 {
                let mut o = Entity::new(
                    EntityKind::Organisation,
                    company,
                    confidence::HIGH,
                    &ctx.scan_id,
                );
                o.tag("github");
                o.tag("derived");
                o.add_evidence(
                    Evidence::new(SRC, format!("Company from GitHub profile @{}", user.login))
                        .with_attr("github_login", &user.login),
                );
                result.push(o);
            }
        }

        // Location → Address + optional inline Coordinates.
        if let Some(location) = user.location.as_deref() {
            let location = location.trim();
            if location.len() >= 3 {
                let mut a = Entity::new(
                    EntityKind::Address,
                    location,
                    confidence::MEDIUM_HIGH,
                    &ctx.scan_id,
                );
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
                result.push(a);

                if let Some((lat, lon)) = crate::util::city_coords::city_coords(location) {
                    let coord_val = format!("{lat:.4},{lon:.4}");
                    let mut c = Entity::new(
                        EntityKind::Coordinates,
                        &coord_val,
                        confidence::MEDIUM_LIGHT,
                        &ctx.scan_id,
                    );
                    c.tag("addr-derived");
                    c.tag("geoint");
                    c.tag("github");
                    if let Some(sc) = crate::util::address_au::single_state_code(location) {
                        c.tag(format!("au-state:{sc}"));
                        c.tag("country:AU");
                    }
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
                    result.push(c);
                }
            }
        }

        // Blog URL → Url entity, when present.
        if let Some(blog) = user.blog.as_deref()
            && !blog.trim().is_empty()
        {
            let blog = blog.trim();
            if blog.starts_with("http://") || blog.starts_with("https://") {
                let mut u = Entity::new(
                    EntityKind::Url,
                    blog,
                    confidence::HIGH_PLUSPLUS,
                    &ctx.scan_id,
                );
                u.tag("personal-site");
                u.add_evidence(
                    Evidence::new(
                        "github_user",
                        format!("Personal site linked from GitHub profile @{}", user.login),
                    )
                    .with_attr("github_login", &user.login),
                );
                result.push(u);

                if let Ok(parsed) = url::Url::parse(blog)
                    && let Some(host) = parsed.host_str()
                {
                    let domain = host.to_lowercase();
                    if domain.contains('.') && domain != "github.com" && domain != "github.io" {
                        let mut d = Entity::new(
                            EntityKind::Domain,
                            &domain,
                            confidence::ATTRIBUTED,
                            &ctx.scan_id,
                        );
                        d.tag("derived");
                        d.tag("personal-site");
                        d.add_evidence(
                            Evidence::new(SRC, format!("Blog domain from @{}", user.login))
                                .with_attr("blog_url", blog)
                                .with_attr("github_login", &user.login),
                        );
                        result.push(d);
                    }
                }
            }
        }

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
