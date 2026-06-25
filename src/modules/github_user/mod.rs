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
        "GitHub profile, repos, and social metadata lookup"
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
        // A code-hosting profile — ATT&CK Code Repositories (T1593.003), not the Social-Media default its category implies.
        &["T1593.003"]
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
            .header("X-GitHub-Api-Version", "2022-11-28")
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
        let mut u_entity = Entity::new(EntityKind::Username, &user.login, 0.95, &ctx.scan_id);
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
            u_entity.tag(format!("twitter:{tw}"));
        }
        u_entity.add_evidence(ev);
        result.push(u_entity);

        // Real name → Person entity, when present.
        if let Some(name) = user.name.as_deref()
            && !name.trim().is_empty()
        {
            let mut p = Entity::new(EntityKind::Person, name.trim(), 0.75, &ctx.scan_id);
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
            && email.contains('@')
        {
            let mut e = Entity::new(EntityKind::Email, email, 0.90, &ctx.scan_id);
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
                let mut o = Entity::new(EntityKind::Organisation, company, 0.65, &ctx.scan_id);
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
                let mut a = Entity::new(EntityKind::Address, location, 0.55, &ctx.scan_id);
                a.tag("github");
                a.tag("geoint");
                a.tag("self-reported");
                if let Some(sc) = crate::util::address_au::state_code(location) {
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
                    let mut c =
                        Entity::new(EntityKind::Coordinates, &coord_val, 0.52, &ctx.scan_id);
                    c.tag("addr-derived");
                    c.tag("geoint");
                    c.tag("github");
                    if let Some(sc) = crate::util::address_au::state_code(location) {
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
                let mut u = Entity::new(EntityKind::Url, blog, 0.80, &ctx.scan_id);
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
                        let mut d = Entity::new(EntityKind::Domain, &domain, 0.72, &ctx.scan_id);
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
        let org_logins = fetch::fetch_orgs(&ctx.http, login, token).await;
        for org_login in org_logins {
            let mut org = Entity::new(EntityKind::Organisation, &org_login, 0.70, &ctx.scan_id);
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

        // Public gists → tag profile entity with "has-gists" if any found.
        let gist_ids = fetch::fetch_gists(&ctx.http, login, token).await;
        if !gist_ids.is_empty()
            && let Some(first) = result.entities.first_mut()
        {
            first.tag("has-gists");
        }

        Ok(result)
    }

    fn max_timeout_ms(&self) -> u64 {
        5_000
    }
}
