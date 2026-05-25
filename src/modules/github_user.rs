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

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

pub struct GithubUser;

#[derive(Deserialize)]
struct GhUser {
    login: String,
    id: u64,
    name: Option<String>,
    email: Option<String>,
    blog: Option<String>,
    company: Option<String>,
    location: Option<String>,
    bio: Option<String>,
    public_repos: Option<u64>,
    followers: Option<u64>,
    following: Option<u64>,
    created_at: Option<String>,
    html_url: Option<String>,
}

#[async_trait]
impl Module for GithubUser {
    fn name(&self) -> &'static str {
        "github_user"
    }

    fn priority(&self) -> u8 {
        108
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(login) = target.trimmed() else {
            return Ok(ModuleResult::new());
        };
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
            .send()
            .await
            .map_err(|e| Error::module("github_user", e.to_string()))?;

        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            return Err(Error::module(
                "github_user",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let user: GhUser = resp
            .json()
            .await
            .map_err(|e| Error::module("github_user", e.to_string()))?;

        let mut result = ModuleResult::new();

        // Username entity with GitHub profile metadata.
        let mut u_entity = Entity::new(EntityKind::Username, &user.login, 0.95, &ctx.scan_id);
        u_entity.tag("github");
        let mut ev = Evidence::new("github_user", format!("GitHub profile @{}", user.login))
            .with_attr("github_id", user.id.to_string())
            .with_attr(
                "profile_url",
                user.html_url
                    .clone()
                    .unwrap_or_else(|| format!("https://github.com/{}", user.login)),
            );
        if let Some(n) = user.name.as_deref() {
            ev = ev.with_attr("name", n);
        }
        if let Some(c) = user.company.as_deref() {
            ev = ev.with_attr("company", c);
        }
        if let Some(l) = user.location.as_deref() {
            ev = ev.with_attr("location", l);
        }
        if let Some(b) = user.blog.as_deref()
            && !b.is_empty()
        {
            ev = ev.with_attr("blog", b);
        }
        if let Some(b) = user.bio.as_deref()
            && !b.is_empty()
        {
            ev = ev.with_attr("bio", b);
        }
        if let Some(c) = user.created_at.as_deref() {
            ev = ev.with_attr("created_at", c);
        }
        if let Some(n) = user.public_repos {
            ev = ev.with_attr("public_repos", n.to_string());
        }
        if let Some(n) = user.followers {
            ev = ev.with_attr("followers", n.to_string());
        }
        if let Some(n) = user.following {
            ev = ev.with_attr("following", n.to_string());
        }
        u_entity.add_evidence(ev);
        result.push(u_entity);

        // Location → Address entity for the people→geo recursion chain:
        //   Username → github_user → Address → nominatim → Coordinates → wigle
        if let Some(loc) = user.location.as_deref()
            && !loc.trim().is_empty()
            && loc.trim().len() >= 3
        {
            let mut addr = Entity::new(EntityKind::Address, loc.trim(), 0.76, &ctx.scan_id);
            addr.tag("profile-location");
            addr.tag("github");
            addr.add_evidence(
                Evidence::new(
                    "github_user",
                    format!(
                        "Location from GitHub profile @{}: {}",
                        user.login,
                        loc.trim()
                    ),
                )
                .with_attr("github_login", &user.login),
            );
            result.push(addr);
        }

        // Real name → Person entity, when present.
        if let Some(name) = user.name.as_deref()
            && !name.trim().is_empty()
        {
            let mut p = Entity::new(EntityKind::Person, name.trim(), 0.75, &ctx.scan_id);
            p.tag("derived");
            p.add_evidence(
                Evidence::new(
                    "github_user",
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
                    "github_user",
                    format!("Email published on GitHub profile @{}", user.login),
                )
                .with_attr("github_login", &user.login)
                .with_attr("profile_url", format!("https://github.com/{}", user.login)),
            );
            result.push(e);
        }

        // Blog URL → Url entity, when present.
        if let Some(blog) = user.blog.as_deref()
            && !blog.trim().is_empty()
        {
            // GitHub stores the blog as a free-form string; only emit if
            // it looks like a URL (must start with a scheme to count).
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
                // Extract the hostname as a Domain entity so the expansion
                // engine can chain dns_resolver/crtsh/whois/rdap on it.
                // Without this, the Url entity is an expansion dead-end
                // (EntityKind::Url → TargetKind = None).
                if let Some(host) = blog
                    .strip_prefix("https://")
                    .or_else(|| blog.strip_prefix("http://"))
                {
                    let host = host.split('/').next().unwrap_or("");
                    if host.contains('.') && !host.is_empty() {
                        let mut d = Entity::new(EntityKind::Domain, host, 0.75, &ctx.scan_id);
                        d.tag("personal-site");
                        d.tag("blog-domain");
                        d.add_evidence(
                            Evidence::new(
                                "github_user",
                                format!("Blog domain from GitHub profile @{}", user.login),
                            )
                            .with_attr("github_login", &user.login)
                            .with_attr("source_url", blog),
                        );
                        result.push(d);
                    }
                }
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_username() {
        let m = GithubUser;
        assert!(m.accepts(&Target::new(TargetKind::Username, "octocat")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }
}
