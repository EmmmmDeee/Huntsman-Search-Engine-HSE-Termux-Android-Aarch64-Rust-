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
    twitter_username: Option<String>,
    public_repos: Option<u64>,
    public_gists: Option<u64>,
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

    fn description(&self) -> &'static str {
        "GitHub profile, repos, and social metadata lookup"
    }

    fn priority(&self) -> u8 {
        108
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let login = target.value.trim();
        // Reject non-conforming logins to avoid a wasted HTTP round-trip.
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

        let mut u_entity = Entity::new(EntityKind::Username, &user.login, 0.95, &ctx.scan_id);
        u_entity.tag("github");
        if let Some(l) = user.location.as_deref() {
            u_entity.tag_if(!l.trim().is_empty(), "has-location");
        }
        if let Some(ref tw) = user.twitter_username {
            if !tw.is_empty() {
                u_entity.tag(format!("twitter:{tw}"));
            }
        }
        let ev = Evidence::new("github_user", format!("GitHub profile @{}", user.login))
            .with_attr("github_id", user.id.to_string())
            .with_attr(
                "profile_url",
                user.html_url.as_deref().map_or_else(
                    || format!("https://github.com/{}", user.login),
                    String::from,
                ),
            )
            .with_opt_attr("name", user.name.as_deref())
            .with_opt_attr("company", user.company.as_deref())
            .with_opt_attr("location", user.location.as_deref())
            .with_opt_attr("blog", user.blog.as_deref().filter(|b| !b.is_empty()))
            .with_opt_attr("bio", user.bio.as_deref().filter(|b| !b.is_empty()))
            .with_opt_attr("created_at", user.created_at.as_deref())
            .with_opt_attr("public_repos", user.public_repos.map(|n| n.to_string()))
            .with_opt_attr("public_gists", user.public_gists.map(|n| n.to_string()))
            .with_opt_attr("followers", user.followers.map(|n| n.to_string()))
            .with_opt_attr("following", user.following.map(|n| n.to_string()))
            .with_opt_attr(
                "twitter",
                user.twitter_username
                    .as_deref()
                    .filter(|tw| !tw.is_empty()),
            );
        u_entity.add_evidence(ev);
        result.push(u_entity);

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

        if let Some(email) = user.email.as_deref()
            && email.contains('@')
            && email.split('@').nth(1).map_or(false, |h| h.contains('.') && !h.starts_with('.') && !h.ends_with('.'))
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
                            Evidence::new(
                                "github_user",
                                format!("Blog domain from @{}", user.login),
                            )
                            .with_attr("blog_url", blog)
                            .with_attr("github_login", &user.login),
                        );
                        result.push(d);
                    }
                }
            }
        }

        // OathNet GHunt enrichment for Gmail addresses found on GitHub
        let oathnet_key =
            crate::util::oathnet::resolve_key(ctx.key_opt(crate::util::oathnet::KEY_ENV));
        if let Some(email) = user.email.as_deref()
            && !ctx.cancel.is_cancelled()
        {
            let is_google = email.ends_with("@gmail.com")
                || email.ends_with("@googlemail.com")
                || email.ends_with("@google.com");
            if is_google {
                if let Ok(Some(ghunt)) = crate::util::oathnet::osint_opt(
                    oathnet_key,
                    crate::util::oathnet::paths::GHUNT,
                    "email",
                    email,
                )
                .await
                {
                    let gname = crate::util::oathnet::val_str_or(
                        &ghunt,
                        &["name", "display_name", "fullName"],
                    );
                    let gaia_id = crate::util::oathnet::val_str_or(
                        &ghunt,
                        &["gaia_id", "gaiaId", "id"],
                    );
                    let last_edit = crate::util::oathnet::val_str_or(
                        &ghunt,
                        &["last_edit", "lastUpdated"],
                    );
                    let yt = crate::util::oathnet::val_str_or(
                        &ghunt,
                        &["youtube_channel", "youtube"],
                    );

                    let ghunt_ev = Evidence::new(
                        "github_user:ghunt",
                        format!("GHunt Google account recon for {email}"),
                    )
                    .with_attr("source", "ghunt")
                    .with_opt_attr("google_name", gname.clone())
                    .with_opt_attr("gaia_id", gaia_id)
                    .with_opt_attr("last_edit", last_edit)
                    .with_opt_attr("youtube", yt.clone());

                    for e in &mut result.entities {
                        if e.kind == EntityKind::Email && e.value == email {
                            e.tag("ghunt");
                            e.add_evidence(ghunt_ev.clone());
                            break;
                        }
                    }

                    if let Some(ref yt_url) = yt {
                        if yt_url.starts_with("http") {
                            let mut ye =
                                Entity::new(EntityKind::Url, yt_url, 0.70, &ctx.scan_id);
                            ye.tag("ghunt");
                            ye.tag("youtube");
                            ye.tag("personal-site");
                            ye.add_evidence(Evidence::new(
                                "github_user:ghunt",
                                "YouTube channel from GHunt via GitHub email",
                            ));
                            result.push(ye);
                        }
                    }

                    if let Some(ref n) = gname {
                        let t = n.trim();
                        if t.len() >= 3 && t.contains(' ') {
                            let mut pe =
                                Entity::new(EntityKind::Person, t, 0.75, &ctx.scan_id);
                            pe.tag("ghunt");
                            pe.add_evidence(ghunt_ev);
                            result.push(pe);
                        }
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
