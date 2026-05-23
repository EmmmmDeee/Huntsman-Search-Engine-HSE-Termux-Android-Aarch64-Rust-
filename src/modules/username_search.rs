//! Sherlock / Maigret-style username search.
//!
//! Fans out parallel HTTP probes against ~25 popular sites to discover
//! which ones host a profile for the given username. Each site has a
//! known existence-detection rule (status code + optional body marker)
//! borrowed from the public sherlock-project sites database.
//!
//! For every site where the username exists, emits one `Url` entity
//! tagged `social-profile` with the platform name in evidence. Also
//! emits one `Username` entity (re-affirming the seed) tagged with the
//! count of platforms found so downstream correlators / the SPA can
//! highlight cross-platform identities.
//!
//! No API keys. Probes time out fast (per-site timeout from the engine
//! ceiling); offline / WAF-blocked sites just don't contribute.

use async_trait::async_trait;
use futures::future::join_all;
use std::time::Duration;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

pub struct UsernameSearch;

/// One site to probe. Kept inline (rather than loaded from a JSON file)
/// so the binary stays self-contained and the list is reviewable in PR.
struct Site {
    /// Display name.
    name: &'static str,
    /// `{}` is replaced with the urlencoded username.
    url: &'static str,
    /// HTTP request method. Most sites accept GET; some return cleaner
    /// status codes for HEAD.
    method: Method,
    /// How to interpret the response.
    detect: Detect,
}

#[derive(Clone, Copy)]
enum Method {
    Get,
    Head,
}

#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy)]
enum Detect {
    /// Profile exists iff status is in this range (inclusive).
    StatusEq(u16),
    /// Profile exists iff status is `success_status` AND body contains `needle`.
    StatusAndBody(u16, &'static str),
    /// Profile exists iff status is `success_status` AND body does NOT contain `needle`
    /// (used for sites that 200 for everything but include a "not found" marker).
    StatusAndNotBody(u16, &'static str),
}

/// Curated set: well-known public profile sites with stable detection.
/// Order is irrelevant; probes run concurrently.
const SITES: &[Site] = &[
    Site { name: "GitHub",      url: "https://github.com/{}",                       method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "GitLab",      url: "https://gitlab.com/{}",                       method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Bitbucket",   url: "https://bitbucket.org/{}/",                   method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Codeberg",    url: "https://codeberg.org/{}",                     method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Sourceforge", url: "https://sourceforge.net/u/{}/profile",        method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Hacker News", url: "https://news.ycombinator.com/user?id={}",     method: Method::Get,  detect: Detect::StatusAndNotBody(200, "No such user.") },
    Site { name: "Reddit",      url: "https://www.reddit.com/user/{}/about.json",   method: Method::Get,  detect: Detect::StatusEq(200) },
    Site { name: "Medium",      url: "https://medium.com/@{}",                      method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Dev.to",      url: "https://dev.to/{}",                           method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Mastodon.social", url: "https://mastodon.social/@{}",             method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Fosstodon",   url: "https://fosstodon.org/@{}",                   method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Lobste.rs",   url: "https://lobste.rs/u/{}",                      method: Method::Get,  detect: Detect::StatusAndNotBody(200, "user not found") },
    Site { name: "Keybase",     url: "https://keybase.io/{}",                       method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Pastebin",    url: "https://pastebin.com/u/{}",                   method: Method::Get,  detect: Detect::StatusAndNotBody(200, "Not Found (#404)") },
    Site { name: "Hashnode",    url: "https://hashnode.com/@{}",                    method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Replit",      url: "https://replit.com/@{}",                      method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Behance",     url: "https://www.behance.net/{}",                  method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Dribbble",    url: "https://dribbble.com/{}",                     method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Flickr",      url: "https://www.flickr.com/people/{}/",           method: Method::Get,  detect: Detect::StatusAndNotBody(200, "Page Not Found") },
    Site { name: "Last.fm",     url: "https://www.last.fm/user/{}",                 method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "SoundCloud",  url: "https://soundcloud.com/{}",                   method: Method::Get,  detect: Detect::StatusAndBody(200, "soundcloud://users") },
    Site { name: "Vimeo",       url: "https://vimeo.com/{}",                        method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Steam",       url: "https://steamcommunity.com/id/{}/",           method: Method::Get,  detect: Detect::StatusAndNotBody(200, "The specified profile could not be found.") },
    Site { name: "Patreon",     url: "https://www.patreon.com/{}",                  method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Pinterest",   url: "https://www.pinterest.com/{}/",               method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Telegram",    url: "https://t.me/{}",                             method: Method::Get,  detect: Detect::StatusAndBody(200, "tgme_page_title") },
    Site { name: "Roblox",      url: "https://www.roblox.com/user.aspx?username={}", method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Twitch",      url: "https://www.twitch.tv/{}",                    method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "About.me",    url: "https://about.me/{}",                         method: Method::Head, detect: Detect::StatusEq(200) },
    Site { name: "Wikipedia",   url: "https://en.wikipedia.org/wiki/User:{}",       method: Method::Head, detect: Detect::StatusEq(200) },
];

#[async_trait]
impl Module for UsernameSearch {
    fn name(&self) -> &'static str {
        "username_search"
    }

    fn priority(&self) -> u8 {
        // Higher than email_to_username (95) so it dispatches first when
        // a Username target is the seed — gives the user visible progress
        // immediately rather than waiting for derivation modules.
        110
    }

    fn is_passive(&self) -> bool {
        // Reaches external sites — not passive in the OSINT-mode sense.
        false
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let username = target.value.trim();
        if username.is_empty() || username.len() > 64 {
            return Ok(ModuleResult::new());
        }

        let encoded = urlencode(username);
        // Per-site timeout deliberately tight: with 30 sites and a 3 s
        // engine ceiling we'd otherwise blow the per-module budget.
        // 2.5 s per site is generous for HEAD/GET against a CDN edge.
        let per_site_timeout = Duration::from_millis(2_500);

        let probes = SITES.iter().map(|site| {
            let url = site.url.replace("{}", &encoded);
            let client = ctx.http.clone();
            async move {
                let req = match site.method {
                    Method::Get => client.get(&url),
                    Method::Head => client.head(&url),
                };
                let resp = tokio::time::timeout(per_site_timeout, req.send()).await;
                let resp = match resp {
                    Ok(Ok(r)) => r,
                    _ => return ProbeResult::Error,
                };

                let status = resp.status().as_u16();
                match site.detect {
                    Detect::StatusEq(want) if status == want => ProbeResult::Found(url),
                    Detect::StatusEq(_) => ProbeResult::NotFound,
                    Detect::StatusAndBody(want, needle) => {
                        if status != want {
                            return ProbeResult::NotFound;
                        }
                        let body = match resp.text().await {
                            Ok(t) => t,
                            Err(_) => return ProbeResult::Error,
                        };
                        if body.contains(needle) {
                            ProbeResult::Found(url)
                        } else {
                            ProbeResult::NotFound
                        }
                    }
                    Detect::StatusAndNotBody(want, needle) => {
                        if status != want {
                            return ProbeResult::NotFound;
                        }
                        let body = match resp.text().await {
                            Ok(t) => t,
                            Err(_) => return ProbeResult::Error,
                        };
                        if body.contains(needle) {
                            ProbeResult::NotFound
                        } else {
                            ProbeResult::Found(url)
                        }
                    }
                }
            }
            .then_with_site(site.name)
        });

        let results: Vec<(String, ProbeResult)> = join_all(probes).await;

        let mut module_result = ModuleResult::new();
        let mut found_names: Vec<&str> = Vec::new();
        for (site_name, outcome) in &results {
            if let ProbeResult::Found(url) = outcome {
                found_names.push(site_name.as_str());
                let mut e = Entity::new(EntityKind::Url, url.as_str(), 0.92, &ctx.scan_id);
                e.tag("social-profile");
                e.tag(format!("platform:{site_name}"));
                e.add_evidence(
                    Evidence::new(
                        "username_search",
                        format!("@{username} has a profile on {site_name}"),
                    )
                    .with_attr("platform", site_name.as_str())
                    .with_attr("username", username)
                    .with_attr("url", url),
                );
                module_result.push(e);
            }
        }

        // Re-emit the seed username with a corroboration-style summary so
        // the SPA's Entities table shows a single "N platforms" row for
        // the username itself, alongside the per-platform Url entities.
        if !found_names.is_empty() {
            let mut summary = Entity::new(EntityKind::Username, username, 0.95, &ctx.scan_id);
            summary.tag("multi-platform");
            summary.add_evidence(
                Evidence::new(
                    "username_search",
                    format!(
                        "@{username} found on {n} platform(s): {list}",
                        n = found_names.len(),
                        list = found_names.join(", ")
                    ),
                )
                .with_attr("platforms_count", found_names.len().to_string())
                .with_attr("platforms", found_names.join(", "))
                .with_attr("sites_probed", SITES.len().to_string()),
            );
            module_result.push(summary);
        }
        Ok(module_result)
    }
}

enum ProbeResult {
    Found(String),
    NotFound,
    Error,
}

/// Pair the future's outcome with the site name for the consumer loop —
/// keeps the futures generic and avoids cloning the &'static str into the
/// async block.
trait WithSite: Sized + std::future::Future<Output = ProbeResult> {
    fn then_with_site(
        self,
        site: &'static str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = (String, ProbeResult)> + Send>>
    where
        Self: Send + 'static,
    {
        Box::pin(async move {
            let out = self.await;
            (site.to_string(), out)
        })
    }
}

impl<F> WithSite for F where F: std::future::Future<Output = ProbeResult> + Send + 'static {}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_username() {
        let m = UsernameSearch;
        assert!(m.accepts(&Target::new(TargetKind::Username, "test")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "test@example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    }

    #[test]
    fn site_list_nontrivial() {
        // Guard against accidentally truncating SITES in a future edit.
        assert!(SITES.len() >= 20, "expected ≥20 sites, got {}", SITES.len());
        // Every URL must contain the substitution placeholder.
        for site in SITES {
            assert!(site.url.contains("{}"), "{} missing placeholder", site.name);
        }
    }
}
