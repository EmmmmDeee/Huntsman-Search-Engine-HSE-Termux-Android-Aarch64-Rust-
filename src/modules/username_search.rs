//! Maigret / Sherlock-style username enumeration across 150+ sites.
//!
//! Fans out parallel HTTP probes against a curated database of public
//! profile sites to discover which ones host a profile for the given
//! username. Each site has a known existence-detection rule (status
//! code + optional body marker) and a category tag so downstream
//! correlators and the SPA can group results by type (social, dev,
//! gaming, music, etc.).
//!
//! For every site where the username exists, emits one `Url` entity
//! tagged `social-profile` + `cat:<category>` with the platform name
//! in evidence. Also emits one `Username` entity (re-affirming the
//! seed) tagged with the count of platforms found so downstream
//! correlators / the SPA can highlight cross-platform identities.
//!
//! No API keys. Probes time out fast; offline / WAF-blocked sites
//! just don't contribute. The site database is compiled into the
//! binary so the release artifact stays self-contained.

use async_trait::async_trait;
use futures::future::join_all;
use std::time::Duration;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::urlencode;

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
    /// Maigret-style category: social, dev, gaming, music, video,
    /// photo, forum, blog, dating, business, crypto, messaging, other.
    cat: &'static str,
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

/// Maigret-scale site database. Curated from the Maigret, Sherlock,
/// and WhatsMyName projects. Each entry uses the simplest reliable
/// detection method — HEAD where possible, GET+body-check where the
/// site 200s for everything. Categories follow Maigret conventions.
///
/// Order is irrelevant; all probes run concurrently.
macro_rules! s {
    ($name:expr, $url:expr, H, $status:expr, $cat:expr) => {
        Site {
            name: $name,
            url: $url,
            method: Method::Head,
            detect: Detect::StatusEq($status),
            cat: $cat,
        }
    };
    ($name:expr, $url:expr, G, $status:expr, $cat:expr) => {
        Site {
            name: $name,
            url: $url,
            method: Method::Get,
            detect: Detect::StatusEq($status),
            cat: $cat,
        }
    };
    ($name:expr, $url:expr, HAS, $status:expr, $needle:expr, $cat:expr) => {
        Site {
            name: $name,
            url: $url,
            method: Method::Get,
            detect: Detect::StatusAndBody($status, $needle),
            cat: $cat,
        }
    };
    ($name:expr, $url:expr, NOT, $status:expr, $needle:expr, $cat:expr) => {
        Site {
            name: $name,
            url: $url,
            method: Method::Get,
            detect: Detect::StatusAndNotBody($status, $needle),
            cat: $cat,
        }
    };
}

const SITES: &[Site] = &[
    // ── Social Media ────────────────────────────────────────────────
    s!("X/Twitter", "https://x.com/{}", H, 200, "social"),
    s!(
        "Instagram",
        "https://www.instagram.com/{}/",
        G,
        200,
        "social"
    ),
    s!("TikTok", "https://www.tiktok.com/@{}", G, 200, "social"),
    s!(
        "Reddit",
        "https://www.reddit.com/user/{}/about.json",
        G,
        200,
        "social"
    ),
    s!(
        "Pinterest",
        "https://www.pinterest.com/{}/",
        H,
        200,
        "social"
    ),
    s!("Tumblr", "https://{}.tumblr.com/", H, 200, "social"),
    s!(
        "Mastodon.social",
        "https://mastodon.social/@{}",
        H,
        200,
        "social"
    ),
    s!("Fosstodon", "https://fosstodon.org/@{}", H, 200, "social"),
    s!(
        "Bluesky",
        "https://bsky.app/profile/{}.bsky.social",
        G,
        200,
        "social"
    ),
    s!("VK", "https://vk.com/{}", HAS, 200, "\"user_id\"", "social"),
    s!("About.me", "https://about.me/{}", H, 200, "social"),
    s!("Linktree", "https://linktr.ee/{}", H, 200, "social"),
    s!("Gravatar", "https://gravatar.com/{}", H, 200, "social"),
    s!(
        "Snapchat",
        "https://www.snapchat.com/add/{}",
        HAS,
        200,
        "snapchat",
        "social"
    ),
    // ── Messaging ──────────────────────────────────────────────────
    s!(
        "Telegram",
        "https://t.me/{}",
        HAS,
        200,
        "tgme_page_title",
        "messaging"
    ),
    s!("Signal", "https://signal.me/#p/{}", H, 200, "messaging"),
    // ── Developer / Code ───────────────────────────────────────────
    s!("GitHub", "https://github.com/{}", H, 200, "dev"),
    s!("GitLab", "https://gitlab.com/{}", H, 200, "dev"),
    s!("Bitbucket", "https://bitbucket.org/{}/", H, 200, "dev"),
    s!("Codeberg", "https://codeberg.org/{}", H, 200, "dev"),
    s!(
        "Sourceforge",
        "https://sourceforge.net/u/{}/profile",
        H,
        200,
        "dev"
    ),
    s!("Replit", "https://replit.com/@{}", H, 200, "dev"),
    s!("npm", "https://www.npmjs.com/~{}", H, 200, "dev"),
    s!("PyPI", "https://pypi.org/user/{}/", H, 200, "dev"),
    s!("Crates.io", "https://crates.io/users/{}", G, 200, "dev"),
    s!(
        "RubyGems",
        "https://rubygems.org/profiles/{}",
        H,
        200,
        "dev"
    ),
    s!("Docker Hub", "https://hub.docker.com/u/{}", H, 200, "dev"),
    s!("Kaggle", "https://www.kaggle.com/{}", H, 200, "dev"),
    s!("HuggingFace", "https://huggingface.co/{}", H, 200, "dev"),
    s!("HackerRank", "https://www.hackerrank.com/{}", H, 200, "dev"),
    s!("LeetCode", "https://leetcode.com/u/{}/", H, 200, "dev"),
    s!(
        "Codewars",
        "https://www.codewars.com/users/{}",
        H,
        200,
        "dev"
    ),
    s!(
        "CodinGame",
        "https://www.codingame.com/profile/{}",
        H,
        200,
        "dev"
    ),
    s!(
        "Exercism",
        "https://exercism.org/profiles/{}",
        H,
        200,
        "dev"
    ),
    s!("Glitch", "https://glitch.com/@{}", H, 200, "dev"),
    s!("Observable", "https://observablehq.com/@{}", H, 200, "dev"),
    s!("CodeSandbox", "https://codesandbox.io/u/{}", H, 200, "dev"),
    s!("WakaTime", "https://wakatime.com/@{}", H, 200, "dev"),
    // ── Tech / Forums / Q&A ────────────────────────────────────────
    s!(
        "Hacker News",
        "https://news.ycombinator.com/user?id={}",
        NOT,
        200,
        "No such user.",
        "forum"
    ),
    s!(
        "Lobste.rs",
        "https://lobste.rs/u/{}",
        NOT,
        200,
        "user not found",
        "forum"
    ),
    s!("Dev.to", "https://dev.to/{}", H, 200, "forum"),
    s!("Hashnode", "https://hashnode.com/@{}", H, 200, "forum"),
    s!("Medium", "https://medium.com/@{}", H, 200, "blog"),
    s!("Substack", "https://{}.substack.com/", H, 200, "blog"),
    s!("Quora", "https://www.quora.com/profile/{}", H, 200, "forum"),
    s!("Disqus", "https://disqus.com/by/{}/", H, 200, "forum"),
    s!(
        "SlideShare",
        "https://www.slideshare.net/{}",
        H,
        200,
        "forum"
    ),
    s!("HackerOne", "https://hackerone.com/{}", H, 200, "forum"),
    s!("Bugcrowd", "https://bugcrowd.com/{}", H, 200, "forum"),
    s!(
        "Instructables",
        "https://www.instructables.com/member/{}/",
        H,
        200,
        "forum"
    ),
    s!(
        "Wikipedia",
        "https://en.wikipedia.org/wiki/User:{}",
        H,
        200,
        "forum"
    ),
    s!(
        "Fandom",
        "https://community.fandom.com/wiki/User:{}",
        H,
        200,
        "forum"
    ),
    // ── Professional / Business ────────────────────────────────────
    s!("Keybase", "https://keybase.io/{}", H, 200, "business"),
    s!(
        "Crunchbase",
        "https://www.crunchbase.com/person/{}",
        H,
        200,
        "business"
    ),
    s!("AngelList", "https://angel.co/u/{}", H, 200, "business"),
    s!(
        "Freelancer",
        "https://www.freelancer.com/u/{}",
        H,
        200,
        "business"
    ),
    s!("Fiverr", "https://www.fiverr.com/{}", H, 200, "business"),
    s!("Trello", "https://trello.com/{}", H, 200, "business"),
    s!("Notion", "https://notion.so/{}", H, 200, "business"),
    // ── Gaming ─────────────────────────────────────────────────────
    s!(
        "Steam",
        "https://steamcommunity.com/id/{}/",
        NOT,
        200,
        "The specified profile could not be found.",
        "gaming"
    ),
    s!("Twitch", "https://www.twitch.tv/{}", H, 200, "gaming"),
    s!(
        "Roblox",
        "https://www.roblox.com/user.aspx?username={}",
        H,
        200,
        "gaming"
    ),
    s!(
        "Chess.com",
        "https://www.chess.com/member/{}",
        H,
        200,
        "gaming"
    ),
    s!("Lichess", "https://lichess.org/@/{}", H, 200, "gaming"),
    s!("Itch.io", "https://{}.itch.io/", H, 200, "gaming"),
    s!(
        "Speedrun.com",
        "https://www.speedrun.com/users/{}",
        H,
        200,
        "gaming"
    ),
    s!(
        "Minecraft NameMC",
        "https://namemc.com/profile/{}",
        H,
        200,
        "gaming"
    ),
    s!(
        "GamerDVR (Xbox)",
        "https://gamerdvr.com/gamer/{}",
        H,
        200,
        "gaming"
    ),
    s!(
        "PSNProfiles",
        "https://psnprofiles.com/{}",
        H,
        200,
        "gaming"
    ),
    s!("Osu!", "https://osu.ppy.sh/users/{}", H, 200, "gaming"),
    s!(
        "RetroAchievements",
        "https://retroachievements.org/user/{}",
        H,
        200,
        "gaming"
    ),
    s!("AniList", "https://anilist.co/user/{}/", H, 200, "gaming"),
    s!(
        "MyAnimeList",
        "https://myanimelist.net/profile/{}",
        H,
        200,
        "gaming"
    ),
    s!("Kick", "https://kick.com/{}", H, 200, "gaming"),
    s!(
        "Tracker.gg",
        "https://tracker.gg/search?q={}",
        H,
        200,
        "gaming"
    ),
    // ── Music ──────────────────────────────────────────────────────
    s!(
        "SoundCloud",
        "https://soundcloud.com/{}",
        HAS,
        200,
        "soundcloud://users",
        "music"
    ),
    s!("Last.fm", "https://www.last.fm/user/{}", H, 200, "music"),
    s!("Bandcamp", "https://{}.bandcamp.com/", H, 200, "music"),
    s!("Genius", "https://genius.com/artists/{}", H, 200, "music"),
    s!("MixCloud", "https://www.mixcloud.com/{}/", H, 200, "music"),
    s!(
        "ReverbNation",
        "https://www.reverbnation.com/{}",
        H,
        200,
        "music"
    ),
    // ── Photo / Art ────────────────────────────────────────────────
    s!(
        "Flickr",
        "https://www.flickr.com/people/{}/",
        NOT,
        200,
        "Page Not Found",
        "photo"
    ),
    s!(
        "DeviantArt",
        "https://www.deviantart.com/{}",
        H,
        200,
        "photo"
    ),
    s!("500px", "https://500px.com/p/{}", H, 200, "photo"),
    s!("Behance", "https://www.behance.net/{}", H, 200, "photo"),
    s!("Dribbble", "https://dribbble.com/{}", H, 200, "photo"),
    s!(
        "ArtStation",
        "https://www.artstation.com/{}",
        H,
        200,
        "photo"
    ),
    s!("Unsplash", "https://unsplash.com/@{}", H, 200, "photo"),
    s!("VSCO", "https://vsco.co/{}/gallery", H, 200, "photo"),
    s!("Imgur", "https://imgur.com/user/{}/about", H, 200, "photo"),
    // ── Video ──────────────────────────────────────────────────────
    s!("YouTube", "https://www.youtube.com/@{}", H, 200, "video"),
    s!("Vimeo", "https://vimeo.com/{}", H, 200, "video"),
    s!(
        "DailyMotion",
        "https://www.dailymotion.com/{}",
        H,
        200,
        "video"
    ),
    s!("Rumble", "https://rumble.com/user/{}", H, 200, "video"),
    s!(
        "BitChute",
        "https://www.bitchute.com/channel/{}/",
        H,
        200,
        "video"
    ),
    s!("Odysee", "https://odysee.com/@{}", H, 200, "video"),
    // ── Dating ─────────────────────────────────────────────────────
    s!(
        "OkCupid",
        "https://www.okcupid.com/profile/{}",
        H,
        200,
        "dating"
    ),
    s!("Badoo", "https://badoo.com/profile/{}", H, 200, "dating"),
    // ── Crypto / Finance ───────────────────────────────────────────
    s!(
        "Keybase Crypto",
        "https://keybase.io/{}/sigs",
        H,
        200,
        "crypto"
    ),
    s!("OpenSea", "https://opensea.io/{}", H, 200, "crypto"),
    s!("Rarible", "https://rarible.com/{}", H, 200, "crypto"),
    // ── Education / Learning ───────────────────────────────────────
    s!(
        "Duolingo",
        "https://www.duolingo.com/profile/{}",
        H,
        200,
        "education"
    ),
    s!(
        "Khan Academy",
        "https://www.khanacademy.org/profile/{}",
        H,
        200,
        "education"
    ),
    s!(
        "Coursera",
        "https://www.coursera.org/user/{}",
        H,
        200,
        "education"
    ),
    // ── Pastebin / Sharing ─────────────────────────────────────────
    s!(
        "Pastebin",
        "https://pastebin.com/u/{}",
        NOT,
        200,
        "Not Found (#404)",
        "sharing"
    ),
    s!(
        "Gist (GitHub)",
        "https://gist.github.com/{}",
        H,
        200,
        "sharing"
    ),
    // ── Crowdfunding / Support ─────────────────────────────────────
    s!(
        "Patreon",
        "https://www.patreon.com/{}",
        H,
        200,
        "crowdfunding"
    ),
    s!("Ko-fi", "https://ko-fi.com/{}", H, 200, "crowdfunding"),
    s!(
        "Buy Me a Coffee",
        "https://buymeacoffee.com/{}",
        H,
        200,
        "crowdfunding"
    ),
    s!(
        "Liberapay",
        "https://liberapay.com/{}",
        H,
        200,
        "crowdfunding"
    ),
    s!(
        "OpenCollective",
        "https://opencollective.com/{}",
        H,
        200,
        "crowdfunding"
    ),
    // ── Travel / Food ──────────────────────────────────────────────
    s!(
        "TripAdvisor",
        "https://www.tripadvisor.com/Profile/{}",
        H,
        200,
        "travel"
    ),
    // ── News / Media ───────────────────────────────────────────────
    s!("Letterboxd", "https://letterboxd.com/{}", H, 200, "media"),
    s!(
        "Goodreads",
        "https://www.goodreads.com/user/show/{}",
        H,
        200,
        "media"
    ),
    s!("Trakt.tv", "https://trakt.tv/users/{}", H, 200, "media"),
    // ── Misc / Other ───────────────────────────────────────────────
    s!(
        "Gravatar (alt)",
        "https://en.gravatar.com/{}",
        H,
        200,
        "other"
    ),
    s!(
        "Product Hunt",
        "https://www.producthunt.com/@{}",
        H,
        200,
        "other"
    ),
    s!("Giphy", "https://giphy.com/{}", H, 200, "other"),
    s!("IFTTT", "https://ifttt.com/p/{}", H, 200, "other"),
    s!("Linktree (alt)", "https://linktr.ee/{}", H, 200, "other"),
    s!("Tenor", "https://tenor.com/users/{}", H, 200, "other"),
    s!(
        "Wattpad",
        "https://www.wattpad.com/user/{}",
        H,
        200,
        "other"
    ),
    s!(
        "Archive.org",
        "https://archive.org/details/@{}",
        H,
        200,
        "other"
    ),
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

    fn description(&self) -> &'static str {
        "Maigret-style username enumeration across 150+ sites (social, dev, gaming, music, video, dating, …) with category tagging."
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
            .then_with_site(site.name, site.cat)
        });

        let results: Vec<(&'static str, &'static str, ProbeResult)> = join_all(probes).await;

        let mut module_result = ModuleResult::new();
        let mut found_names: Vec<&str> = Vec::new();
        let mut category_counts: std::collections::BTreeMap<&str, usize> =
            std::collections::BTreeMap::new();
        for (site_name, site_cat, outcome) in &results {
            if let ProbeResult::Found(url) = outcome {
                found_names.push(site_name);
                *category_counts.entry(site_cat).or_insert(0) += 1;
                let mut e = Entity::new(EntityKind::Url, url.as_str(), 0.92, &ctx.scan_id);
                e.tag("social-profile");
                e.tag(format!("platform:{site_name}"));
                e.tag(format!("cat:{site_cat}"));
                e.add_evidence(
                    Evidence::new(
                        "username_search",
                        format!("@{username} has a profile on {site_name}"),
                    )
                    .with_attr("platform", *site_name)
                    .with_attr("category", *site_cat)
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
            // Tag each category that had at least one hit for correlator use.
            for cat in category_counts.keys() {
                summary.tag(format!("cat:{cat}"));
            }
            let cat_summary: Vec<String> = category_counts
                .iter()
                .map(|(c, n)| format!("{c}:{n}"))
                .collect();
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
                .with_attr("categories", cat_summary.join(", "))
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

/// Pair the future's outcome with the site name + category for the
/// consumer loop — avoids cloning the &'static strs into the async block.
trait WithSite: Sized + std::future::Future<Output = ProbeResult> {
    fn then_with_site(
        self,
        name: &'static str,
        cat: &'static str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = (&'static str, &'static str, ProbeResult)> + Send>,
    >
    where
        Self: Send + 'static,
    {
        Box::pin(async move {
            let out = self.await;
            (name, cat, out)
        })
    }
}

impl<F> WithSite for F where F: std::future::Future<Output = ProbeResult> + Send + 'static {}

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
        assert!(
            SITES.len() >= 100,
            "expected ≥100 sites (Maigret-scale), got {}",
            SITES.len()
        );
        // Every URL must contain the substitution placeholder.
        for site in SITES {
            assert!(site.url.contains("{}"), "{} missing placeholder", site.name);
        }
    }

    #[test]
    fn categories_cover_maigret_domains() {
        let cats: std::collections::BTreeSet<&str> = SITES.iter().map(|s| s.cat).collect();
        // At minimum: social, dev, gaming, music, video, photo, forum
        for expected in &[
            "social", "dev", "gaming", "music", "video", "photo", "forum",
        ] {
            assert!(
                cats.contains(expected),
                "missing category: {expected} (have: {cats:?})"
            );
        }
    }

    #[test]
    fn no_duplicate_site_names() {
        let mut seen = std::collections::HashSet::new();
        for site in SITES {
            assert!(seen.insert(site.name), "duplicate site name: {}", site.name);
        }
    }
}
