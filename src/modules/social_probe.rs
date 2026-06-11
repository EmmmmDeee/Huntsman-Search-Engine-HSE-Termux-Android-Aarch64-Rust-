//! Direct social profile probing — free, zero API keys.
//!
//! For a Username target, sends HEAD/GET requests to known profile URL
//! patterns on 20+ platforms. A 200 response confirms the profile exists;
//! 404 confirms it doesn't. Each confirmed profile becomes a Url entity
//! with the platform tagged.
//!
//! For a FullName target, probes people-search directories that use
//! name-in-URL patterns (PeeKYou, Facebook public directory, etc.).
//!
//! Uses curl subprocess for maximum compatibility — social platforms
//! often block non-browser TLS fingerprints.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "social_probe";

pub struct SocialProbe;

struct Platform {
    name: &'static str,
    url_pattern: &'static str,
    exists_codes: &'static [u16],
    /// Optional structural guard: returns `false` when the slug is
    /// demonstrably invalid for this platform (e.g. dots in a Twitter
    /// handle), preventing soft-200 false positives before any HTTP
    /// request is made. `None` means "accept any slug".
    handle_ok: Option<fn(&str) -> bool>,
}

// ── Per-platform slug validators ────────────────────────────────────────────
// Only the most impactful rules are encoded here — the ones that cause the
// most false positives (platforms that return 200 for any path, but only
// support a subset of characters in real handles).

/// Twitter/X: alphanumerics + underscore only, max 15 chars, no dots.
fn twitter_handle_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 15 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// TikTok: alphanumerics, underscores, dots allowed, max 24 chars.
/// Dots ARE valid on TikTok but the handle must not start/end with one.
fn tiktok_handle_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 24
        && !s.starts_with('.')
        && !s.ends_with('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

/// Twitch: alphanumerics + underscore only, 4–25 chars, no dots.
fn twitch_handle_ok(s: &str) -> bool {
    (4..=25).contains(&s.len()) && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Steam community ID: alphanumerics + underscore + hyphen, no dots.
fn steam_handle_ok(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Pinterest: alphanumerics + underscore only, 3–30 chars, no dots.
fn pinterest_handle_ok(s: &str) -> bool {
    (3..=30).contains(&s.len()) && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Threads / Mastodon / Bluesky: same rule as Twitter — no dots.
fn nodot_handle_ok(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// GitHub: alphanumerics + hyphens only, no consecutive hyphens, no dots.
fn github_handle_ok(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.contains("--")
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

const USERNAME_PLATFORMS: &[Platform] = &[
    Platform {
        name: "facebook",
        url_pattern: "https://www.facebook.com/{}",
        exists_codes: &[200, 302],
        handle_ok: None,
    },
    Platform {
        name: "twitter",
        url_pattern: "https://twitter.com/{}",
        exists_codes: &[200, 301, 302],
        handle_ok: Some(twitter_handle_ok),
    },
    Platform {
        name: "instagram",
        url_pattern: "https://www.instagram.com/{}/",
        exists_codes: &[200],
        handle_ok: None, // Instagram allows dots
    },
    Platform {
        name: "tiktok",
        url_pattern: "https://www.tiktok.com/@{}",
        exists_codes: &[200],
        handle_ok: Some(tiktok_handle_ok),
    },
    Platform {
        name: "github",
        url_pattern: "https://github.com/{}",
        exists_codes: &[200],
        handle_ok: Some(github_handle_ok),
    },
    Platform {
        name: "gitlab",
        url_pattern: "https://gitlab.com/{}",
        exists_codes: &[200],
        handle_ok: None,
    },
    Platform {
        name: "reddit",
        url_pattern: "https://www.reddit.com/user/{}/about.json",
        exists_codes: &[200],
        handle_ok: None,
    },
    Platform {
        name: "pinterest",
        url_pattern: "https://www.pinterest.com/{}/",
        exists_codes: &[200],
        handle_ok: Some(pinterest_handle_ok),
    },
    Platform {
        name: "steam",
        url_pattern: "https://steamcommunity.com/id/{}",
        exists_codes: &[200],
        handle_ok: Some(steam_handle_ok),
    },
    Platform {
        name: "medium",
        url_pattern: "https://medium.com/@{}",
        exists_codes: &[200],
        handle_ok: None,
    },
    Platform {
        name: "devto",
        url_pattern: "https://dev.to/{}",
        exists_codes: &[200],
        handle_ok: None,
    },
    Platform {
        name: "keybase",
        url_pattern: "https://keybase.io/{}",
        exists_codes: &[200],
        handle_ok: None,
    },
    Platform {
        name: "hackernews",
        url_pattern: "https://news.ycombinator.com/user?id={}",
        exists_codes: &[200],
        handle_ok: None,
    },
    Platform {
        name: "twitch",
        url_pattern: "https://www.twitch.tv/{}",
        exists_codes: &[200],
        handle_ok: Some(twitch_handle_ok),
    },
    Platform {
        name: "vimeo",
        url_pattern: "https://vimeo.com/{}",
        exists_codes: &[200],
        handle_ok: None,
    },
    Platform {
        name: "soundcloud",
        url_pattern: "https://soundcloud.com/{}",
        exists_codes: &[200],
        handle_ok: None,
    },
    Platform {
        name: "spotify",
        url_pattern: "https://open.spotify.com/user/{}",
        exists_codes: &[200],
        handle_ok: None,
    },
    Platform {
        name: "flickr",
        url_pattern: "https://www.flickr.com/people/{}",
        exists_codes: &[200],
        handle_ok: None,
    },
    Platform {
        name: "bitbucket",
        url_pattern: "https://bitbucket.org/{}/",
        exists_codes: &[200],
        handle_ok: None,
    },
    Platform {
        name: "stackoverflow",
        url_pattern: "https://stackoverflow.com/users/{}",
        exists_codes: &[200],
        handle_ok: None,
    },
    Platform {
        name: "myspace",
        url_pattern: "https://myspace.com/{}",
        exists_codes: &[200],
        handle_ok: None,
    },
    Platform {
        name: "linktree",
        url_pattern: "https://linktr.ee/{}",
        exists_codes: &[200],
        handle_ok: Some(nodot_handle_ok),
    },
    Platform {
        name: "about.me",
        url_pattern: "https://about.me/{}",
        exists_codes: &[200],
        handle_ok: None,
    },
    Platform {
        name: "behance",
        url_pattern: "https://www.behance.net/{}",
        exists_codes: &[200],
        handle_ok: None,
    },
    Platform {
        name: "dribbble",
        url_pattern: "https://dribbble.com/{}",
        exists_codes: &[200],
        handle_ok: None,
    },
    Platform {
        name: "mastodon",
        url_pattern: "https://mastodon.social/@{}",
        exists_codes: &[200],
        handle_ok: Some(nodot_handle_ok),
    },
    Platform {
        name: "bluesky",
        url_pattern: "https://bsky.app/profile/{}.bsky.social",
        exists_codes: &[200],
        handle_ok: Some(nodot_handle_ok),
    },
    Platform {
        name: "threads",
        url_pattern: "https://www.threads.net/@{}",
        exists_codes: &[200],
        handle_ok: Some(nodot_handle_ok),
    },
];

const NAME_PLATFORMS: &[Platform] = &[
    Platform {
        name: "facebook-public",
        url_pattern: "https://www.facebook.com/public/{}/",
        exists_codes: &[200],
        handle_ok: None,
    },
    Platform {
        name: "peekyou",
        url_pattern: "https://www.peekyou.com/{}",
        exists_codes: &[200],
        handle_ok: None,
    },
];

#[async_trait]
impl Module for SocialProbe {
    fn name(&self) -> &'static str {
        "social_probe"
    }

    fn description(&self) -> &'static str {
        "Direct profile probing across 20+ social platforms"
    }

    fn priority(&self) -> u8 {
        108
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username | TargetKind::FullName)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Url,
            EntityKind::Username,
            EntityKind::Person,
            EntityKind::Domain,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        40_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let value = target.value.trim();
        if value.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        let mut found_count = 0u32;
        let mut checked_count = 0u32;
        let mut found_platforms: Vec<&str> = Vec::new();

        let platforms = match target.kind {
            TargetKind::Username => USERNAME_PLATFORMS,
            TargetKind::FullName => NAME_PLATFORMS,
            _ => return Ok(result),
        };

        let slug = match target.kind {
            TargetKind::FullName => value.to_lowercase().replace(' ', "-"),
            _ => value.to_string(),
        };

        for platform in platforms {
            if ctx.cancel.is_cancelled() {
                break;
            }

            // Skip before any HTTP call if the slug is structurally
            // incompatible with this platform's handle rules — prevents
            // the soft-200 false positives seen with dotted handles on
            // Twitter, Twitch, Steam, Bluesky, Mastodon, Threads, etc.
            if platform.handle_ok.is_some_and(|v| !v(&slug)) {
                continue;
            }

            let url = platform.url_pattern.replace("{}", &slug);
            checked_count += 1;

            let code = probe_url(&url).await;

            if platform.exists_codes.contains(&code) {
                found_count += 1;
                found_platforms.push(platform.name);

                let mut entity = Entity::new(EntityKind::Url, &url, 0.80, &ctx.scan_id);
                entity.tag("social-profile");
                entity.tag(format!("platform:{}", platform.name));
                entity.add_evidence(
                    Evidence::new(SRC, format!("Profile found on {}", platform.name))
                        .with_attr("platform", platform.name)
                        .with_attr("http_status", code.to_string())
                        .with_attr("profile_url", &url),
                );
                result.push(entity);

                // Also extract the domain for infrastructure expansion
                if let Some(host) = url::Url::parse(&url)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_lowercase))
                    && host.contains('.')
                {
                    let mut dom = Entity::new(EntityKind::Domain, &host, 0.40, &ctx.scan_id);
                    dom.tag("social-platform");
                    dom.add_evidence(
                        Evidence::new(
                            SRC,
                            format!("Platform domain from {} profile", platform.name),
                        )
                        .with_attr("platform", platform.name),
                    );
                    result.push(dom);
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }

        // Add a summary echo of the target ONLY when at least one profile was
        // actually confirmed (see `should_echo_target`). The negative result is
        // still recorded in the dispatch log; it just must not vouch for the seed.
        found_platforms.sort_unstable();
        if let Some(summary) = build_target_summary(
            target,
            found_count,
            checked_count,
            &found_platforms,
            &ctx.scan_id,
        ) {
            result.push(summary);
        }

        Ok(result)
    }
}

/// Whether a completed probe run should echo the target back as a corroborating
/// entity. Only a run that actually confirmed at least one profile may vouch for
/// the seed: a "probed N, found 0" run retrieved nothing, so echoing the seed
/// would let a module that confirmed nothing count as an independent
/// corroborating source — inflating `C_eff` to VERIFIED and firing "confirmed
/// across the social family" on phantom evidence (observed on a network-blocked
/// self-scan).
#[must_use]
fn should_echo_target(found_count: u32) -> bool {
    found_count > 0
}

/// Build the target-echo summary entity for a probe run, or `None` when the run
/// confirmed nothing (see [`should_echo_target`]).
fn build_target_summary(
    target: &Target,
    found_count: u32,
    checked_count: u32,
    found_platforms: &[&str],
    scan_id: &str,
) -> Option<Entity> {
    if !should_echo_target(found_count) {
        return None;
    }
    let mut summary = target.to_entity(0.82, scan_id);
    summary.tag("social-probed");
    if found_count >= 3 {
        summary.tag("multi-platform");
    }
    summary.add_evidence(
        Evidence::new(
            SRC,
            format!("Probed {checked_count} platforms, found {found_count} profiles"),
        )
        .with_attr("checked", checked_count.to_string())
        .with_attr("found", found_count.to_string())
        .with_attr("platforms", found_platforms.join(", ")),
    );
    Some(summary)
}

async fn probe_url(url: &str) -> u16 {
    let output = tokio::process::Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "4",
            "-L",
            "-A",
            crate::util::curl::UA_MOBILE,
            "--",
            url,
        ])
        .kill_on_drop(true)
        .output()
        .await;

    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .trim()
            .parse()
            .unwrap_or(0),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_username_and_fullname() {
        let m = SocialProbe;
        assert!(m.accepts(&Target::new(TargetKind::Username, "test")));
        assert!(m.accepts(&Target::new(TargetKind::FullName, "Test User")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    #[test]
    fn platform_count() {
        assert!(USERNAME_PLATFORMS.len() >= 28);
        assert!(NAME_PLATFORMS.len() >= 2);
    }

    #[test]
    fn probe_with_no_hits_does_not_echo_the_seed() {
        // A run that checked platforms but confirmed nothing must NOT vouch for
        // the target — otherwise it counts as an independent corroborating
        // source and inflates the seed to VERIFIED on phantom evidence.
        assert!(!should_echo_target(0));
        let t = Target::new(TargetKind::Username, "haigenb");
        assert!(build_target_summary(&t, 0, 28, &[], "scan").is_none());
    }

    #[test]
    fn probe_with_a_hit_echoes_the_seed_as_corroboration() {
        assert!(should_echo_target(1));
        let t = Target::new(TargetKind::Username, "haigenb");
        let summary = build_target_summary(&t, 1, 28, &["github"], "scan")
            .expect("a confirmed profile must echo the seed");
        assert_eq!(summary.value, "haigenb");
        assert!(summary.has_tag("social-probed"));
        assert!(!summary.has_tag("multi-platform"));
        // Three or more confirmed profiles flags the multi-platform footprint.
        let multi = build_target_summary(&t, 3, 28, &["github", "reddit", "twitch"], "scan")
            .expect("entity");
        assert!(multi.has_tag("multi-platform"));
    }
}
