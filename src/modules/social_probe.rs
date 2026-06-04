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
}

const USERNAME_PLATFORMS: &[Platform] = &[
    Platform {
        name: "facebook",
        url_pattern: "https://www.facebook.com/{}",
        exists_codes: &[200, 302],
    },
    Platform {
        name: "twitter",
        url_pattern: "https://twitter.com/{}",
        exists_codes: &[200, 301, 302],
    },
    Platform {
        name: "instagram",
        url_pattern: "https://www.instagram.com/{}/",
        exists_codes: &[200],
    },
    Platform {
        name: "tiktok",
        url_pattern: "https://www.tiktok.com/@{}",
        exists_codes: &[200],
    },
    Platform {
        name: "github",
        url_pattern: "https://github.com/{}",
        exists_codes: &[200],
    },
    Platform {
        name: "gitlab",
        url_pattern: "https://gitlab.com/{}",
        exists_codes: &[200],
    },
    Platform {
        name: "reddit",
        url_pattern: "https://www.reddit.com/user/{}/about.json",
        exists_codes: &[200],
    },
    Platform {
        name: "pinterest",
        url_pattern: "https://www.pinterest.com/{}/",
        exists_codes: &[200],
    },
    Platform {
        name: "steam",
        url_pattern: "https://steamcommunity.com/id/{}",
        exists_codes: &[200],
    },
    Platform {
        name: "medium",
        url_pattern: "https://medium.com/@{}",
        exists_codes: &[200],
    },
    Platform {
        name: "devto",
        url_pattern: "https://dev.to/{}",
        exists_codes: &[200],
    },
    Platform {
        name: "keybase",
        url_pattern: "https://keybase.io/{}",
        exists_codes: &[200],
    },
    Platform {
        name: "hackernews",
        url_pattern: "https://news.ycombinator.com/user?id={}",
        exists_codes: &[200],
    },
    Platform {
        name: "twitch",
        url_pattern: "https://www.twitch.tv/{}",
        exists_codes: &[200],
    },
    Platform {
        name: "vimeo",
        url_pattern: "https://vimeo.com/{}",
        exists_codes: &[200],
    },
    Platform {
        name: "soundcloud",
        url_pattern: "https://soundcloud.com/{}",
        exists_codes: &[200],
    },
    Platform {
        name: "spotify",
        url_pattern: "https://open.spotify.com/user/{}",
        exists_codes: &[200],
    },
    Platform {
        name: "flickr",
        url_pattern: "https://www.flickr.com/people/{}",
        exists_codes: &[200],
    },
    Platform {
        name: "bitbucket",
        url_pattern: "https://bitbucket.org/{}/",
        exists_codes: &[200],
    },
    Platform {
        name: "stackoverflow",
        url_pattern: "https://stackoverflow.com/users/{}",
        exists_codes: &[200],
    },
    Platform {
        name: "myspace",
        url_pattern: "https://myspace.com/{}",
        exists_codes: &[200],
    },
    Platform {
        name: "linktree",
        url_pattern: "https://linktr.ee/{}",
        exists_codes: &[200],
    },
    Platform {
        name: "about.me",
        url_pattern: "https://about.me/{}",
        exists_codes: &[200],
    },
    Platform {
        name: "behance",
        url_pattern: "https://www.behance.net/{}",
        exists_codes: &[200],
    },
    Platform {
        name: "dribbble",
        url_pattern: "https://dribbble.com/{}",
        exists_codes: &[200],
    },
    Platform {
        name: "mastodon",
        url_pattern: "https://mastodon.social/@{}",
        exists_codes: &[200],
    },
    Platform {
        name: "bluesky",
        url_pattern: "https://bsky.app/profile/{}.bsky.social",
        exists_codes: &[200],
    },
    Platform {
        name: "threads",
        url_pattern: "https://www.threads.net/@{}",
        exists_codes: &[200],
    },
];

const NAME_PLATFORMS: &[Platform] = &[
    Platform {
        name: "facebook-public",
        url_pattern: "https://www.facebook.com/public/{}/",
        exists_codes: &[200],
    },
    Platform {
        name: "peekyou",
        url_pattern: "https://www.peekyou.com/{}",
        exists_codes: &[200],
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

        for (platform, url) in probe_plan(target.kind, value) {
            if ctx.cancel.is_cancelled() {
                break;
            }

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
                if let Some(host) = platform_domain(&url) {
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

        // Add summary to the target entity
        if found_count > 0 || checked_count > 0 {
            let mut summary = target.to_entity(0.82, &ctx.scan_id);
            summary.tag("social-probed");
            if found_count >= 3 {
                summary.tag("multi-platform");
            }
            found_platforms.sort_unstable();
            summary.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Probed {checked_count} platforms, found {found_count} profiles"),
                )
                .with_attr("checked", checked_count.to_string())
                .with_attr("found", found_count.to_string())
                .with_attr("platforms", found_platforms.join(", ")),
            );
            result.push(summary);
        }

        Ok(result)
    }
}

/// Turn a target into a probe slug. **Pure**: a `FullName` is lowercased and
/// space-hyphenated (people-directory URL shape, e.g. `Jane Roe` → `jane-roe`);
/// every other kind — in practice `Username` — is passed through verbatim so
/// the handle's exact case and punctuation reach the platform unchanged.
fn build_slug(kind: TargetKind, value: &str) -> String {
    match kind {
        TargetKind::FullName => value.to_lowercase().replace(' ', "-"),
        _ => value.to_string(),
    }
}

/// The `(platform, probe-URL)` pairs to check for a target. **Pure** — captures
/// the platform-table selection (`Username` vs `FullName`), the slug transform,
/// and the `{}` URL-pattern substitution, none of which were previously tested.
/// Returns empty for kinds the module does not probe.
fn probe_plan(kind: TargetKind, value: &str) -> Vec<(&'static Platform, String)> {
    let platforms = match kind {
        TargetKind::Username => USERNAME_PLATFORMS,
        TargetKind::FullName => NAME_PLATFORMS,
        _ => return Vec::new(),
    };
    let slug = build_slug(kind, value);
    platforms
        .iter()
        .map(|p| (p, p.url_pattern.replace("{}", &slug)))
        .collect()
}

/// The lowercased registrable host of a confirmed profile URL, used to seed an
/// infrastructure-expansion `Domain`. **Pure**: `None` when the URL does not
/// parse or its host carries no dot (e.g. `localhost`), so junk never becomes a
/// domain entity.
fn platform_domain(profile_url: &str) -> Option<String> {
    url::Url::parse(profile_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_lowercase))
        .filter(|h| h.contains('.'))
}

async fn probe_url(url: &str) -> u16 {
    let output = tokio::process::Command::new("curl")
        .args([
            "-s", "-o", "/dev/null",
            "-w", "%{http_code}",
            "--max-time", "4",
            "-L",
            "-A", "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
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
    fn fullname_slug_is_lowercased_and_hyphenated() {
        assert_eq!(build_slug(TargetKind::FullName, "Jane Roe"), "jane-roe");
        // Internal punctuation is preserved; only spaces become hyphens.
        assert_eq!(
            build_slug(TargetKind::FullName, "John A. Doe"),
            "john-a.-doe"
        );
    }

    #[test]
    fn username_slug_is_passed_through_verbatim() {
        // Case and underscores survive — a handle is matched exactly.
        assert_eq!(build_slug(TargetKind::Username, "John_Doe99"), "John_Doe99");
    }

    #[test]
    fn username_plan_covers_every_platform_and_substitutes_slug() {
        let plan = probe_plan(TargetKind::Username, "John_Doe99");
        assert_eq!(plan.len(), USERNAME_PLATFORMS.len());
        let url = |name: &str| {
            plan.iter()
                .find(|(p, _)| p.name == name)
                .map(|(_, u)| u.as_str())
                .unwrap()
        };
        assert_eq!(url("github"), "https://github.com/John_Doe99");
        // The slug lands before the pattern's trailing suffix.
        assert_eq!(
            url("bluesky"),
            "https://bsky.app/profile/John_Doe99.bsky.social"
        );
        assert_eq!(url("mastodon"), "https://mastodon.social/@John_Doe99");
    }

    #[test]
    fn fullname_plan_uses_hyphenated_slug() {
        let plan = probe_plan(TargetKind::FullName, "Jane Roe");
        assert_eq!(plan.len(), NAME_PLATFORMS.len());
        let peekyou = plan
            .iter()
            .find(|(p, _)| p.name == "peekyou")
            .map(|(_, u)| u.as_str())
            .unwrap();
        assert_eq!(peekyou, "https://www.peekyou.com/jane-roe");
    }

    #[test]
    fn probe_plan_empty_for_unprobed_kinds() {
        assert!(probe_plan(TargetKind::Email, "x@y.com").is_empty());
        assert!(probe_plan(TargetKind::Domain, "x.com").is_empty());
    }

    #[test]
    fn platform_domain_extracts_lowercased_host() {
        assert_eq!(
            platform_domain("https://github.com/foo"),
            Some("github.com".to_string())
        );
        assert_eq!(
            platform_domain("https://www.TikTok.com/@bar"),
            Some("www.tiktok.com".to_string())
        );
    }

    #[test]
    fn platform_domain_rejects_unparseable_or_dotless_hosts() {
        assert_eq!(platform_domain("not a url"), None);
        assert_eq!(platform_domain("http://localhost/x"), None);
    }
}
