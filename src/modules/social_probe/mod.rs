//! Direct social profile probing — free, zero API keys.
//!
//! For a Username target, sends HEAD/GET requests to known profile URL
//! patterns on 20+ platforms. A matching status code is a hit; for the
//! handful of platforms known to return that status for any handle
//! (soft-404/SPA-shell), a `negative_patterns` body check must also pass —
//! see `Platform::negative_patterns`. Each confirmed profile becomes a Url
//! entity with the platform tagged, plus `verified-detection` (body-marker
//! confirmed) or `weak-detection` (status code alone — the correlator
//! discounts these, see `core::correlator::rules::identity::account`'s
//! AU-055 and `cluster`'s AU-003) so a bare status-only guess is never
//! presented as a confirmed, subject-controlled account.
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

#[cfg(test)]
mod tests;

pub(super) const SRC: &str = "social_probe";

pub(super) struct Platform {
    pub(super) name: &'static str,
    pub(super) url_pattern: &'static str,
    pub(super) exists_codes: &'static [u16],
    /// Substrings that, when found in the response body, indicate the profile
    /// does NOT exist even though the server returned a success status code.
    /// Used for platforms that return HTTP 200 for all paths regardless of
    /// whether a user exists. Leave empty (`&[]`) for platforms where the
    /// status code is reliable.
    pub(super) negative_patterns: &'static [&'static str],
}

/// Confidence + verified-flag a hit earns, tiered by rigour — mirrors
/// `streaming_probe`/`username_search`'s `detection_strength`. A platform
/// with a `negative_patterns` check just had its body inspected for a
/// "doesn't exist" marker and passed — a real confirmation (0.92, verified).
/// A platform with no negative pattern rests entirely on the HTTP status
/// code, which a soft-404/SPA-shell can return for almost any handle — an
/// unconfirmed status-only lead (0.74, unverified). Tagging the weak case
/// `weak-detection` lets the correlator (AU-003/AU-038/AU-045/AU-055)
/// discount it instead of counting a guess as a confirmed, subject-controlled
/// account — the exact false signal a real scan against a guessed handle
/// produced across 30+ status-only platforms.
fn detection_strength(platform: &Platform) -> (f64, bool) {
    crate::util::probe_confidence::detection_strength(!platform.negative_patterns.is_empty())
}

pub(super) const USERNAME_PLATFORMS: &[Platform] = &[
    Platform {
        name: "facebook",
        url_pattern: "https://www.facebook.com/{}",
        exists_codes: &[200, 302],
        negative_patterns: &[],
    },
    Platform {
        name: "twitter",
        url_pattern: "https://twitter.com/{}",
        exists_codes: &[200, 301, 302],
        negative_patterns: &[],
    },
    Platform {
        name: "instagram",
        url_pattern: "https://www.instagram.com/{}/",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "tiktok",
        url_pattern: "https://www.tiktok.com/@{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "github",
        url_pattern: "https://github.com/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "gitlab",
        url_pattern: "https://gitlab.com/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "reddit",
        url_pattern: "https://www.reddit.com/user/{}/about.json",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "pinterest",
        url_pattern: "https://www.pinterest.com/{}/",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "steam",
        url_pattern: "https://steamcommunity.com/id/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "medium",
        url_pattern: "https://medium.com/@{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "devto",
        url_pattern: "https://dev.to/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "keybase",
        url_pattern: "https://keybase.io/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "hackernews",
        url_pattern: "https://news.ycombinator.com/user?id={}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "twitch",
        url_pattern: "https://www.twitch.tv/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "vimeo",
        url_pattern: "https://vimeo.com/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "soundcloud",
        url_pattern: "https://soundcloud.com/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "spotify",
        url_pattern: "https://open.spotify.com/user/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "flickr",
        url_pattern: "https://www.flickr.com/people/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "bitbucket",
        url_pattern: "https://bitbucket.org/{}/",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "stackoverflow",
        url_pattern: "https://stackoverflow.com/users/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "myspace",
        url_pattern: "https://myspace.com/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "linktree",
        url_pattern: "https://linktr.ee/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "about.me",
        url_pattern: "https://about.me/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "behance",
        url_pattern: "https://www.behance.net/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "dribbble",
        url_pattern: "https://dribbble.com/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "mastodon",
        url_pattern: "https://mastodon.social/@{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "bluesky",
        url_pattern: "https://bsky.app/profile/{}.bsky.social",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "threads",
        url_pattern: "https://www.threads.net/@{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    // Platforms known to return HTTP 200 for all paths regardless of user existence.
    // negative_patterns gate the false positives that status-code-only checks miss.
    Platform {
        name: "livejasmin",
        url_pattern: "https://www.livejasmin.com/en/{}",
        exists_codes: &[200],
        negative_patterns: &["Page Not Found", "performer not found", "no results"],
    },
    Platform {
        name: "imlive",
        url_pattern: "https://www.imlive.com/{}",
        exists_codes: &[200],
        negative_patterns: &["Page Not Found", "user not found", "404"],
    },
    Platform {
        name: "mydirtyhobby",
        url_pattern: "https://www.mydirtyhobby.com/{}",
        exists_codes: &[200],
        negative_patterns: &["Leider existiert", "not found", "does not exist"],
    },
    Platform {
        name: "sextpanther",
        url_pattern: "https://www.sextpanther.com/{}",
        exists_codes: &[200],
        negative_patterns: &["Page Not Found", "user not found", "profile not found"],
    },
    Platform {
        name: "stripchat",
        url_pattern: "https://stripchat.com/{}",
        exists_codes: &[200],
        negative_patterns: &["Model Not Found", "not found", "404 Not Found"],
    },
    Platform {
        name: "loyalfans",
        url_pattern: "https://www.loyalfans.com/{}",
        exists_codes: &[200],
        negative_patterns: &["Page Not Found", "user not found", "profile not found"],
    },
];

pub(super) const NAME_PLATFORMS: &[Platform] = &[
    Platform {
        name: "facebook-public",
        url_pattern: "https://www.facebook.com/public/{}/",
        exists_codes: &[200],
        negative_patterns: &[],
    },
    Platform {
        name: "peekyou",
        url_pattern: "https://www.peekyou.com/{}",
        exists_codes: &[200],
        negative_patterns: &[],
    },
];

pub struct SocialProbe;

#[async_trait]
impl Module for SocialProbe {
    fn name(&self) -> &'static str {
        "social_probe"
    }

    fn description(&self) -> &'static str {
        "Social identity sweep — direct profile probing across 20+ platforms"
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

            // Percent-encode the substituted value so a handle with URL-significant
            // characters can't break out of the path/query (matches the other
            // presence probes); a plain alphanumeric handle is unchanged.
            let url = platform
                .url_pattern
                .replace("{}", &crate::util::http::urlencode(&slug));
            checked_count += 1;

            let (code, body) = crate::util::curl::fetch_with_status(
                &url,
                4_000,
                !platform.negative_patterns.is_empty(),
            )
            .await;

            let body_blocks = !platform.negative_patterns.is_empty()
                && platform.negative_patterns.iter().any(|p| body.contains(p));

            if platform.exists_codes.contains(&code) && !body_blocks {
                found_count += 1;
                found_platforms.push(platform.name);

                let (confidence, verified) = detection_strength(platform);

                let mut entity = Entity::new(EntityKind::Url, &url, confidence, &ctx.scan_id);
                entity.tag("social-profile");
                entity.tag(format!("platform:{}", platform.name));
                entity.tag(if verified {
                    "verified-detection"
                } else {
                    "weak-detection"
                });
                entity.add_evidence(
                    Evidence::new(SRC, format!("Profile found on {}", platform.name))
                        .with_attr("platform", platform.name)
                        .with_attr("http_status", code.to_string())
                        .with_attr("profile_url", &url)
                        .with_attr(
                            "detection",
                            if verified {
                                "body-marker"
                            } else {
                                "status-only"
                            },
                        ),
                );
                result.push(entity);

                // A confirmed profile's value is the URL + handle, already
                // emitted above. The platform's APEX domain (instagram.com,
                // tiktok.com, …) is the provider's estate, never the subject's
                // asset — emitting it as a Domain entity drags the scan into
                // mapping the platform's DNS/CDN infrastructure and inflates
                // correlations (a real on-device scan flagged exactly this as
                // CRITICAL infrastructure-pollution). Only surface a platform host
                // that is NOT a known mega/social/infra domain — i.e. a niche or
                // self-hosted site that might genuinely belong to the subject.
                if let Some(host) = url::Url::parse(&url)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_lowercase))
                    && host.contains('.')
                    && !crate::core::scan::is_noncentral_domain(&host)
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
pub(super) fn should_echo_target(found_count: u32) -> bool {
    found_count > 0
}

/// Build the target-echo summary entity for a probe run, or `None` when the run
/// confirmed nothing (see [`should_echo_target`]).
pub(super) fn build_target_summary(
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
        // `platforms_count` is the canonical attribute the cross-platform
        // username-footprint correlator (AU-011) reads to count how many
        // platforms one module confirmed a handle on. The sibling aggregate
        // probes (`username_search`, `streaming_probe`) both stamp it; without
        // it AU-011 falls back to counting distinct PLATFORM_SOURCES modules —
        // and `social_probe` is not on that list — so a handle this module
        // confirmed on ≥3 platforms would silently never fire AU-011 despite
        // being tagged `multi-platform` here. Kept alongside `found` (its own
        // profiles-checked convention) rather than replacing it.
        .with_attr("platforms_count", found_platforms.len().to_string())
        .with_attr("platforms", found_platforms.join(", ")),
    );
    Some(summary)
}
