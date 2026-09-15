//! Direct social profile probing — free, zero API keys.
//!
//! For a Username target, sends HEAD/GET requests to known profile URL
//! patterns on 20+ platforms. A matching status code is a hit; for the
//! handful of platforms known to return that status for any handle
//! (soft-404/SPA-shell), a `negative_patterns` body check must also pass —
//! see `Platform::negative_patterns`. Each confirmed profile becomes a Url
//! entity with the platform tagged, plus `verified-detection` (body-marker
//! confirmed over the WHOLE page — a page curl cut short at the download cap
//! is inconclusive, never a hit; see `classify_probe`) or `weak-detection`
//! (status code alone — the correlator
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
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::curl::StatusProbe;
use crate::util::probe::{
    ProbeResult, classify_non_matching_status, control_handle, control_presences,
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
/// with a `negative_patterns` check just had its WHOLE body inspected for a
/// "doesn't exist" marker and passed — a real confirmation (0.92, verified);
/// a body curl cut short never gets here (see [`classify_probe`]).
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

/// Decide what one platform probe proved, from curl's answer alone. Pure, so
/// the whole hit / absence / inconclusive policy is testable without the
/// network.
///
/// * A status outside the platform's `exists_codes` is a definitive absence
///   when it is one a platform answers for a missing handle (404/410, or a 2xx
///   the table did not list) and inconclusive when it is a refusal — a WAF
///   challenge, a throttle, an outage, or curl's `0` for "no answer at all"
///   ([`classify_non_matching_status`], the policy the reqwest enumerators use).
/// * A presence status on a status-only platform is a weak hit.
/// * A presence status on a negative-marker platform is a definitive absence
///   when the body carries a marker (a partial body suffices — the marker was
///   seen), a verified hit when the **whole** body was read and carries none,
///   and **inconclusive** when curl refused or cut the body
///   ([`StatusProbe::truncated`]): the marker check is the only thing that
///   separates a profile from this platform's 200-for-everything not-found
///   page, and it ran over a document that was never delivered. Before this
///   an empty body simply "contained no marker", and the probe minted a 0.92
///   `verified-detection` profile for any handle on any of these platforms
///   whose not-found page exceeds the download cap
///   (`docs/PROVIDER_SWEEP_BACKLOG.md` #38).
pub(super) fn classify_probe(platform: &Platform, url: &str, answer: &StatusProbe) -> ProbeResult {
    if !platform.exists_codes.contains(&answer.status) {
        return classify_non_matching_status(answer.status);
    }
    let (confidence, verified) = detection_strength(platform);
    if platform.negative_patterns.is_empty() {
        return ProbeResult::Found {
            url: url.to_string(),
            confidence,
            verified,
            controlled: false,
        };
    }
    if platform
        .negative_patterns
        .iter()
        .any(|p| answer.body.contains(p))
    {
        return ProbeResult::NotFound;
    }
    if answer.truncated {
        return ProbeResult::Error;
    }
    ProbeResult::Found {
        url: url.to_string(),
        confidence,
        verified,
        controlled: false,
    }
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
        // The public Atom feed, NOT `about.json`. Verified live in July 2026:
        // the JSON endpoint answers 403 to every non-OAuth client regardless of
        // User-Agent, which this probe read as "account does not exist" — so
        // reddit reported a silent false negative on every scan. `.rss` answers
        // 200 for a real account and 404 for one that does not exist, which is
        // the clean existence oracle `exists_codes` needs.
        url_pattern: "https://www.reddit.com/user/{}/.rss",
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
        // Probes 20+ platforms for username presence (T1593.001) and, for
        // FullName targets, probes people-search directories (PeeKYou,
        // Facebook public directory) whose confirmed hits are summarized into
        // a genuine Person entity via target.to_entity() (T1589.003) —
        // produces() explicitly lists Person, unlike structural siblings
        // username_search/streaming_probe (Username-only, no Person) which
        // override the same default down to just T1593.001 for exactly that
        // reason. Because social_probe actually does resolve real-name
        // identity via FullName probing, the category default fits it
        // tightly and needs no override.
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
        // The first wave is sequential and paced (37 platforms × up to 4 s of
        // curl + 250 ms), the control wave concurrent (one more curl per
        // presence); the 40 s envelope was reached on this sandbox at 37 s.
        60_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let value = target.value.trim();
        if value.is_empty() {
            return Ok(ModuleResult::new());
        }

        let platforms = match target.kind {
            TargetKind::Username => USERNAME_PLATFORMS,
            TargetKind::FullName => NAME_PLATFORMS,
            _ => return Ok(ModuleResult::new()),
        };

        let slug = match target.kind {
            TargetKind::FullName => value.to_lowercase().replace(' ', "-"),
            _ => value.to_string(),
        };

        // First wave: every platform, for the target, paced.
        let mut first: Vec<((&'static Platform, u16), ProbeResult)> = Vec::new();
        let mut checked_count = 0u32;
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
            let answer = crate::util::curl::fetch_with_status(
                &url,
                4_000,
                !platform.negative_patterns.is_empty(),
            )
            .await;
            first.push((
                (platform, answer.status),
                classify_probe(platform, &url, &answer),
            ));
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }

        // Second wave: each presence judged against the control handle on the
        // same platform (`util::probe::control_presences`) — a platform that is
        // "present" for a handle nobody holds cannot tell a held handle from an
        // unheld one, and on these platforms a fabricated presence is a
        // sensitive claim (four adult/cam platforms answered so on 2026-09-15).
        let judged = control_presences(first, |(platform, _): (&'static Platform, u16)| {
            let url = platform
                .url_pattern
                .replace("{}", &crate::util::http::urlencode(control_handle()));
            let capture = !platform.negative_patterns.is_empty();
            let probe_url = url.clone();
            (url, async move {
                let answer = crate::util::curl::fetch_with_status(&probe_url, 4_000, capture).await;
                classify_probe(platform, &probe_url, &answer)
            })
        })
        .await;

        let (mut result, tally) = emit_judged(&judged, &ctx.scan_id);

        // M6: a zero-hit run where at least half the probes returned no definitive
        // answer (curl code 0 — blocked / unreachable / no egress — or a platform
        // that cannot tell) is *inconclusive*, not a confirmed absence. Surface it
        // as a module error so a network-blocked sweep is never read as "this
        // handle is on no social platform" — the same disambiguation
        // `username_search` and `streaming_probe` make. A cancelled run is
        // exempt: the operator stopped it, so the module asserts nothing about
        // what it didn't probe.
        if !ctx.cancel.is_cancelled()
            && let Some(msg) = inconclusive_sweep(
                tally.found,
                tally.inconclusive,
                tally.indiscriminate_platforms.len() as u32,
                checked_count,
            )
        {
            return Err(Error::module(SRC, msg));
        }

        // Add a summary echo of the target ONLY when at least one profile was
        // actually confirmed (see `should_echo_target`). The negative result is
        // still recorded in the dispatch log; it just must not vouch for the seed.
        if let Some(summary) = build_target_summary(
            target,
            tally.found,
            tally.verified,
            checked_count,
            &tally.found_platforms,
            &tally.indiscriminate_platforms,
            tally.uncontrolled,
            &ctx.scan_id,
        ) {
            result.push(summary);
        }

        Ok(result)
    }
}

/// What a sweep counted, for the summary and the M6 verdict.
#[derive(Default)]
pub(super) struct SweepTally {
    pub(super) found: u32,
    pub(super) verified: u32,
    /// Probes that returned no definitive answer (curl code 0, a refusal).
    pub(super) inconclusive: u32,
    /// Presences whose control could not be read: they stand as they were.
    pub(super) uncontrolled: u32,
    pub(super) found_platforms: Vec<&'static str>,
    /// Platforms that answered "present" for the control handle too — no
    /// answer about the handle, never a profile.
    pub(super) indiscriminate_platforms: Vec<&'static str>,
}

/// Turn the judged probes into entities. Pure (no I/O), so the reading of the
/// control judgement — an indiscriminate platform is never a profile, a
/// presence says whether its control was absent — is unit-tested directly.
pub(super) fn emit_judged(
    judged: &[((&'static Platform, u16), ProbeResult)],
    scan_id: &str,
) -> (ModuleResult, SweepTally) {
    let mut result = ModuleResult::new();
    let mut tally = SweepTally::default();
    for ((platform, status), outcome) in judged {
        let status = *status;
        match outcome {
            ProbeResult::Error => tally.inconclusive += 1,
            ProbeResult::NotFound => {}
            ProbeResult::Indiscriminate { .. } => {
                tally.indiscriminate_platforms.push(platform.name);
            }
            ProbeResult::Found {
                url,
                confidence,
                verified,
                controlled,
            } => {
                let (url, confidence, verified, controlled) =
                    (url.as_str(), *confidence, *verified, *controlled);
                let mut found_count = 0u32;
                let mut verified_count = 0u32;
                let mut found_platforms: Vec<&'static str> = Vec::new();
                found_count += 1;
                found_platforms.push(platform.name);
                if verified {
                    verified_count += 1;
                }

                let mut entity = Entity::new(EntityKind::Url, url, confidence, scan_id);
                entity.tag("social-profile");
                entity.tag(format!("platform:{}", platform.name));
                entity.tag(if verified {
                    "verified-detection"
                } else {
                    "weak-detection"
                });
                entity.add_evidence(
                    Evidence::new(
                        crate::modules::corpus_source(url, SRC),
                        format!("Profile found on {}", platform.name),
                    )
                    .with_attr("platform", platform.name)
                    .with_attr("http_status", status.to_string())
                    .with_attr("profile_url", url)
                    .with_attr(
                        "detection",
                        if verified {
                            "body-marker"
                        } else {
                            "status-only"
                        },
                    )
                    .with_attr("control", if controlled { "absent" } else { "unavailable" }),
                );
                if !controlled {
                    tally.uncontrolled += 1;
                }
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
                if let Some(host) = url::Url::parse(url)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_lowercase))
                    && host.contains('.')
                    && !crate::core::scan::is_noncentral_domain(&host)
                {
                    let mut dom = Entity::new(EntityKind::Domain, &host, confidence::LOW, scan_id);
                    dom.tag("social-platform");
                    dom.add_evidence(
                        Evidence::new(
                            crate::modules::corpus_source(url, SRC),
                            format!("Platform domain from {} profile", platform.name),
                        )
                        .with_attr("platform", platform.name),
                    );
                    result.push(dom);
                }
                tally.found += found_count;
                tally.verified += verified_count;
                tally.found_platforms.extend(found_platforms);
            }
        }
    }
    tally.found_platforms.sort_unstable();
    (result, tally)
}

/// Post-sweep M6 verdict: a zero-hit run is *inconclusive* — not a confirmed
/// absence — when at least half the attempted probes returned no definitive
/// answer (`fetch_with_status` code `0`: curl could not connect / was blocked /
/// had no egress). Returns the error message to surface, or `None` when the run
/// is a genuine result (any hit, or a mostly-definitive set of not-founds).
///
/// Pure, so the policy is testable without the network. Delegates the "mostly
/// blocked" threshold to [`crate::util::probe::inconclusive`] — the same
/// predicate the `username_search` and `streaming_probe` enumerators use — so
/// all three existence-probe modules agree on when a blocked sweep must be
/// reported as inconclusive rather than as a confirmed absence.
fn inconclusive_sweep(
    found: u32,
    inconclusive_probes: u32,
    indiscriminate: u32,
    checked: u32,
) -> Option<String> {
    crate::util::probe::inconclusive_after_control(
        found as usize,
        inconclusive_probes as usize,
        indiscriminate as usize,
        checked as usize,
    )
    .then(|| {
        format!(
            "inconclusive: {inconclusive_probes} of {} platform probes that can tell returned no \
             definitive answer (blocked / unreachable / no egress), {indiscriminate} platforms \
             answer \"present\" for any handle — not a confirmed absence",
            checked - indiscriminate
        )
    })
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
#[allow(clippy::too_many_arguments)]
pub(super) fn build_target_summary(
    target: &Target,
    found_count: u32,
    verified_count: u32,
    checked_count: u32,
    found_platforms: &[&str],
    indiscriminate_platforms: &[&str],
    uncontrolled_count: u32,
    scan_id: &str,
) -> Option<Entity> {
    if !should_echo_target(found_count) {
        return None;
    }
    // VERY_HIGH_PLUSPLUS matches the identical "independently confirmed across
    // platforms" claim its structural siblings' summaries use
    // (username_search, streaming_probe) — a bare 0.82 scored the same claim
    // a full tier lower for no documented reason.
    let mut summary = target.to_entity(confidence::VERY_HIGH_PLUSPLUS, scan_id);
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
        .with_attr("platforms", found_platforms.join(", "))
        // AU-035/AU-077's `is_verified_discovery` reads `hits_verified` on THIS
        // aggregate record — the per-platform verified/weak split lives on the
        // separate Url entities those rules never scan. An absent attribute
        // reads as vacuously verified, so an all-status-only sweep could still
        // fabricate a "prediction confirmed" bridge. Mirrors the shape
        // `username_search`/`streaming_probe` already stamp.
        .with_attr("hits_verified", verified_count.to_string())
        .with_attr(
            "hits_status_only",
            (found_count - verified_count).to_string(),
        )
        // The negative control (`util::probe::control_handle`): platforms that
        // were "present" for a handle nobody holds too, and presences whose
        // control could not be read.
        .with_attr(
            "sites_indiscriminate",
            indiscriminate_platforms.len().to_string(),
        )
        .with_attr(
            "indiscriminate_platforms",
            indiscriminate_platforms.join(", "),
        )
        .with_attr("hits_uncontrolled", uncontrolled_count.to_string()),
    );
    Some(summary)
}
