//! Webcam, fan-subscription, and adult-video platform identity discovery.
//!
//! Fans out parallel HTTP probes across ~40 platforms that are specific to live
//! streaming, cam performance, and subscription-content creation — categories
//! not covered by the general `username_search` module (which targets mainstream
//! social/dev/gaming/music platforms). The full platform set spans:
//!
//! - **cam** — Live webcam / performer streaming (Chaturbate, Stripchat,
//!   BongaCams, Cam4, CamSoda, MyFreeCams, Streamate, LiveJasmin, ImLive,
//!   Runetki/Russia, Cherry.tv/Eastern-Europe, …)
//! - **fans** — Fan-subscription / content-creator platforms (OnlyFans, Fansly,
//!   ManyVids, FanCentro, Fanvue, Loyalfans, AVN Stars, PocketStars,
//!   Mym/France-Francophone, Boosty/Russia-CIS, 4Based/Ukraine-Eastern-Europe,
//!   JustForFans/LGBTQ-intl, OhMyFans/Spanish-LATAM, Unlockd/UK,
//!   Cam.tv/Italy-Europe, …)
//! - **adult** — Adult-video profile pages (Pornhub model, xHamster, xVideos,
//!   SpankBang, Erome, RedTube, MyDirtyHobby/Germany, SuicideGirls/intl,
//!   Iwara/Japan-3D)
//!
//! For every hit, emits one `Url` entity tagged `cam-profile`/`fans-profile`/
//! `adult-profile` (matching the platform's category bucket) plus
//! `platform:<name>`. Also emits a summary `Username` entity with exposure
//! tags (`cam-identity-exposed`, `subscription-platform-found`) so the SPA's
//! Entities table shows the aggregated picture alongside the per-URL rows.
//!
//! No API keys required. Detection uses HEAD (status 200/404) where the
//! platform cleanly distinguishes present vs absent, and GET + body-not-contains
//! for JS-rendered platforms (e.g. OnlyFans) that return 200 for all URLs.

use async_trait::async_trait;
use futures::future::join_all;
use std::sync::Arc;
use std::time::Duration;

const MAX_CONCURRENT_PROBES: usize = 16;
const BODY_PROBE_CAP: usize = 256 * 1024;

/// Browser-shaped UA — same rationale as `username_search`: Cloudflare and
/// PerimeterX score non-browser TLS fingerprints as bots and 403 them.
const BROWSER_UA: &str = crate::util::curl::UA_MOBILE;
const BROWSER_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;\
    q=0.9,image/avif,image/webp,*/*;q=0.8";

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::urlencode;

const SRC: &str = "streaming_probe";

pub struct StreamingProbe;

mod sites;
#[cfg(test)]
use sites::CATEGORIES;
use sites::{Detect, Method, SITES};

#[async_trait]
impl Module for StreamingProbe {
    fn name(&self) -> &'static str {
        "streaming_probe"
    }

    fn priority(&self) -> u8 {
        // Just below username_search (111) so the general sweep runs first;
        // this specialised sweep runs in the same engine pass without competing.
        108
    }

    fn description(&self) -> &'static str {
        "Webcam, fan-subscription, and adult-video identity sweep across ~40 sites including international platforms: Russia (Runetki, Boosty), France (Mym), Germany (MyDirtyHobby), Eastern Europe (Cherry.tv, 4Based), LGBTQ+ (JustForFans), Spanish LATAM (OhMyFans), Japan (Iwara), and the English-language mainstream (Chaturbate, OnlyFans, Fansly, Pornhub, …)."
    }

    fn is_passive(&self) -> bool {
        false
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        // Social → T1593.001 (Search Social Media) + T1589.003 (Employee Names);
        // T1593.001 is the correct MITRE mapping for platform-presence enumeration.
        ModuleCategory::Social
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Url, EntityKind::Username];
        KINDS
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Social default is T1593.001 (Social Media) + T1589.003 (Employee Names),
        // but this module only searches streaming/cam/adult PLATFORMS for a handle
        // and emits a profile `Url` + the `Username` — it never resolves a real-name
        // `Person`, so T1589.003 is over-claimed (same correction as hacker_news /
        // reddit_user / username_search). Searching those platforms is T1593.001.
        &["T1593.001"]
    }

    fn max_timeout_ms(&self) -> u64 {
        // ceil(42 sites / 16 concurrent) × 4.5s/probe = 13.5s needed;
        // 30s envelope gives generous headroom for CloudFlare challenges,
        // JS-rendered responses (OnlyFans body reads take ~1–2s extra), and
        // the higher latency of probing non-CDN international platforms.
        30_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let username = target.value.trim();
        if username.is_empty() || username.len() > 64 {
            return Ok(ModuleResult::new());
        }

        let encoded = urlencode(username);
        let per_site_timeout = Duration::from_millis(4_500);

        let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PROBES));
        let probes = SITES.iter().map(|site| {
            let url = site.url.replace("{}", &encoded);
            let client = ctx.http.clone();
            let sem = Arc::clone(&sem);
            async move {
                let _permit = sem.acquire().await;
                let req = match site.method {
                    Method::Get => client.get(&url),
                    Method::Head => client.head(&url),
                };
                let req = req
                    .header("User-Agent", BROWSER_UA)
                    .header("Accept", BROWSER_ACCEPT)
                    .header("Accept-Language", "en-US,en;q=0.9");
                let resp = tokio::time::timeout(per_site_timeout, req.send()).await;
                let resp = match resp {
                    Ok(Ok(r)) => r,
                    _ => return ProbeResult::Error,
                };

                let status = resp.status().as_u16();
                let (confidence, verified) = detection_strength(&site.detect);
                match site.detect {
                    Detect::StatusEq(want) if status == want => ProbeResult::Found {
                        url,
                        confidence,
                        verified,
                    },
                    Detect::StatusEq(_) => ProbeResult::NotFound,
                    Detect::StatusAndNotBody(want, needle) => {
                        if status != want {
                            return ProbeResult::NotFound;
                        }
                        match crate::util::http::read_body_capped(resp, BODY_PROBE_CAP).await {
                            Some(body) if body.contains(needle) => ProbeResult::NotFound,
                            Some(_) => ProbeResult::Found {
                                url,
                                confidence,
                                verified,
                            },
                            None => ProbeResult::Error,
                        }
                    }
                }
            }
            .then_with_site(site.name, site.cat)
        });

        let results: Vec<(&'static str, &'static str, ProbeResult)> = join_all(probes).await;
        let results_len = results.len();

        let mut hits: Vec<Hit> = Vec::new();
        let mut inconclusive_probes = 0usize;
        let mut definitive_absent = 0usize;

        for (site_name, site_cat, outcome) in results {
            match outcome {
                ProbeResult::Found {
                    url,
                    confidence,
                    verified,
                } => hits.push(Hit {
                    site_name,
                    site_cat,
                    url,
                    confidence,
                    verified,
                }),
                ProbeResult::NotFound => definitive_absent += 1,
                ProbeResult::Error => inconclusive_probes += 1,
            }
        }

        if hits.is_empty() {
            if inconclusive(0, inconclusive_probes, results_len) {
                return Err(Error::module(
                    SRC,
                    format!(
                        "inconclusive: {inconclusive_probes}/{results_len} platform probes were \
                         blocked or unreachable — not a confirmed absence"
                    ),
                ));
            }
            return Ok(ModuleResult::new());
        }

        Ok(build_entities(
            username,
            &ctx.scan_id,
            &hits,
            &ProbeTally {
                definitive_absent,
                inconclusive_probes,
                sites_probed: SITES.len(),
            },
        ))
    }
}

enum ProbeResult {
    Found {
        url: String,
        confidence: f64,
        verified: bool,
    },
    NotFound,
    Error,
}

/// A confirmed profile hit, carrying the confidence its detection method earns.
struct Hit {
    site_name: &'static str,
    site_cat: &'static str,
    url: String,
    confidence: f64,
    verified: bool,
}

/// Non-hit probe tallies, surfaced on the summary so an operator can see how much
/// of the sweep was definitive vs blocked.
struct ProbeTally {
    definitive_absent: usize,
    inconclusive_probes: usize,
    sites_probed: usize,
}

/// Confidence + verified-flag a detection method earns, tiered by rigour — the
/// same discipline [`crate::modules::username_search`]'s `detection_strength`
/// applies. A body-verified hit (`StatusAndNotBody`: the profile page rendered and
/// did NOT carry the platform's "not found" marker) is a real presence signal
/// (0.92, verified). A bare status match (`StatusEq`: HEAD/GET returned 200) is
/// weaker — a soft-404, a CloudFlare interstitial, or a catch-all route all answer
/// 200 for any handle — so it rides as a status-only lead (0.74, unverified), not a
/// confirmed hit. Emitting a flat 0.92 on a status-only cam/adult match fabricates a
/// high-confidence, sensitive identity association from an unverified 200.
fn detection_strength(detect: &Detect) -> (f64, bool) {
    crate::util::probe_confidence::detection_strength(matches!(
        detect,
        Detect::StatusAndNotBody(..)
    ))
}

/// Build the per-hit `Url` entities and the summary `Username` entity from the
/// confirmed hits. Pure (no HTTP), so the confidence tiering and the
/// verified-gated exposure tags are unit-testable. Returns an empty result when
/// there are no hits.
fn build_entities(username: &str, scan_id: &str, hits: &[Hit], tally: &ProbeTally) -> ModuleResult {
    use std::collections::BTreeMap;
    let mut module_result = ModuleResult::new();
    if hits.is_empty() {
        return module_result;
    }

    let mut found_names: Vec<&str> = Vec::new();
    // category -> (total hits, body-verified hits)
    let mut cat_counts: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut verified_total = 0usize;
    let mut weak_total = 0usize;

    for h in hits {
        found_names.push(h.site_name);
        let entry = cat_counts.entry(h.site_cat).or_insert((0, 0));
        entry.0 += 1;
        if h.verified {
            entry.1 += 1;
            verified_total += 1;
        } else {
            weak_total += 1;
        }

        let profile_tag = match h.site_cat {
            "cam" => "cam-profile",
            "fans" => "fans-profile",
            "adult" => "adult-profile",
            _ => "streaming-profile",
        };
        let detection = if h.verified {
            "body-verified"
        } else {
            "status-only"
        };
        let mut e = Entity::new(EntityKind::Url, h.url.as_str(), h.confidence, scan_id);
        e.tag(profile_tag);
        e.tag(format!("platform:{}", h.site_name));
        e.tag(format!("cat:{}", h.site_cat));
        // Provenance so the correlator / SPA can discount a status-only lead.
        e.tag(if h.verified {
            "verified-detection"
        } else {
            "weak-detection"
        });
        e.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "@{username} has a {} profile on {} ({detection})",
                    h.site_cat, h.site_name
                ),
            )
            .with_attr("platform", h.site_name)
            .with_attr("category", h.site_cat)
            .with_attr("username", username)
            .with_attr("url", h.url.as_str())
            .with_attr("detection", detection),
        );
        module_result.push(e);
    }

    let mut summary = Entity::new(EntityKind::Username, username, 0.95, scan_id);
    summary.tag("streaming-identity");
    cat_counts
        .keys()
        .for_each(|cat| summary.tag(format!("cat:{cat}")));

    // Strong exposure claims require a BODY-VERIFIED hit in the category: a bare
    // status-only 200 can be a soft-404 / interstitial, so asserting "identity
    // exposed" from it would fabricate a sensitive claim about a real person.
    // Weak-only categories still surface their (weak-tagged, 0.74) URLs — the lead
    // is not lost, only its unearned high-confidence assertion.
    let cat_verified = |c: &str| cat_counts.get(c).map_or(0, |(_, v)| *v);
    if cat_verified("cam") > 0 {
        summary.tag("cam-identity-exposed");
    }
    if cat_verified("fans") > 0 {
        summary.tag("subscription-platform-found");
    }
    if cat_verified("adult") > 0 {
        summary.tag("adult-profile-found");
    }
    if verified_total >= 3 {
        summary.tag("high-streaming-exposure");
    }

    let cat_summary: Vec<String> = cat_counts
        .iter()
        .map(|(c, (n, v))| format!("{c}:{n}({v} verified)"))
        .collect();

    summary.add_evidence(
        Evidence::new(
            SRC,
            format!(
                "@{username} found on {n} streaming/cam platform(s): {list}",
                n = found_names.len(),
                list = found_names.join(", ")
            ),
        )
        .with_attr("platforms_count", found_names.len().to_string())
        .with_attr("platforms", found_names.join(", "))
        .with_attr("categories", cat_summary.join(", "))
        .with_attr("hits_verified", verified_total.to_string())
        .with_attr("hits_status_only", weak_total.to_string())
        .with_attr("sites_probed", tally.sites_probed.to_string())
        .with_attr("sites_not_found", tally.definitive_absent.to_string())
        .with_attr("sites_inconclusive", tally.inconclusive_probes.to_string()),
    );
    module_result.push(summary);
    module_result
}

/// True when a zero-hit run is inconclusive (most probes were blocked) rather
/// than a confirmed absence. Mirrors `username_search::inconclusive` — same M6
/// disambiguation policy, independently testable.
fn inconclusive(found: usize, errored: usize, total: usize) -> bool {
    found == 0 && total > 0 && errored * 2 >= total
}

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
    include!("tests.rs");
}
