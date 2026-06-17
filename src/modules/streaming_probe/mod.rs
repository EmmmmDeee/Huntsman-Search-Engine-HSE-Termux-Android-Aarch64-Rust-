//! Webcam, fan-subscription, and adult-video platform identity discovery.
//!
//! Fans out parallel HTTP probes across ~30 platforms that are specific to live
//! streaming, cam performance, and subscription-content creation — categories
//! not covered by the general `username_search` module (which targets mainstream
//! social/dev/gaming/music platforms). The full platform set spans:
//!
//! - **cam** — Live webcam / performer streaming (Chaturbate, Stripchat,
//!   BongaCams, Cam4, CamSoda, MyFreeCams, Streamate, LiveJasmin, ImLive, …)
//! - **fans** — Fan-subscription / content-creator platforms (OnlyFans, Fansly,
//!   ManyVids, FanCentro, Fanvue, Loyalfans, AVN Stars, PocketStars, …)
//! - **adult** — Adult-video profile pages (Pornhub model, xHamster, xVideos,
//!   SpankBang, Erome, RedTube)
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
        "Webcam, fan-subscription, and adult-video platform identity discovery \
         across ~30 sites (Chaturbate, OnlyFans, Fansly, Pornhub model, xHamster, …)."
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

    fn max_timeout_ms(&self) -> u64 {
        // ceil(30 sites / 16 concurrent) × 4.5s/probe = 9s needed;
        // 30s envelope gives generous headroom for CloudFlare challenges and
        // JS-rendered responses (OnlyFans body reads take ~1–2s extra).
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
                match site.detect {
                    Detect::StatusEq(want) if status == want => ProbeResult::Found(url),
                    Detect::StatusEq(_) => ProbeResult::NotFound,
                    Detect::StatusAndNotBody(want, needle) => {
                        if status != want {
                            return ProbeResult::NotFound;
                        }
                        match crate::util::http::read_body_capped(resp, BODY_PROBE_CAP).await {
                            Some(body) if body.contains(needle) => ProbeResult::NotFound,
                            Some(_) => ProbeResult::Found(url),
                            None => ProbeResult::Error,
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
        let mut inconclusive_probes = 0usize;
        let mut definitive_absent = 0usize;

        for (site_name, site_cat, outcome) in &results {
            match outcome {
                ProbeResult::Found(url) => {
                    found_names.push(site_name);
                    *category_counts.entry(site_cat).or_insert(0) += 1;

                    let profile_tag = match *site_cat {
                        "cam" => "cam-profile",
                        "fans" => "fans-profile",
                        "adult" => "adult-profile",
                        _ => "streaming-profile",
                    };

                    let mut e = Entity::new(EntityKind::Url, url.as_str(), 0.92, &ctx.scan_id);
                    e.tag(profile_tag);
                    e.tag(format!("platform:{site_name}"));
                    e.tag(format!("cat:{site_cat}"));
                    e.add_evidence(
                        Evidence::new(
                            SRC,
                            format!("@{username} has a {site_cat} profile on {site_name}"),
                        )
                        .with_attr("platform", *site_name)
                        .with_attr("category", *site_cat)
                        .with_attr("username", username)
                        .with_attr("url", url),
                    );
                    module_result.push(e);
                }
                ProbeResult::NotFound => definitive_absent += 1,
                ProbeResult::Error => inconclusive_probes += 1,
            }
        }

        if found_names.is_empty() {
            if inconclusive(found_names.len(), inconclusive_probes, results.len()) {
                return Err(Error::module(
                    SRC,
                    format!(
                        "inconclusive: {inconclusive_probes}/{} platform probes were blocked or \
                         unreachable — not a confirmed absence",
                        results.len()
                    ),
                ));
            }
            return Ok(module_result);
        }

        // Summary entity: one `Username` row in the SPA with exposure tags.
        let mut summary = Entity::new(EntityKind::Username, username, 0.95, &ctx.scan_id);
        summary.tag("streaming-identity");

        category_counts
            .keys()
            .for_each(|cat| summary.tag(format!("cat:{cat}")));

        let cam_count = category_counts.get("cam").copied().unwrap_or(0);
        let fans_count = category_counts.get("fans").copied().unwrap_or(0);
        let adult_count = category_counts.get("adult").copied().unwrap_or(0);

        if cam_count > 0 {
            summary.tag("cam-identity-exposed");
        }
        if fans_count > 0 {
            summary.tag("subscription-platform-found");
        }
        if adult_count > 0 {
            summary.tag("adult-profile-found");
        }
        if cam_count + fans_count + adult_count >= 3 {
            summary.tag("high-streaming-exposure");
        }

        let cat_summary: Vec<String> = category_counts
            .iter()
            .map(|(c, n)| format!("{c}:{n}"))
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
            .with_attr("cam_count", cam_count.to_string())
            .with_attr("fans_count", fans_count.to_string())
            .with_attr("adult_count", adult_count.to_string())
            .with_attr("sites_probed", SITES.len().to_string())
            .with_attr("sites_not_found", definitive_absent.to_string())
            .with_attr("sites_inconclusive", inconclusive_probes.to_string()),
        );
        module_result.push(summary);

        Ok(module_result)
    }
}

enum ProbeResult {
    Found(String),
    NotFound,
    Error,
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
