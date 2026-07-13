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
use std::sync::Arc;
use std::time::Duration;

/// Concurrent probe ceiling. Each batch is bounded by `per_site_timeout`
/// so the wall-time is `ceil(SITES.len()/MAX) × per_site_timeout`. At 32
/// concurrent + 4.5s/probe + 334 sites that's ~47s — fits inside the
/// 60s `max_timeout_ms` budget below with comfortable slack.
const MAX_CONCURRENT_PROBES: usize = 32;
/// Cap each profile-probe body read so a hostile site can't OOM the 32-way
/// fan-out; 256 KiB is far more than any needle check needs.
const BODY_PROBE_CAP: usize = 256 * 1024;

/// Browser-shaped User-Agent for the per-site probes.
///
/// Until v1.2 the module used reqwest's default client UA
/// (`huntsman-search-engine/x.y.z (+url)`), which Cloudflare /
/// PerimeterX / Akamai-fronted social platforms routinely 403'd as a
/// bot signal — meaning ~30% of the SITES table was returning Error
/// even when the username existed. Sending a real Chrome-on-Android
/// UA (chosen to match the `util::curl_client` fingerprint used by
/// the paid OSINT modules) restores hit rate.
const BROWSER_UA: &str = crate::util::curl::UA_MOBILE;

/// Accept header — wide image/html/anything spec that matches what a
/// browser sends. Some WAFs (notably Akamai Bot Manager) score
/// requests with `accept: */*` as suspicious.
const BROWSER_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;\
    q=0.9,image/avif,image/webp,*/*;q=0.8";

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::urlencode;

const SRC: &str = "username_search";

pub struct UsernameSearch;

/// One site to probe. Kept inline (rather than loaded from a JSON file)
/// so the binary stays self-contained and the list is reviewable in PR.
mod sites;
#[cfg(test)]
use sites::CATEGORIES;
use sites::{Detect, Method, SITES};

#[async_trait]
impl Module for UsernameSearch {
    fn name(&self) -> &'static str {
        "username_search"
    }

    fn priority(&self) -> u8 {
        // Higher than email_to_username (95) so it dispatches first when
        // a Username target is the seed — gives the user visible progress
        // immediately rather than waiting for derivation modules.
        111
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

    fn max_timeout_ms(&self) -> u64 {
        // The previous default of 3_000 (inherited from
        // `MODULE_TIMEOUT_MS`) was killing the module after ~2 probe
        // batches of 16, surfacing only ~32 of 334 sites' results.
        // 60s envelope gives 47s of probing wall-time + 13s of slack
        // for slow Cloudflare / Akamai / PerimeterX challenges that
        // social-analyzer's published research flags as the dominant
        // failure mode for username-enumeration tools.
        60_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Url, EntityKind::Username];
        KINDS
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Social default is T1593.001 (Social Media) + T1589.003 (Employee
        // Names), but this module only ENUMERATES handle presence across 300+
        // sites: it emits a profile `Url` and the confirmed `Username` (see
        // `produces`) and never resolves a real-name `Person`, so T1589.003 is
        // over-claimed — the same correction already applied to hacker_news /
        // lobsters / nostr / reddit_user. Unlike those it has no bio-email path
        // (no `Email` in `produces`), so T1593.001 (searching open websites for
        // the account) is the single precise technique.
        &["T1593.001"]
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let username = target.value.trim();
        if username.is_empty() || username.len() > 64 {
            return Ok(ModuleResult::new());
        }

        let encoded = urlencode(username);
        // Per-site timeout raised from 2.5s → 4.5s to absorb the
        // Cloudflare / Akamai / PerimeterX "checking your browser"
        // challenges that flag the dominant failure mode for username-
        // enumeration tools (per social-analyzer's published rate-
        // limit research). The outer module envelope (60s) gives ~13s
        // of slack on top of the worst-case batch wall-time.
        let per_site_timeout = Duration::from_millis(4_500);

        let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PROBES));
        let probes = SITES.iter().map(|site| {
            let url = site.url.replace("{}", &encoded);
            let client = ctx.http.clone();
            let sem = Arc::clone(&sem);
            // Confidence + provenance the hit will carry, decided by how
            // rigorously THIS site's rule corroborates existence (see
            // `detection_strength`). Captured before the await so the async
            // block doesn't need to borrow `site` past its lifetime.
            let (hit_conf, hit_verified) = detection_strength(&site.detect);
            async move {
                let _permit = sem.acquire().await;
                let req = match site.method {
                    Method::Get => client.get(&url),
                    Method::Head => client.head(&url),
                };
                // Browser-shaped UA + Accept headers — the tool-shaped
                // default UA was being 403'd by Cloudflare-fronted
                // platforms (~30% of SITES), masking real hits as
                // Errors. See BROWSER_UA constant for rationale.
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
                let found = |url: String| ProbeResult::Found {
                    url,
                    confidence: hit_conf,
                    verified: hit_verified,
                };
                match site.detect {
                    Detect::StatusEq(want) if status == want => found(url),
                    Detect::StatusEq(_) => ProbeResult::NotFound,
                    Detect::StatusAndBody(want, needle) => {
                        if status != want {
                            return ProbeResult::NotFound;
                        }
                        let body =
                            match crate::util::http::read_body_capped(resp, BODY_PROBE_CAP).await {
                                Some(t) => t,
                                None => return ProbeResult::Error,
                            };
                        scan_text_for_keys(&body);
                        if body.contains(needle) {
                            found(url)
                        } else {
                            ProbeResult::NotFound
                        }
                    }
                    Detect::StatusAndNotBody(want, needle) => {
                        if status != want {
                            return ProbeResult::NotFound;
                        }
                        let body =
                            match crate::util::http::read_body_capped(resp, BODY_PROBE_CAP).await {
                                Some(t) => t,
                                None => return ProbeResult::Error,
                            };
                        scan_text_for_keys(&body);
                        if body.contains(needle) {
                            ProbeResult::NotFound
                        } else {
                            found(url)
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
        // Track inconclusive (blocked/unreachable) vs definitive not-found so a
        // mostly-blocked run isn't reported as a confirmed absence (error-tree
        // finding M6 — `found=0` must not conflate "absent" with "couldn't tell").
        let mut inconclusive_probes = 0usize;
        let mut definitive_absent = 0usize;
        // Provenance split: hits corroborated by a body marker vs. those resting
        // on a bare HTTP-200 (which an SPA shell / soft-404 can fake). Surfaced in
        // the summary so the operator can weigh a "47 platforms" result honestly.
        let mut verified_hits = 0usize;
        let mut weak_hits = 0usize;
        for (site_name, site_cat, outcome) in &results {
            match outcome {
                ProbeResult::Found {
                    url,
                    confidence,
                    verified,
                } => {
                    found_names.push(site_name);
                    *category_counts.entry(site_cat).or_insert(0) += 1;
                    let mut e =
                        Entity::new(EntityKind::Url, url.as_str(), *confidence, &ctx.scan_id);
                    e.tag("social-profile");
                    e.tag(format!("platform:{site_name}"));
                    e.tag(format!("cat:{site_cat}"));
                    // Provenance tag lets the correlator / SPA discount status-only
                    // hits without re-deriving how the match was made.
                    if *verified {
                        verified_hits += 1;
                        e.tag("verified-detection");
                    } else {
                        weak_hits += 1;
                        e.tag("weak-detection");
                    }
                    e.add_evidence(
                        Evidence::new(SRC, format!("@{username} has a profile on {site_name}"))
                            .with_attr("platform", *site_name)
                            .with_attr("category", *site_cat)
                            .with_attr("username", username)
                            .with_attr("url", url)
                            .with_attr(
                                "detection",
                                if *verified {
                                    "body-marker"
                                } else {
                                    "status-only"
                                },
                            ),
                    );
                    module_result.push(e);
                }
                ProbeResult::NotFound => definitive_absent += 1,
                ProbeResult::Error => inconclusive_probes += 1,
            }
        }

        // Zero hits: distinguish a genuine "not on any site" from "couldn't tell"
        // (WAF / rate-limit / no egress blocked the probes). If the probes were
        // mostly inconclusive, surface an error instead of a silent zero so the
        // operator never reads a blocked run as a confirmed absence.
        if found_names.is_empty() {
            if inconclusive(found_names.len(), inconclusive_probes, results.len()) {
                return Err(Error::module(
                    SRC,
                    format!(
                        "inconclusive: {inconclusive_probes}/{} site probes were blocked or \
                         unreachable (WAF / rate-limit / no egress) — not a confirmed absence",
                        results.len()
                    ),
                ));
            }
            return Ok(module_result);
        }

        // Re-emit the seed username with a corroboration-style summary so
        // the SPA's Entities table shows a single "N platforms" row for
        // the username itself, alongside the per-platform Url entities.
        if !found_names.is_empty() {
            let mut summary = Entity::new(EntityKind::Username, username, 0.95, &ctx.scan_id);
            summary.tag("multi-platform");

            // Tag each category that had at least one hit.
            category_counts
                .keys()
                .for_each(|cat| summary.tag(format!("cat:{cat}")));

            // People-centric intelligence tags: flag high-value
            // categories that reveal personal lifestyle/identity
            // exposure. These are MORE valuable for OSINT than dev
            // platform presence (which is professional, not personal).
            let social_count = category_counts.get("social").copied().unwrap_or(0);
            let dating_count = category_counts.get("dating").copied().unwrap_or(0);
            let messaging_count = category_counts.get("messaging").copied().unwrap_or(0);
            let gaming_count = category_counts.get("gaming").copied().unwrap_or(0);

            if social_count >= 3 {
                summary.tag("strong-social-presence");
            }
            if dating_count > 0 {
                summary.tag("dating-profile-exposed");
            }
            if messaging_count > 0 {
                summary.tag("messaging-identity");
            }
            if social_count + dating_count + messaging_count + gaming_count >= 5 {
                summary.tag("high-personal-exposure");
            }
            // At least three body-marker-confirmed hits is a genuinely corroborated
            // identity, not a pile of status-only guesses — let the SPA highlight it.
            if verified_hits >= 3 {
                summary.tag("strong-corroboration");
            }

            let cat_summary: Vec<String> = category_counts
                .iter()
                .map(|(c, n)| format!("{c}:{n}"))
                .collect();
            summary.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "@{username} found on {n} platform(s): {list}",
                        n = found_names.len(),
                        list = found_names.join(", ")
                    ),
                )
                .with_attr("platforms_count", found_names.len().to_string())
                .with_attr("platforms", found_names.join(", "))
                .with_attr("categories", cat_summary.join(", "))
                .with_attr("social_count", social_count.to_string())
                .with_attr("dating_count", dating_count.to_string())
                .with_attr("messaging_count", messaging_count.to_string())
                .with_attr("sites_probed", SITES.len().to_string())
                .with_attr("sites_not_found", definitive_absent.to_string())
                .with_attr("sites_inconclusive", inconclusive_probes.to_string())
                .with_attr("hits_verified", verified_hits.to_string())
                .with_attr("hits_status_only", weak_hits.to_string()),
            );
            module_result.push(summary);
        }
        Ok(module_result)
    }
}

enum ProbeResult {
    Found {
        url: String,
        /// Confidence to stamp on the emitted `Url`, tiered by detection rigor.
        confidence: f64,
        /// True when corroborated by a body marker (vs. a bare status code).
        verified: bool,
    },
    NotFound,
    Error,
}

/// Confidence and provenance for a positive hit, tiered by how rigorously a
/// site's detection rule actually corroborates that the account exists.
///
/// Status-only detection ([`Detect::StatusEq`]) is the dominant false-positive
/// source in Sherlock-class enumerators: single-page-app shells, soft-404s and
/// login walls all answer HTTP 200 for a username that was never registered, so
/// a bare 200 is *plausible but unverified*. Body-marker rules
/// ([`Detect::StatusAndBody`] / [`Detect::StatusAndNotBody`]) inspect the page
/// for an actual existence signal, so they earn full confidence. Stamping both
/// at a flat 0.92 (as the module did before) overstated every status-only hit
/// and let SPA false-positives masquerade as confirmed profiles.
///
/// The weak tier (0.74) stays above the engine's 0.50 `min_expand_confidence`
/// floor — a status-200 hit is still worth pivoting on — but ranks visibly below
/// a body-confirmed 0.92 so the correlator and SPA can weight it accordingly.
fn detection_strength(detect: &Detect) -> (f64, bool) {
    match detect {
        Detect::StatusAndBody(..) | Detect::StatusAndNotBody(..) => (0.92, true),
        Detect::StatusEq(_) => (0.74, false),
    }
}

/// True when a zero-hit run is *inconclusive* rather than a confirmed absence:
/// nothing was found AND at least half the probes were blocked/unreachable, so
/// most sites never gave a definitive answer. Pure (unit-tested) so the M6
/// disambiguation policy is verifiable without the network.
fn inconclusive(found: usize, errored: usize, total: usize) -> bool {
    found == 0 && total > 0 && errored * 2 >= total
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

fn scan_text_for_keys(body: &str) {
    use crate::util::key_harvest::identify_api_key;
    let pool = crate::util::key_pool::global_pool();
    for word in body.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '`') {
        let t = word.trim();
        if t.len() >= 16
            && t.len() <= 200
            && let Some((service, key_val)) = identify_api_key(t)
        {
            let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
            entry.status = crate::util::key_pool::KeyStatus::Untested;
            entry.notes = Some("Profile page body".into());
            pool.add(service, entry);
        }
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
