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
/// concurrent + 4.5s/probe + 354 sites that's ~54s — fits inside the
/// 60s `max_timeout_ms` budget below, with slack for slow probes.
const MAX_CONCURRENT_PROBES: usize = 32;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{RequestBuilderExt, urlencode};
// Shared existence-probe plumbing — the browser headers, body cap, outcome
// enum, per-site adapter, and the M6 zero-hit disambiguation are single-sourced
// in `util::probe` (see `streaming_probe`, which shares the same primitives).
use crate::util::probe::{
    BODY_PROBE_CAP, BROWSER_ACCEPT, BROWSER_UA, PageVerdict, ProbeResult,
    classify_non_matching_status, classify_page, control_handle, control_presences,
    inconclusive_after_control,
};

const SRC: &str = "username_search";

pub struct UsernameSearch;

/// One site to probe. Kept inline (rather than loaded from a JSON file)
/// so the binary stays self-contained and the list is reviewable in PR.
mod sites;
#[cfg(test)]
use sites::CATEGORIES;
use sites::{Detect, Method, SITES, Site};

#[async_trait]
impl Module for UsernameSearch {
    fn name(&self) -> &'static str {
        "username_search"
    }

    fn priority(&self) -> u8 {
        // Higher than email_parse (96) so it dispatches first when a
        // Username target is the seed — gives the user visible progress
        // immediately rather than waiting for derivation modules.
        111
    }

    fn description(&self) -> &'static str {
        "Maigret-style username enumeration — sweeps a handle across 150+ sites (social, dev, gaming, music, video, dating, …) with category tagging"
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
        // batches of 16, surfacing only ~32 of 354 sites' results.
        // 60s envelope gives ~54s of probing wall-time + ~6s of slack
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

        let results = sweep(&ctx.http, SITES, username).await;
        aggregate_results(username, &results, &ctx.scan_id)
    }
}

/// The per-site budget of a control probe: the site already answered once
/// within the sweep's own budget, so its second answer is expected sooner.
const CONTROL_TIMEOUT: Duration = Duration::from_millis(3_000);

/// One site, one handle: the site's answer for `url`, bounded by
/// `per_site_timeout` under the shared semaphore.
async fn probe_site(
    client: reqwest::Client,
    sem: Arc<tokio::sync::Semaphore>,
    site: &'static Site,
    url: String,
    per_site_timeout: Duration,
) -> ProbeResult {
    let (hit_conf, hit_verified) = detection_strength(&site.detect);
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
    // The ENTIRE probe — request dispatch AND the body read — shares
    // ONE `per_site_timeout` budget. Previously only `send()` was
    // bounded here; the `read_body_capped` branches then fell back to
    // the shared client's 30s read_timeout while still holding a
    // semaphore permit, so a few slow-body sites could each pin one of
    // the MAX_CONCURRENT_PROBES slots for ~34.5s and shrink coverage on
    // exactly the flaky mobile links this module targets.
    let probe = async {
        let resp = match req.send_tagged(SRC).await {
            Ok(r) => r,
            Err(_) => return ProbeResult::Error,
        };

        let status = resp.status().as_u16();
        let found = |url: String| ProbeResult::Found {
            url,
            confidence: hit_conf,
            verified: hit_verified,
            controlled: false,
        };
        match site.detect {
            Detect::StatusEq(want) if status == want => found(url),
            // A status that is not this site's presence code is not
            // automatically an absence: a 403 WAF challenge, a 429
            // throttle or a 5xx outage establishes nothing. See
            // `classify_non_matching_status` — the shared policy that
            // keeps a blocked sweep out of `definitive_absent`.
            Detect::StatusEq(_) => classify_non_matching_status(status),
            Detect::StatusAndBody(want, needle) => {
                if status != want {
                    return classify_non_matching_status(status);
                }
                let body = match crate::util::http::read_body_capped(resp, BODY_PROBE_CAP).await {
                    Some(t) => t,
                    None => return ProbeResult::Error,
                };
                scan_text_for_keys(&body);
                // A wall served with the presence status is
                // neither presence nor absence (`classify_page`).
                match classify_page(&body, needle, true) {
                    PageVerdict::Present => found(url),
                    PageVerdict::Absent => ProbeResult::NotFound,
                    PageVerdict::Wall => ProbeResult::Error,
                }
            }
            Detect::StatusAndNotBody(want, needle) => {
                if status != want {
                    return classify_non_matching_status(status);
                }
                let body = match crate::util::http::read_body_capped(resp, BODY_PROBE_CAP).await {
                    Some(t) => t,
                    None => return ProbeResult::Error,
                };
                scan_text_for_keys(&body);
                // The missing profile carries the marker here, so a
                // wall — which carries no marker — used to read as
                // a verified presence. `classify_page` judges the
                // wall first.
                match classify_page(&body, needle, false) {
                    PageVerdict::Present => found(url),
                    PageVerdict::Absent => ProbeResult::NotFound,
                    PageVerdict::Wall => ProbeResult::Error,
                }
            }
        }
    };
    match tokio::time::timeout(per_site_timeout, probe).await {
        Ok(result) => result,
        Err(_) => ProbeResult::Error,
    }
}

/// Sweep every site for the handle, then judge each presence against the
/// control handle on the same site ([`control_presences`]): a site that
/// answers "present" for a handle nobody holds cannot tell a held handle
/// from an unheld one for this client, and its presence for the target is
/// [`ProbeResult::Indiscriminate`] — never a profile. On 2026-09-15 that was
/// 78 of the 139 "profiles" the sweep reported for `torvalds`. `sites` is a
/// parameter so the real request path is driven against a loopback.
async fn sweep(
    client: &reqwest::Client,
    sites: &'static [Site],
    username: &str,
) -> Vec<(&'static str, &'static str, ProbeResult)> {
    let encoded = urlencode(username);
    let per_site_timeout = Duration::from_millis(4_500);
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PROBES));
    let first: Vec<(&'static Site, ProbeResult)> = join_all(sites.iter().map(|site| {
        let probe = probe_site(
            client.clone(),
            Arc::clone(&sem),
            site,
            site.url.replace("{}", &encoded),
            per_site_timeout,
        );
        async move { (site, probe.await) }
    }))
    .await;
    let control_encoded = urlencode(control_handle());
    let judged = control_presences(first, |site: &'static Site| {
        let url = site.url.replace("{}", &control_encoded);
        let probe = probe_site(
            client.clone(),
            Arc::clone(&sem),
            site,
            url.clone(),
            CONTROL_TIMEOUT,
        );
        (url, probe)
    })
    .await;
    judged
        .into_iter()
        .map(|(site, result)| (site.name, site.cat, result))
        .collect()
}

/// Turn resolved per-site probe outcomes into the module's entities. Pure (no
/// I/O), so the aggregation — in particular the URL-based dedup below — is
/// unit-tested directly against synthetic outcomes; the network shell in
/// `process` stays thin.
fn aggregate_results(
    username: &str,
    results: &[(&'static str, &'static str, ProbeResult)],
    scan_id: &str,
) -> Result<ModuleResult> {
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
    // Presences whose control could not be read stand as they were, and say so.
    let mut uncontrolled_hits = 0usize;
    // Sites that answered "present" for the control handle too: no answer
    // about the handle at all (`ProbeResult::Indiscriminate`).
    let mut indiscriminate_sites: Vec<&str> = Vec::new();
    // Status-only presences whose control could not be read: unjudgeable,
    // never a profile, named so the operator can look by hand
    // (`ProbeResult::Uncontrolled`, REQ-PROBE-002).
    let mut uncontrolled_sites: Vec<&str> = Vec::new();

    // A handful of site-table entries resolve to the SAME URL (two upstream
    // list sources describing the same platform with different detection
    // rules — e.g. a bare-200 check and a body-marker check both aimed at
    // the identical profile URL, such as the real `DeviantArt` (status-only)
    // vs `DeviantArt (alt)` (body-marker) pair). Pass 1: reduce to the
    // STRONGEST hit per URL — verified beats unverified, and among two of the
    // same provenance the higher confidence wins — rather than whichever
    // table entry happens to be probed first. A first-seen-wins dedup would
    // let site-table ORDER decide whether a URL a stronger sibling rule also
    // confirmed still ends up reported as merely "weak-detection".
    let mut best_by_url: std::collections::HashMap<&str, (&str, &str, f64, bool, bool)> =
        std::collections::HashMap::new();
    let mut url_order: Vec<&str> = Vec::new();
    for (site_name, site_cat, outcome) in results {
        match outcome {
            ProbeResult::Found {
                url,
                confidence,
                verified,
                controlled,
            } => {
                let candidate = (*site_name, *site_cat, *confidence, *verified, *controlled);
                match best_by_url.entry(url.as_str()) {
                    std::collections::hash_map::Entry::Vacant(v) => {
                        url_order.push(url.as_str());
                        v.insert(candidate);
                    }
                    std::collections::hash_map::Entry::Occupied(mut o) => {
                        let existing = *o.get();
                        // Compare (verified, confidence): verified strictly
                        // outranks unverified regardless of confidence, and
                        // ties within the same tier break on confidence.
                        if (candidate.3, candidate.2) > (existing.3, existing.2) {
                            o.insert(candidate);
                        }
                    }
                }
            }
            ProbeResult::NotFound => definitive_absent += 1,
            ProbeResult::Error => inconclusive_probes += 1,
            ProbeResult::Indiscriminate { .. } => indiscriminate_sites.push(*site_name),
            ProbeResult::Uncontrolled { .. } => {
                uncontrolled_sites.push(*site_name);
                // The site could not be judged: for the verdict it is one
                // more probe that could not tell.
                inconclusive_probes += 1;
            }
        }
    }

    // Pass 2: emit one entity per distinct URL, in first-seen order, using
    // whichever table entry won the reduction above.
    for url in &url_order {
        let (site_name, site_cat, confidence, verified, controlled) = best_by_url[url];
        found_names.push(site_name);
        *category_counts.entry(site_cat).or_insert(0) += 1;
        let mut e = Entity::new(EntityKind::Url, *url, confidence, scan_id);
        e.tag("social-profile");
        e.tag(format!("platform:{site_name}"));
        e.tag(format!("cat:{site_cat}"));
        // Provenance tag lets the correlator / SPA discount status-only
        // hits without re-deriving how the match was made.
        if verified {
            verified_hits += 1;
            e.tag("verified-detection");
        } else {
            weak_hits += 1;
            e.tag("weak-detection");
        }
        e.add_evidence(
            // A site another module owns (Keybase, Gravatar) is that module's
            // corpus: the hit carries its name, or the same profile counts twice.
            Evidence::new(
                crate::modules::corpus_source(url, SRC),
                format!("@{username} has a profile on {site_name}"),
            )
            .with_attr("platform", site_name)
            .with_attr("category", site_cat)
            .with_attr("username", username)
            .with_attr("url", *url)
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
            uncontrolled_hits += 1;
        }
        module_result.push(e);
    }

    // Zero hits: distinguish a genuine "not on any site" from "couldn't tell"
    // (WAF / rate-limit / no egress blocked the probes). If the probes were
    // mostly inconclusive, surface an error instead of a silent zero so the
    // operator never reads a blocked run as a confirmed absence.
    if found_names.is_empty() {
        if inconclusive_after_control(
            found_names.len(),
            inconclusive_probes,
            indiscriminate_sites.len(),
            results.len(),
        ) {
            return Err(Error::module(
                SRC,
                format!(
                    "inconclusive: {inconclusive_probes} of {} site probes that can tell were blocked or \
                         unreachable (WAF / rate-limit / no egress), {} sites answer \"present\" for \
                         any handle — not a confirmed absence",
                    results.len() - indiscriminate_sites.len(),
                    indiscriminate_sites.len()
                ),
            ));
        }
        return Ok(module_result);
    }

    // Re-emit the seed username with a corroboration-style summary so
    // the SPA's Entities table shows a single "N platforms" row for
    // the username itself, alongside the per-platform Url entities.
    if !found_names.is_empty() {
        let mut summary = Entity::new(
            EntityKind::Username,
            username,
            confidence::VERY_HIGH_PLUSPLUS,
            scan_id,
        );
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
            .with_attr("hits_status_only", weak_hits.to_string())
            .with_attr("hits_uncontrolled", uncontrolled_hits.to_string())
            .with_attr(
                "sites_indiscriminate",
                indiscriminate_sites.len().to_string(),
            )
            .with_attr("indiscriminate_platforms", indiscriminate_sites.join(", "))
            .with_attr("sites_uncontrolled", uncontrolled_sites.len().to_string())
            .with_attr("uncontrolled_platforms", uncontrolled_sites.join(", ")),
        );
        module_result.push(summary);
    }
    Ok(module_result)
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
    crate::util::probe_confidence::detection_strength(matches!(
        detect,
        Detect::StatusAndBody(..) | Detect::StatusAndNotBody(..)
    ))
}

fn scan_text_for_keys(body: &str) {
    use crate::util::found_keys::{MAX_TOKEN, key_tokens};
    use crate::util::key_harvest::identify_api_key;
    let pool = crate::util::key_pool::global_pool();
    for t in key_tokens(body, MAX_TOKEN) {
        if let Some((service, key_val)) = identify_api_key(t) {
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
