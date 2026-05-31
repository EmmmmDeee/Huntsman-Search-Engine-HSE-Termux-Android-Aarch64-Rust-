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

/// Browser-shaped User-Agent for the per-site probes.
///
/// Until v1.2 the module used reqwest's default client UA
/// (`huntsman-search-engine/x.y.z (+url)`), which Cloudflare /
/// PerimeterX / Akamai-fronted social platforms routinely 403'd as a
/// bot signal — meaning ~30% of the SITES table was returning Error
/// even when the username existed. Sending a real Chrome-on-Android
/// UA (chosen to match the `util::curl_client` fingerprint used by
/// the paid OSINT modules) restores hit rate.
const BROWSER_UA: &str = "Mozilla/5.0 (Linux; Android 14; Pixel 8) \
    AppleWebKit/537.36 (KHTML, like Gecko) \
    Chrome/125.0.0.0 Mobile Safari/537.36";

/// Accept header — wide image/html/anything spec that matches what a
/// browser sends. Some WAFs (notably Akamai Bot Manager) score
/// requests with `accept: */*` as suspicious.
const BROWSER_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;\
    q=0.9,image/avif,image/webp,*/*;q=0.8";

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::urlencode;

const SRC: &str = "username_search";

pub struct UsernameSearch;

/// One site to probe. Kept inline (rather than loaded from a JSON file)
/// so the binary stays self-contained and the list is reviewable in PR.
mod sites;
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
                        scan_text_for_keys(&body);
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
                        scan_text_for_keys(&body);
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
                    Evidence::new(SRC, format!("@{username} has a profile on {site_name}"))
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

            // Tag each category that had at least one hit.
            for cat in category_counts.keys() {
                summary.tag(format!("cat:{cat}"));
            }

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

fn scan_text_for_keys(body: &str) {
    use crate::modules::oathnet_pro::key_harvest::identify_api_key;
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

    #[test]
    fn max_timeout_ms_budgeted_for_full_table_sweep() {
        // Regression guard: with 334 sites and 32 concurrent probes,
        // the module needs ~ceil(334/32) × 4.5s = 47s of probing
        // wall-time. If a future contributor reverts to the default
        // 3_000ms (MODULE_TIMEOUT_MS) the engine will kill the
        // module after ~2 batches and surface only ~10% of real
        // hits. 60s envelope leaves headroom for slow CDN probes.
        let m = UsernameSearch;
        let budget = m.max_timeout_ms();
        let needed = ((SITES.len() as u64).div_ceil(MAX_CONCURRENT_PROBES as u64)) * 4_500;
        assert!(
            budget >= needed,
            "max_timeout_ms ({budget}ms) too tight for full sweep of {} sites \
             at {MAX_CONCURRENT_PROBES} concurrent probes (need ≥ {needed}ms)",
            SITES.len(),
        );
    }

    #[test]
    fn browser_ua_is_chrome_shaped() {
        // Regression guard: if a contributor reverts to the tool UA
        // (`huntsman-search-engine/...`), Cloudflare-fronted sites
        // will 403 ~30% of the table again. Lock in the shape so
        // anyone changing it has to update this test too.
        assert!(BROWSER_UA.contains("Mozilla/5.0"));
        assert!(BROWSER_UA.contains("Chrome/"));
        assert!(!BROWSER_UA.contains("huntsman-search-engine"));
    }
}
