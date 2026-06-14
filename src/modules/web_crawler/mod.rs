//! Unified web crawler — supersedes SpiderFoot 4.0's sfp_spider + sfp_pageinfo
//! + sfp_webframework + sfp_webserver in a single async BFS crawler.
//!
//! Capabilities (all executed in one `process()` call):
//!   1. **Recursive BFS crawl** — async concurrent page fetching within the
//!      target domain, bounded by depth (3) and page count (60). Respects
//!      robots.txt `Disallow` rules and filters binary file extensions.
//!   2. **Link discovery** — extracts internal links (same domain), external
//!      links (other domains), and subdomain links. Each discovered subdomain
//!      becomes a Domain entity for expansion.
//!   3. **Content extraction** — emails, phones, and usernames found in page
//!      bodies are emitted as entities with source provenance.
//!   4. **Page classification** — login forms, admin panels, file upload
//!      forms, and password fields are detected and tagged.
//!   5. **Framework fingerprinting** — detects 25+ web frameworks and
//!      technologies from HTML content (WordPress, React, Angular, Vue,
//!      jQuery, Bootstrap, Next.js, Django, Laravel, Rails, etc.).
//!   6. **Security header audit** — checks for HSTS, CSP, X-Frame-Options,
//!      X-Content-Type-Options, Permissions-Policy from the seed response.
//!
//! Design principles:
//!   - Zero additional dependencies — uses reqwest (already in Cargo.toml)
//!     and string-based extraction (same approach as SpiderFoot's regex).
//!   - Bounded memory — visited set is capped, page bodies are processed
//!     and discarded (not accumulated).
//!   - Termux-friendly — 4 concurrent requests, 200ms inter-request delay,
//!     64 KB body cap per page. Total wall-time stays under 60s for typical
//!     sites.

use std::collections::{HashSet, VecDeque};

use async_trait::async_trait;
use url::Url;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};

const SRC: &str = "web_crawler";

pub struct WebCrawler;

pub(super) const MAX_PAGES: usize = 60;
pub(super) const MAX_DEPTH: u32 = 3;
const BODY_CAP: usize = 65_536;
const INTER_REQUEST_MS: u64 = 200;
const URL_TARGET_MAX_PAGES: usize = 5;
const URL_TARGET_MAX_DEPTH: u32 = 1;

pub(super) const BINARY_EXTENSIONS: &[&str] = &[
    "png", "gif", "jpg", "jpeg", "tiff", "tif", "webp", "svg", "ico", "pdf", "doc", "docx", "xls",
    "xlsx", "ppt", "pptx", "csv", "zip", "gz", "tar", "bz2", "rar", "7z", "iso", "mp3", "mp4",
    "avi", "mov", "flv", "mpg", "mpeg", "mkv", "wmv", "exe", "bin", "dmg", "msi", "deb", "rpm",
    "woff", "woff2", "ttf", "eot", "otf", "css", "map",
];

const NOTABLE_PAGES_CAP: usize = 20;
const NOTABLE_PAGE_TYPES: &[&str] = &["login_form", "file_upload", "admin_panel", "api_reference"];

pub(super) struct CrawlState {
    pub(super) visited: HashSet<String>,
    pub(super) queue: VecDeque<(String, u32)>,
    pages_fetched: usize,
    disallow_rules: Vec<String>,
    pub(super) result: ModuleResult,
    // Aggregated discovery
    pub(super) external_domains: HashSet<String>,
    pub(super) subdomains: HashSet<String>,
    pub(super) emails: HashSet<String>,
    pub(super) phones: HashSet<String>,
    /// `(canonical_id, provider)` web-analytics IDs seen across crawled pages.
    pub(super) tracking_ids: HashSet<(String, String)>,
    pub(super) frameworks: HashSet<&'static str>,
    pub(super) page_types: HashSet<&'static str>,
    pub(super) security_headers: Vec<(&'static str, bool)>,
    internal_links: usize,
    external_links: usize,
    pub(super) notable_pages: Vec<String>,
}

#[async_trait]
impl Module for WebCrawler {
    fn name(&self) -> &'static str {
        "web_crawler"
    }

    fn description(&self) -> &'static str {
        "Recursive web crawler with framework fingerprinting"
    }

    fn priority(&self) -> u8 {
        20
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Url)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Web
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Email,
            EntityKind::Url,
            EntityKind::Domain,
            EntityKind::Phone,
            EntityKind::ApiKey,
            EntityKind::TrackingId,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        60_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let is_url_target = target.kind == TargetKind::Url;

        let (seed, domain) = if is_url_target {
            let raw = target.value.trim().to_string();
            if raw.is_empty() {
                return Ok(ModuleResult::new());
            }
            let parsed =
                Url::parse(&raw).map_err(|e| Error::module(SRC, format!("bad URL target: {e}")))?;
            let host = parsed
                .host_str()
                .ok_or_else(|| Error::module(SRC, "URL has no host"))?
                .to_lowercase();
            (raw, host)
        } else {
            let d = target.value.trim().to_lowercase();
            if d.is_empty() {
                return Ok(ModuleResult::new());
            }
            let s = resolve_seed(&ctx.http, &d).await?;
            (s, d)
        };

        let max_pages = if is_url_target {
            URL_TARGET_MAX_PAGES
        } else {
            MAX_PAGES
        };
        let max_depth = if is_url_target {
            URL_TARGET_MAX_DEPTH
        } else {
            MAX_DEPTH
        };

        let seed_url =
            Url::parse(&seed).map_err(|e| Error::module(SRC, format!("bad seed URL: {e}")))?;
        let base_host = seed_url.host_str().unwrap_or(&domain).to_lowercase();

        let mut state = CrawlState {
            visited: HashSet::with_capacity(MAX_PAGES),
            queue: VecDeque::with_capacity(MAX_PAGES),
            pages_fetched: 0,
            disallow_rules: Vec::new(),
            result: ModuleResult::new(),
            external_domains: HashSet::new(),
            subdomains: HashSet::new(),
            emails: HashSet::new(),
            phones: HashSet::new(),
            tracking_ids: HashSet::new(),
            frameworks: HashSet::new(),
            page_types: HashSet::new(),
            security_headers: Vec::new(),
            internal_links: 0,
            external_links: 0,
            notable_pages: Vec::new(),
        };

        fetch_robots(&ctx.http, &seed_url, &mut state.disallow_rules).await;
        let leaks = probe_config_leaks(&ctx.http, seed_url.as_str(), &domain).await;

        // Convert each discovered key into an ApiKey entity so it shows up
        // in the operator's scan results and triggers AU-021 correlation.
        // Also tag the parent Domain with config-leak so downstream rules
        // can prioritise it.
        let mut domain_was_leaky = false;
        for (path, bytes, keys) in &leaks {
            domain_was_leaky = true;
            for (service, key_val) in keys {
                let roi = crate::util::key_roi::classify(service);
                let mut e = Entity::new(EntityKind::ApiKey, key_val, 0.90, &ctx.scan_id);
                e.tag("api-key");
                e.tag("config-leak");
                e.tag("web-crawler");
                e.tag(format!("service:{service}"));
                e.tag(format!("roi:{}", roi.label()));
                if roi == crate::util::key_roi::KeyRoi::Multiplier {
                    e.tag("force-multiplier");
                }
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("API key ({service}) exposed at {domain}{path}"),
                    )
                    .with_attr("service", *service)
                    .with_attr("roi_tier", roi.label())
                    .with_attr("exposure_path", path.as_str())
                    .with_attr("file_size_bytes", bytes.to_string()),
                );
                state.result.push(e);
            }
        }
        if domain_was_leaky {
            // Emit a meta-evidence entry on the domain even before the
            // main crawl runs. The Domain entity is still built below;
            // we just remember to tag it.
            state.frameworks.insert("config-leak-detected");
        }

        let seed_for_entities = seed.clone();
        state.queue.push_back((seed, 0));

        while let Some((url, depth)) = state.queue.pop_front() {
            if state.pages_fetched >= max_pages || ctx.cancel.is_cancelled() {
                break;
            }
            if state.visited.contains(&url) {
                continue;
            }
            state.visited.insert(url.clone());

            // SSRF egress guard (defense in depth): never fetch a discovered
            // link whose host is a private/reserved IP literal (loopback,
            // RFC1918, 169.254 cloud-metadata, …). `extract_links` keeps the
            // queue on the seed host and the HTTP client's DNS resolver vets
            // hostnames, but an IP-literal link bypasses the resolver — so the
            // guard is enforced explicitly here rather than left implicit in the
            // same-host filter, which a future change could loosen.
            if crate::util::preflight::url_host_is_private(&url) {
                continue;
            }

            if is_disallowed(&url, &state.disallow_rules) {
                continue;
            }

            let resp = match ctx.http.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(url = %url, error = %e, "web_crawler: fetch failed");
                    continue;
                }
            };

            let status = resp.status();
            if status.as_u16() == 429 || status.as_u16() == 503 {
                tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
                continue;
            }
            if !status.is_success() {
                continue;
            }

            let headers = resp.headers().clone();
            if state.pages_fetched == 0 {
                audit_security_headers(&headers, &mut state.security_headers);
            }

            let ct = headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !ct.contains("text/html")
                && !ct.contains("text/plain")
                && !ct.contains("application/xhtml")
            {
                continue;
            }

            // Stream the (untrusted) page body and STOP at BODY_CAP. A plain
            // `resp.text()` buffers the WHOLE body first — a hostile multi-GB page
            // would OOM the device before any truncation. `read_body_capped` never
            // accumulates beyond the cap, and decodes UTF-8-lossy so there's no
            // mid-codepoint panic at the boundary (web_crawler runs under
            // catch_unwind, where such a panic would silently void all findings).
            let Some(body) = crate::util::http::read_body_capped(resp, BODY_CAP).await else {
                continue;
            };

            state.pages_fetched += 1;

            detect_frameworks(&body, &mut state.frameworks);

            let mut per_page_types: HashSet<&'static str> = HashSet::new();
            detect_page_types(&body, &mut per_page_types);
            if state.notable_pages.len() < NOTABLE_PAGES_CAP
                && per_page_types
                    .iter()
                    .any(|pt| NOTABLE_PAGE_TYPES.contains(pt))
            {
                state.notable_pages.push(url.clone());
            }
            state.page_types.extend(per_page_types);

            extract_emails(&body, &mut state.emails);
            extract_phones(&body, &mut state.phones);
            extract_tracking_ids(&body, &mut state.tracking_ids);
            extract_api_keys_from_body(&body, &domain);

            if depth < max_depth {
                extract_links(&body, &url, &base_host, &domain, &mut state);
            }

            if state.pages_fetched < max_pages {
                tokio::time::sleep(std::time::Duration::from_millis(INTER_REQUEST_MS)).await;
            }
        }

        build_entities(
            &domain,
            &base_host,
            &ctx.scan_id,
            max_depth,
            is_url_target,
            &seed_for_entities,
            &mut state,
        );
        Ok(state.result)
    }
}

mod crawl_util;
use crawl_util::*;

fn build_entities(
    domain: &str,
    _base_host: &str,
    scan_id: &str,
    max_depth: u32,
    is_url_target: bool,
    seed_url: &str,
    state: &mut CrawlState,
) {
    // For URL targets, emit the URL entity itself with crawl results
    if is_url_target {
        let mut url_entity = Entity::new(EntityKind::Url, seed_url, 0.90, scan_id);
        url_entity.tag(tags::WEB);
        url_entity.tag(tags::CRAWLED);
        for fw in &state.frameworks {
            url_entity.tag(format!("tech:{}", fw.to_lowercase().replace(' ', "-")));
        }
        url_entity.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "Single-page harvest of {seed_url}: {} pages",
                    state.pages_fetched
                ),
            )
            .with_attr("pages_crawled", state.pages_fetched.to_string())
            .with_attr("emails_found", state.emails.len().to_string())
            .with_attr("phones_found", state.phones.len().to_string()),
        );
        state.result.push(url_entity);
    }

    // Main domain entity with crawl summary
    let mut entity = Entity::new(EntityKind::Domain, domain, 0.90, scan_id);
    entity.tag(tags::WEB);
    entity.tag(tags::CRAWLED);

    for fw in &state.frameworks {
        entity.tag(format!("tech:{}", fw.to_lowercase().replace(' ', "-")));
    }
    for pt in &state.page_types {
        entity.tag(format!("page:{pt}"));
    }

    // Security header tags
    let missing_headers: Vec<&str> = state
        .security_headers
        .iter()
        .filter(|(_, present)| !present)
        .map(|(name, _)| *name)
        .collect();
    if !missing_headers.is_empty() {
        entity.tag(tags::MISSING_SECURITY_HEADERS);
    }

    let mut ev = Evidence::new(
        SRC,
        format!(
            "Crawled {domain}: {} pages, {} internal links, {} external links",
            state.pages_fetched, state.internal_links, state.external_links
        ),
    )
    .with_attr("pages_crawled", state.pages_fetched.to_string())
    .with_attr("internal_links", state.internal_links.to_string())
    .with_attr("external_links", state.external_links.to_string())
    .with_attr("max_depth", max_depth.to_string());

    if !state.frameworks.is_empty() {
        let mut fws: Vec<&str> = state.frameworks.iter().copied().collect();
        fws.sort_unstable();
        ev = ev.with_attr("frameworks", fws.join(", "));
    }
    if !state.page_types.is_empty() {
        let mut pts: Vec<&str> = state.page_types.iter().copied().collect();
        pts.sort_unstable();
        ev = ev.with_attr("page_types", pts.join(", "));
    }
    if !state.notable_pages.is_empty() {
        ev = ev.with_attr("notable_pages", state.notable_pages.join(" | "));
    }
    ev = ev.with_attr("subdomains_found", state.subdomains.len().to_string());
    ev = ev.with_attr("emails_found", state.emails.len().to_string());
    ev = ev.with_attr("phones_found", state.phones.len().to_string());

    if !missing_headers.is_empty() {
        ev = ev.with_attr("missing_security_headers", missing_headers.join(", "));
    }
    let present_headers: Vec<&str> = state
        .security_headers
        .iter()
        .filter(|(_, present)| *present)
        .map(|(name, _)| *name)
        .collect();
    if !present_headers.is_empty() {
        ev = ev.with_attr("present_security_headers", present_headers.join(", "));
    }

    entity.add_evidence(ev);
    state.result.push(entity);

    // Subdomain entities — feed back into expansion
    state.result.extend(state.subdomains.iter().map(|sub| {
        let mut e = Entity::new(EntityKind::Domain, sub.as_str(), 0.82, scan_id);
        e.tag(tags::WEB);
        e.tag(tags::SUBDOMAIN);
        e.add_evidence(
            Evidence::new(SRC, format!("Subdomain discovered by crawling {domain}"))
                .with_attr("parent_domain", domain),
        );
        e
    }));

    // External domain entities
    state
        .result
        .extend(state.external_domains.iter().map(|ext| {
            let mut e = Entity::new(EntityKind::Domain, ext.as_str(), 0.50, scan_id);
            e.tag(tags::EXTERNAL);
            e.add_evidence(
                Evidence::new(SRC, format!("External domain linked from {domain}"))
                    .with_attr("source_domain", domain),
            );
            e
        }));

    // Email entities. A crawl that scrapes an implausible number of distinct
    // addresses has hit a directory / forum / comment-thread dump, not the
    // subject's contacts — emitting them floods the graph with strangers (a real
    // scan pulled ~100 unrelated emails off one comment page). Above the dump
    // threshold the whole batch is co-occurrence noise, so suppress it; a normal
    // contact/about page (a handful of addresses) passes through.
    const CONTACT_DUMP_LIMIT: usize = 20;
    if state.emails.len() <= CONTACT_DUMP_LIMIT {
        state.result.extend(state.emails.iter().map(|email| {
            let mut e = Entity::new(EntityKind::Email, email.as_str(), 0.75, scan_id);
            e.tag(tags::WEB_SCRAPED);
            e.add_evidence(
                Evidence::new(SRC, format!("Email found on {domain}"))
                    .with_attr("source_domain", domain),
            );
            e
        }));
    }

    // Tracking-ID entities (web-analytics affiliate pivot). The id is a hard
    // identifier, so confidence is high (0.80); the `source_domain` attr lets the
    // correlator count how many distinct sites carry the same id (shared id ⇒
    // common ownership). When two crawled domains share an id, both emit the same
    // TrackingId value → it merges to one entity, raising corroboration.
    state
        .result
        .extend(state.tracking_ids.iter().map(|(id, provider)| {
            let mut e = Entity::new(EntityKind::TrackingId, id.as_str(), 0.80, scan_id);
            e.tag(tags::WEB_SCRAPED);
            e.tag("web-analytics");
            e.add_evidence(
                Evidence::new(SRC, format!("{provider} tracking id {id} on {domain}"))
                    .with_attr("provider", provider)
                    .with_attr("source_domain", domain),
            );
            e
        }));

    // Phone entities — same dump guard (a page with dozens of numbers is a
    // directory, not the subject's).
    if state.phones.len() <= CONTACT_DUMP_LIMIT {
        state.result.extend(state.phones.iter().map(|phone| {
            let mut e = Entity::new(EntityKind::Phone, phone.as_str(), 0.75, scan_id);
            e.tag(tags::WEB_SCRAPED);
            e.add_evidence(
                Evidence::new(SRC, format!("Phone found on {domain}"))
                    .with_attr("source_domain", domain),
            );
            e
        }));
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
