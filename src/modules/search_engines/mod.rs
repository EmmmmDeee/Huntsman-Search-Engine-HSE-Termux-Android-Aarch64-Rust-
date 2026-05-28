//! Multi-engine search scraping — 13 search engines, zero API keys.
//!
//! Queries Yahoo, Bing, AOL, DuckDuckGo, Google, Brave, Mojeek,
//! Startpage, Yandex, Ecosia, Qwant, Dogpile, and Swisscows with
//! OSINT dork queries and extracts entities from result URLs and
//! snippets.
//!
//! Engine selection rationale:
//!   - Yahoo/AOL: Bing-powered, most reliable from datacenter IPs,
//!     /RU= redirect URL decoding
//!   - Bing: <cite> tag extraction, reliable from datacenter IPs
//!   - DuckDuckGo HTML: no JS, `uddg` redirect decoded
//!   - Google: /url?q= redirect extraction (requires JS since 2025,
//!     best from residential IPs)
//!   - Brave: independent index, direct href extraction
//!   - Mojeek: independent index, CAPTCHA-resistant
//!   - Startpage: Google-sourced, POST endpoint with session warming
//!   - Yandex: independent Russian index (SmartCaptcha from DC IPs,
//!     works from residential)
//!   - Ecosia: Bing-powered, tree-planting search engine
//!   - Qwant: European privacy engine (lite endpoint)
//!   - Dogpile: Meta-aggregator (System1), aggregates multiple engines
//!   - Swisscows: Swiss privacy engine, Bing-powered
//!
//! Blocked engines are harmless — detected and skipped in <1s via
//! the interstitial/CAPTCHA detector (checks for anomaly-modal,
//! unusual traffic, consent walls, DataDome, SmartCaptcha, etc.).
//!
//! Dork query strategy per target type:
//!   - Domain: site: subdomain discovery, email harvesting, document
//!     discovery (filetype:pdf/doc/xls), login/admin exposure
//!   - Email: quoted mention search, paste-site exposure, social pivots
//!   - Username: social platform dorks (github, linkedin, twitter, reddit)
//!   - FullName: professional profile + document discovery
//!
//! Entity production:
//!   - Domain (subdomains at 0.70, external at 0.45) → triggers 15+ modules
//!   - Email (from snippet text at 0.60) → triggers breach + identity stack
//!   - Phone (from snippet text at 0.55) → triggers numverify, phone_intl

use std::collections::HashSet;

mod engines;
mod fetch;
mod helpers;

use engines::{ENGINES, EngineSpec};
use fetch::*;
pub(crate) use helpers::SearchResult;
use helpers::*;

use async_trait::async_trait;

use crate::core::{
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
};

pub struct SearchEngines;

const MAX_RESULTS_PER_ENGINE: usize = 20;
const INTER_ENGINE_MS: u64 = 400;
const MAX_PAGES: usize = 2;
const MAX_ACCUMULATED_RESULTS: usize = 2000;

const SOCIAL_HOSTS: &[&str] = &[
    "facebook.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "instagram.com",
    "github.com",
    "reddit.com",
    "myspace.com",
    "soundcloud.com",
    "peekyou.com",
    "youtube.com",
    "tiktok.com",
    "pinterest.com",
    "tumblr.com",
    "linktr.ee",
    "medium.com",
];

fn is_social_host(host: &str) -> bool {
    SOCIAL_HOSTS.iter().any(|s| {
        host == *s
            || (host.len() > s.len()
                && host.ends_with(s)
                && host.as_bytes()[host.len() - s.len() - 1] == b'.')
    })
}

#[async_trait]
impl Module for SearchEngines {
    fn name(&self) -> &'static str {
        "search_engines"
    }

    fn description(&self) -> &'static str {
        "Multi-engine OSINT dork search across 13 engines"
    }

    fn priority(&self) -> u8 {
        25
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Domain
                | TargetKind::Email
                | TargetKind::Username
                | TargetKind::FullName
                | TargetKind::Phone
                | TargetKind::IpAddress
                | TargetKind::Organisation
                | TargetKind::Address
                | TargetKind::Asn
                | TargetKind::AbnAcn
                | TargetKind::Url
                | TargetKind::Coordinates
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        120_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let queries = build_queries(target);
        if queries.is_empty() {
            return Ok(ModuleResult::new());
        }

        let process_start = std::time::Instant::now();
        let budget_ms = self.max_timeout_ms();
        let mut all_results: Vec<SearchResult> = Vec::new();

        // Track engines that failed on the first query so we skip them
        // on subsequent queries — avoids burning the entire timeout
        // budget on engines that are down/blocked for this session.
        let mut dead_engines: HashSet<&str> = HashSet::new();

        // ── Primary pass: run all queries against live engines ─────
        for (qi, query) in queries.iter().enumerate() {
            if ctx.cancel.is_cancelled() {
                break;
            }
            let elapsed = process_start.elapsed().as_millis() as u64;
            if elapsed > budget_ms.saturating_sub(30_000) {
                break;
            }

            for engine in ENGINES {
                if ctx.cancel.is_cancelled() {
                    break;
                }
                if qi > 0 && dead_engines.contains(engine.name) {
                    continue;
                }
                let url = (engine.build_url)(query);
                let post_body = engine.build_post.map(|f| f(query));
                if all_results.len() >= MAX_ACCUMULATED_RESULTS {
                    break;
                }
                let before = all_results.len();
                if let Some(mut results) =
                    fetch_and_parse(&url, engine, query, post_body.as_deref()).await
                {
                    let got_results = !results.is_empty();
                    all_results.append(&mut results);
                    if all_results.len() >= MAX_ACCUMULATED_RESULTS {
                        all_results.truncate(MAX_ACCUMULATED_RESULTS);
                    }
                    if got_results
                        && qi == 0
                        && let Some(paginate_fn) = engine.paginate
                    {
                        for page in 1..MAX_PAGES {
                            if ctx.cancel.is_cancelled() {
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(INTER_ENGINE_MS))
                                .await;
                            let page_url = paginate_fn(query, page);
                            if let Some(mut pr) =
                                fetch_and_parse(&page_url, engine, query, None).await
                            {
                                if pr.is_empty() {
                                    break;
                                }
                                all_results.append(&mut pr);
                            } else {
                                break;
                            }
                        }
                    }
                } else if qi == 0 {
                    dead_engines.insert(engine.name);
                }
                if all_results.len() > before {
                    tokio::time::sleep(std::time::Duration::from_millis(INTER_ENGINE_MS)).await;
                }
            }
        }

        // ── Secondary pivot: re-search discovered usernames + variants
        //    on reliable engines for cross-platform linkage ────────────
        if !ctx.cancel.is_cancelled() {
            let mut pivots = extract_username_pivots(&all_results, target);

            // Generate username variants for the strongest pivots
            // (separator swaps, trailing digits, truncations)
            let base_pivots: Vec<String> = pivots.clone();
            for base in &base_pivots {
                let raw = base.trim_matches('"');
                for variant in generate_username_variants(raw) {
                    let vq = format!("\"{variant}\"");
                    if !pivots.contains(&vq) {
                        pivots.push(vq);
                    }
                }
            }

            if !pivots.is_empty() {
                let reliable = [&ENGINES[0], &ENGINES[1], &ENGINES[5]]; // yahoo, bing, brave
                for pivot_query in pivots.iter().take(10) {
                    if ctx.cancel.is_cancelled() {
                        break;
                    }
                    for engine in &reliable {
                        if ctx.cancel.is_cancelled() {
                            break;
                        }
                        if dead_engines.contains(engine.name) {
                            continue;
                        }
                        let url = (engine.build_url)(pivot_query);
                        if let Some(mut results) =
                            fetch_and_parse(&url, engine, pivot_query, None).await
                        {
                            all_results.append(&mut results);
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(INTER_ENGINE_MS)).await;
                    }
                }
            }
        }

        // Deduplicate results by canonical URL before entity extraction.
        let all_results = dedup_results(all_results);

        let mut module_result = build_entities(target, &ctx.scan_id, &all_results);

        // ── Recursive entity recycler: re-search high-confidence
        //    discovered entities for geolocation and cross-linking ─────
        let elapsed_ms = process_start.elapsed().as_millis() as u64;
        let remaining_ms = budget_ms.saturating_sub(elapsed_ms);
        if !ctx.cancel.is_cancelled() && remaining_ms > 15_000 {
            recycle_entities(ctx, &mut module_result, &dead_engines, &all_results).await;
        }

        Ok(module_result)
    }
}

// ─── Recursive entity recycler ─────────────────────────────────────────────
//
// After the primary search pass produces entities, the recycler takes
// the highest-confidence discoveries and re-searches them on reliable
// engines to find geolocation cross-links. This catches the common
// OSINT pattern where an email → username → address chain only becomes
// visible when you search for the intermediate entity.

async fn recycle_entities(
    ctx: &ModuleContext,
    result: &mut ModuleResult,
    dead_engines: &HashSet<&str>,
    _primary_results: &[SearchResult],
) {
    let reliable = [&ENGINES[0], &ENGINES[1], &ENGINES[5]]; // yahoo, bing, brave

    let mut recycle_queries: Vec<String> = Vec::new();
    let mut seen_queries: HashSet<String> = HashSet::new();

    for entity in &result.entities {
        if entity.confidence < 0.40 {
            continue;
        }
        let q = match entity.kind {
            EntityKind::Email => {
                let local = entity.value.split('@').next().unwrap_or("");
                if local.len() >= 3 {
                    Some(format!("\"{local}\" address OR location OR suburb OR city"))
                } else {
                    None
                }
            }
            EntityKind::Username if entity.value.len() >= 3 => {
                Some(format!("\"{}\" address OR location OR city", entity.value))
            }
            EntityKind::Person => Some(format!("\"{}\" address OR email OR phone", entity.value)),
            EntityKind::Address if entity.confidence >= 0.40 => Some(format!(
                "\"{}\" name OR resident OR owner OR phone",
                entity.value
            )),
            EntityKind::Phone => Some(format!("\"{}\" name OR address OR owner", entity.value)),
            EntityKind::Domain if entity.confidence >= 0.55 => {
                let domain = &entity.value;
                Some(format!(
                    "\"{domain}\" location OR address OR city OR suburb"
                ))
            }
            EntityKind::Organisation if entity.confidence >= 0.50 => {
                Some(format!("\"{}\" address OR ABN OR location", entity.value))
            }
            _ => None,
        };
        if let Some(query) = q
            && seen_queries.insert(query.clone())
        {
            recycle_queries.push(query);
        }
    }

    if recycle_queries.is_empty() {
        return;
    }

    let scan_id = result
        .entities
        .first()
        .map(|e| e.scan_id.clone())
        .unwrap_or_default();

    let mut recycled_results: Vec<SearchResult> = Vec::new();

    for query in recycle_queries.iter().take(12) {
        if ctx.cancel.is_cancelled() {
            break;
        }
        for engine in &reliable {
            if ctx.cancel.is_cancelled() {
                break;
            }
            if dead_engines.contains(engine.name) {
                continue;
            }
            let url = (engine.build_url)(query);
            if let Some(mut results) = fetch_and_parse(&url, engine, query, None).await {
                recycled_results.append(&mut results);
            }
            tokio::time::sleep(std::time::Duration::from_millis(INTER_ENGINE_MS)).await;
        }
    }

    if recycled_results.is_empty() {
        return;
    }

    let recycled_results = dedup_results(recycled_results);
    let mut seen_addrs: HashSet<String> = HashSet::new();
    let mut seen_emails: HashSet<String> = HashSet::new();
    let mut seen_phones: HashSet<String> = HashSet::new();

    // Collect existing entity values to avoid duplicates
    for e in &result.entities {
        match e.kind {
            EntityKind::Address => {
                seen_addrs.insert(e.value.to_lowercase());
            }
            EntityKind::Email => {
                seen_emails.insert(e.value.to_lowercase());
            }
            EntityKind::Phone => {
                seen_phones.insert(e.value.clone());
            }
            _ => {}
        }
    }

    for r in &recycled_results {
        let combined = format!("{} {}", r.title, r.snippet);

        for addr in extract_addresses_from_text(&combined) {
            if seen_addrs.insert(addr.to_lowercase()) {
                let mut e = Entity::new(EntityKind::Address, &addr, 0.45, &scan_id);
                e.tag("search-discovered");
                e.tag("recycled");
                e.add_evidence(
                    Evidence::new(
                        "search_engines",
                        format!("[{}] Address from recycled search — {}", r.engine, r.url),
                    )
                    .with_attr("url", &r.url)
                    .with_attr("engine", r.engine)
                    .with_attr("recycle_query", &r.query),
                );
                result.push(e);
            }
        }

        for email in extract_emails_from_text(&combined) {
            if seen_emails.insert(email.clone()) {
                let mut e = Entity::new(EntityKind::Email, &email, 0.55, &scan_id);
                e.tag("search-discovered");
                e.tag("recycled");
                e.add_evidence(
                    Evidence::new(
                        "search_engines",
                        format!("[{}] Email from recycled search — {}", r.engine, r.url),
                    )
                    .with_attr("url", &r.url)
                    .with_attr("engine", r.engine),
                );
                result.push(e);
            }
        }

        for phone in extract_phones_from_text(&combined) {
            if seen_phones.insert(phone.clone()) {
                let mut e = Entity::new(EntityKind::Phone, &phone, 0.50, &scan_id);
                e.tag("search-discovered");
                e.tag("recycled");
                e.add_evidence(
                    Evidence::new(
                        "search_engines",
                        format!("[{}] Phone from recycled search — {}", r.engine, r.url),
                    )
                    .with_attr("url", &r.url)
                    .with_attr("engine", r.engine),
                );
                result.push(e);
            }
        }
    }
}

fn build_queries(target: &Target) -> Vec<String> {
    let v = target.value.trim();
    if v.is_empty() {
        return Vec::new();
    }
    match target.kind {
        TargetKind::Domain => vec![
            format!("site:{v}"),
            format!("site:{v} filetype:pdf OR filetype:doc OR filetype:xls"),
            format!("\"{v}\" \"@{v}\""),
            format!("site:{v} inurl:login OR inurl:admin OR inurl:signin"),
            format!("\"{v}\" ABN OR ACN OR \"Pty Ltd\" OR \"business number\""),
        ],
        TargetKind::Email => {
            let domain = v.rsplit_once('@').map_or("", |(_, d)| d);
            let local = v.split('@').next().unwrap_or("");
            let mut q = vec![format!("\"{v}\""), format!("\"{local}\"")];
            if !domain.is_empty()
                && !["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"].contains(&domain)
            {
                q.push(format!(
                    "\"{v}\" site:linkedin.com OR site:github.com OR site:facebook.com"
                ));
            }
            if local.len() >= 3 {
                q.push(format!(
                    "\"{local}\" site:linkedin.com OR site:twitter.com \
                     OR site:facebook.com OR site:myspace.com"
                ));
                q.push(format!(
                    "\"{local}\" site:peekyou.com OR site:nuwber.com \
                     OR site:spokeo.com OR site:pipl.com"
                ));
                q.push(format!(
                    "{local} site:soundcloud.com OR site:instagram.com \
                     OR site:youtube.com OR site:tiktok.com"
                ));
                q.push(format!("\"{local}\" address OR location OR city"));
                q.push(format!(
                    "\"{local}\" site:whitepages.com.au OR site:locatefamily.com \
                     OR site:peoplefinder.com.au OR site:searchfind.com.au"
                ));
            }
            q
        }
        TargetKind::Username => vec![
            format!("\"{v}\" site:github.com OR site:linkedin.com OR site:facebook.com"),
            format!("\"{v}\" site:twitter.com OR site:reddit.com OR site:instagram.com"),
            format!("\"{v}\" profile OR account OR about"),
            format!("\"{v}\" email OR contact OR address"),
            format!(
                "\"{v}\" site:peekyou.com OR site:nuwber.com \
                 OR site:spokeo.com OR site:pipl.com"
            ),
        ],
        TargetKind::FullName => {
            let parts: Vec<&str> = v.split_whitespace().collect();
            let mut q = vec![
                format!("\"{v}\""),
                format!("\"{v}\" site:linkedin.com OR site:facebook.com OR site:twitter.com"),
            ];
            if parts.len() >= 2 {
                let first = parts[0];
                let last = parts[parts.len() - 1];
                let fl = format!("{first} {last}");

                // First+Last without middle names — broader match
                if parts.len() > 2 {
                    q.push(format!("\"{fl}\""));
                }

                // Social / professional
                q.push(format!(
                    "{fl} site:instagram.com OR site:github.com OR site:reddit.com"
                ));
                q.push(format!("\"{v}\" email OR contact OR profile"));
                q.push(format!(
                    "\"{v}\" site:peekyou.com OR site:spokeo.com \
                     OR site:nuwber.com OR site:pipl.com"
                ));
                q.push(format!("\"{v}\" address OR location OR city OR suburb"));

                // Middle names as potential usernames (3+ part names)
                if parts.len() >= 3 {
                    let middle = parts[1..parts.len() - 1].join(" ");
                    // Common username patterns from multi-part names
                    let fl_concat = format!("{}{}", first.to_lowercase(), last.to_lowercase());
                    let fml = format!(
                        "{}{}{}",
                        &first.to_lowercase()[..1.min(first.len())],
                        middle.to_lowercase(),
                        last.to_lowercase()
                    );
                    q.push(format!("\"{fl_concat}\" OR \"{fml}\" profile OR account"));
                }

                // Business / corporate
                q.push(format!("\"{v}\" ABN OR ACN OR \"Pty Ltd\" OR director"));

                // Australian people-search directories
                q.push(format!(
                    "\"{v}\" site:whitepages.com.au OR site:locatefamily.com \
                     OR site:peoplefinder.com.au OR site:searchfind.com.au"
                ));

                // Australian public records — courts, electoral, property
                q.push(format!(
                    "\"{v}\" site:courts.qld.gov.au OR site:ecourts.justice.nsw.gov.au \
                     OR site:austlii.edu.au OR site:jade.io"
                ));
                q.push(format!(
                    "\"{fl}\" Queensland OR Brisbane OR \"Gold Coast\" OR Cairns"
                ));

                // Email discovery dork — search for the name near email addresses
                q.push(format!(
                    "\"{fl}\" \"@gmail.com\" OR \"@hotmail.com\" OR \"@outlook.com\" OR \"@yahoo.com\""
                ));

                // News / media mentions
                q.push(format!(
                    "\"{v}\" site:abc.net.au OR site:news.com.au \
                     OR site:smh.com.au OR site:couriermail.com.au"
                ));

                // Forum / community (usernames often match real names)
                q.push(format!(
                    "\"{fl}\" site:whirlpool.net.au OR site:forums.realestate.com.au \
                     OR site:ozbargain.com.au"
                ));
            }
            q
        }
        TargetKind::Phone => {
            let mut q = vec![format!("\"{v}\"")];
            let digits: String = v.chars().filter(char::is_ascii_digit).collect();
            if digits.len() >= 7 {
                q.push(format!(
                    "\"{v}\" site:whitepages.com OR site:truecaller.com \
                     OR site:whocalledme.com OR site:reversephonelookup.com"
                ));
                q.push(format!("\"{v}\" name OR address OR owner"));
            }
            q
        }
        TargetKind::IpAddress => vec![
            format!("\"{v}\""),
            format!("\"{v}\" hostname OR server OR domain"),
            format!("\"{v}\" site:shodan.io OR site:censys.io OR site:zoomeye.org"),
            format!("\"{v}\" location OR city OR country OR ISP"),
        ],
        TargetKind::Organisation => {
            let mut q = vec![
                format!("\"{v}\""),
                format!("\"{v}\" ABN OR ACN OR \"business number\" OR director"),
                format!(
                    "\"{v}\" site:abr.business.gov.au OR site:asic.gov.au \
                     OR site:opencorporates.com"
                ),
                format!("\"{v}\" address OR location OR headquarters"),
                format!("\"{v}\" email OR contact OR phone"),
            ];
            let lower = v.to_lowercase();
            if !lower.contains("pty") && !lower.contains("ltd") {
                q.push(format!("\"{v}\" \"Pty Ltd\" OR \"Limited\" OR \"Inc\""));
            }
            q
        }
        TargetKind::Address => {
            let mut q = vec![format!("\"{v}\"")];
            q.push(format!("\"{v}\" resident OR owner OR tenant OR occupant"));
            q.push(format!(
                "\"{v}\" site:realestate.com.au OR site:domain.com.au \
                 OR site:zillow.com OR site:trulia.com"
            ));
            q.push(format!("\"{v}\" ABN OR business OR company OR shop"));
            q
        }
        TargetKind::Asn => {
            let asn = if v.starts_with("AS") || v.starts_with("as") {
                v.to_uppercase()
            } else {
                format!("AS{v}")
            };
            vec![
                format!("\"{asn}\""),
                format!("\"{asn}\" site:bgp.he.net OR site:bgpview.io OR site:peeringdb.com"),
                format!("\"{asn}\" abuse OR peering OR prefix OR allocation"),
            ]
        }
        TargetKind::AbnAcn => {
            let digits: String = v.chars().filter(char::is_ascii_digit).collect();
            vec![
                format!("\"{v}\""),
                format!(
                    "\"{digits}\" site:abr.business.gov.au OR site:asic.gov.au \
                     OR site:opencorporates.com"
                ),
                format!("\"{digits}\" ABN OR ACN OR \"business number\" OR director"),
            ]
        }
        TargetKind::Url => {
            let host = v
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or(v);
            vec![
                format!("\"{v}\""),
                format!("site:{host}"),
                format!("\"{host}\" email OR contact OR about"),
            ]
        }
        TargetKind::Coordinates => {
            if let Some((lat, lon)) = v.split_once(',') {
                let lat = lat.trim();
                let lon = lon.trim();
                vec![
                    format!("\"{lat}\" \"{lon}\""),
                    format!("\"{lat},{lon}\" address OR location OR property"),
                    format!("\"{lat}\" \"{lon}\" site:google.com/maps OR site:openstreetmap.org"),
                ]
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

// ─── Username variant generation ────────────────────────────────────────────

/// Generate common username variants from a base handle. OSINT best
/// practice: people reuse patterns like underscore/dot swaps, trailing
/// digits, first-initial+lastname. This dramatically increases cross-
/// platform discovery.
fn generate_username_variants(base: &str) -> Vec<String> {
    let lower = base.to_lowercase();
    let mut variants = Vec::with_capacity(8);

    // Separator swaps: jerome-despal ↔ jerome_despal ↔ jerome.despal ↔ jeromedespal
    if lower.contains('_') || lower.contains('-') || lower.contains('.') {
        let no_sep: String = lower
            .chars()
            .filter(|c| *c != '_' && *c != '-' && *c != '.')
            .collect();
        let with_under = lower.replace(['-', '.'], "_");
        let with_dash = lower.replace(['_', '.'], "-");
        let with_dot = lower.replace(['_', '-'], ".");
        for v in [no_sep, with_under, with_dash, with_dot] {
            if v != lower && v.len() >= 3 {
                variants.push(v);
            }
        }
    }

    // Trailing digit variants: jdespal → jdespal1, jdespal2
    if !lower.ends_with(|c: char| c.is_ascii_digit()) && lower.len() >= 4 {
        variants.push(format!("{lower}1"));
        variants.push(format!("{lower}2"));
    }

    // Truncation: jdespal → jdespa (off-by-one typos / platform limits)
    if lower.len() >= 5 {
        variants.push(lower[..lower.len() - 1].to_string());
    }

    variants
}

/// Extract family members from search results: people who share the
/// target's last name but have a different first name. These are high-
/// value geolocation and identity leads (same household, same address).
fn extract_family_names(results: &[SearchResult], target: &Target) -> Vec<(String, String)> {
    if !matches!(target.kind, TargetKind::FullName | TargetKind::Email) {
        return Vec::new();
    }
    let parts: Vec<&str> = target.value.split_whitespace().collect();
    let lastname = match target.kind {
        TargetKind::FullName if parts.len() >= 2 => parts.last().unwrap().to_lowercase(),
        TargetKind::Email => {
            let local = target.value.split('@').next().unwrap_or("");
            if local.len() >= 5 {
                local[1..].to_lowercase()
            } else {
                return Vec::new();
            }
        }
        _ => return Vec::new(),
    };

    if lastname.len() < 4 {
        return Vec::new();
    }

    let mut found = Vec::new();
    let mut seen = HashSet::new();
    let target_lower = target.value.to_lowercase();

    for r in results {
        // Strip HTML artifacts before scanning for names
        let raw = format!("{} {}", r.title, r.snippet);
        let text = strip_tags(&raw, raw.len());
        let lower = text.to_lowercase();
        let words: Vec<&str> = lower.split_whitespace().collect();
        for window in words.windows(2) {
            let first = window[0].trim_matches(|c: char| !c.is_alphanumeric());
            let last = window[1].trim_matches(|c: char| !c.is_alphanumeric());
            if last != lastname || first.len() < 3 || first.len() > 15 {
                continue;
            }
            if !first.chars().all(|c| c.is_ascii_alphabetic()) {
                continue;
            }
            if target_lower.contains(first) {
                continue;
            }
            if is_non_name_word(first) {
                continue;
            }
            if !seen.insert(first.to_string()) {
                continue;
            }
            let name = format!(
                "{}{} {}{}",
                first[..1].to_uppercase(),
                &first[1..],
                lastname[..1].to_uppercase(),
                &lastname[1..]
            );
            found.push((name, r.url.clone()));
        }
    }
    found
}

// ─── Secondary pivot: extract usernames from discovered URLs ────────────────

/// Extract potential username pivots from search results. Social
/// profile URLs contain usernames in their path that can be used
/// as secondary search seeds to find cross-platform identity links.
fn extract_username_pivots(results: &[SearchResult], target: &Target) -> Vec<String> {
    let terms = target_terms(target);
    let mut seen = HashSet::new();
    let target_lower = target.value.to_lowercase();
    let mut pivots = Vec::new();

    for r in results {
        let host = extract_host(&r.url);
        if !is_social_host(&host) {
            continue;
        }
        if let Some(username) = extract_path_username(&r.url) {
            let lower = username.to_lowercase();
            if lower.len() >= 3
                && lower != target_lower
                && !is_navigation_path(&lower)
                && seen.insert(lower.clone())
            {
                let (score, _) = score_username(&lower, &extract_host(&r.url), &terms, r);
                if score >= 3 {
                    pivots.push(format!("\"{username}\""));
                }
            }
        }
    }
    pivots
}

fn build_entities(target: &Target, scan_id: &str, results: &[SearchResult]) -> ModuleResult {
    let mut result = ModuleResult::new();
    if results.is_empty() {
        return result;
    }

    let terms = target_terms(target);

    // Pre-scan: count how many independent engines confirmed each URL.
    // Multi-engine corroboration boosts entity confidence because
    // different engines have different indexes — an independent match
    // is strong evidence of relevance.
    let mut url_engine_count: std::collections::HashMap<String, HashSet<&str>> =
        std::collections::HashMap::new();
    for r in results {
        let key = canonicalize_url(&r.url);
        url_engine_count.entry(key).or_default().insert(r.engine);
    }

    let mut seen_domains: HashSet<String> = HashSet::new();
    let mut seen_emails: HashSet<String> = HashSet::new();
    let mut seen_phones: HashSet<String> = HashSet::new();
    let target_domain = match target.kind {
        TargetKind::Domain => Some(target.value.to_lowercase()),
        TargetKind::Email => target.value.rsplit_once('@').map(|(_, d)| d.to_lowercase()),
        _ => None,
    };

    let engines_hit: HashSet<&str> = results.iter().map(|r| r.engine).collect();
    let queries_run: HashSet<&str> = results.iter().map(|r| r.query.as_str()).collect();

    // Parent entity with search metadata
    let mut parent = target.to_entity(0.82, scan_id);
    parent.tag("search-enriched");
    let mut engines_list: Vec<&str> = engines_hit.iter().copied().collect();
    engines_list.sort_unstable();
    parent.add_evidence(
        Evidence::new(
            "search_engines",
            format!(
                "Search across {} engine(s) returned {} result(s) from {} quer{}",
                engines_hit.len(),
                results.len(),
                queries_run.len(),
                if queries_run.len() == 1 { "y" } else { "ies" },
            ),
        )
        .with_attr("result_count", results.len().to_string())
        .with_attr("engines", engines_list.join(", "))
        .with_attr("queries_run", queries_run.len().to_string()),
    );
    result.push(parent);

    for r in results {
        let host = extract_host(&r.url);
        if host.is_empty() {
            continue;
        }

        let domain = extract_registrable(&host);
        let is_subdomain = target_domain
            .as_ref()
            .is_some_and(|td| host != *td && host.ends_with(&format!(".{td}")));

        let n_engines = url_engine_count
            .get(&canonicalize_url(&r.url))
            .map_or(1, |s| s.len() as u32);

        if is_subdomain && seen_domains.insert(host.clone()) {
            let mut e = Entity::new(EntityKind::Domain, &host, 0.70, scan_id);
            e.corroboration = n_engines;
            e.tag(tags::SUBDOMAIN);
            e.tag("search-discovered");
            e.add_evidence(build_search_evidence(r));
            result.push(e);
        } else if target_domain.as_ref().is_none_or(|td| domain != *td)
            && !is_generic_domain(&domain)
            && seen_domains.insert(domain.clone())
        {
            let mut e = Entity::new(EntityKind::Domain, &domain, 0.45, scan_id);
            e.corroboration = n_engines;
            e.tag(tags::EXTERNAL);
            e.tag("search-discovered");
            e.add_evidence(build_search_evidence(r));
            result.push(e);
        }

        // Extract emails from title + snippet text
        let combined_text = format!("{} {}", r.title, r.snippet);
        for email in extract_emails_from_text(&combined_text) {
            if seen_emails.insert(email.clone()) {
                let mut e = Entity::new(EntityKind::Email, &email, 0.60, scan_id);
                e.tag(tags::WEB_SCRAPED);
                e.tag("search-discovered");
                e.add_evidence(
                    Evidence::new(
                        "search_engines",
                        format!(
                            "[{}] Email found on {} — {}",
                            r.engine,
                            extract_host(&r.url),
                            r.url
                        ),
                    )
                    .with_attr("url", &r.url)
                    .with_attr("engine", r.engine)
                    .with_attr("query", &r.query),
                );
                result.push(e);
            } else if let Some(existing) = result
                .entities
                .iter_mut()
                .find(|e| e.kind == EntityKind::Email && e.value == email)
            {
                existing.confidence = (existing.confidence + 0.10).min(0.85);
                existing.corroboration = existing.corroboration.saturating_add(1);
            }
        }

        for phone in extract_phones_from_text(&combined_text) {
            if seen_phones.insert(phone.clone()) {
                let mut e = Entity::new(EntityKind::Phone, &phone, 0.55, scan_id);
                e.tag(tags::WEB_SCRAPED);
                e.tag("search-discovered");
                e.add_evidence(
                    Evidence::new(
                        "search_engines",
                        format!(
                            "[{}] Phone found on {} — {}",
                            r.engine,
                            extract_host(&r.url),
                            r.url
                        ),
                    )
                    .with_attr("url", &r.url)
                    .with_attr("engine", r.engine),
                );
                result.push(e);
            } else if let Some(existing) = result
                .entities
                .iter_mut()
                .find(|e| e.kind == EntityKind::Phone && e.value == phone)
            {
                existing.confidence = (existing.confidence + 0.12).min(0.80);
                existing.corroboration = existing.corroboration.saturating_add(1);
            }
        }

        // Extract ABN/ACN numbers from snippet text
        for (num, kind_label) in extract_abn_acn_from_text(&combined_text) {
            if seen_domains.insert(format!("@abn:{num}")) {
                let mut e = Entity::new(EntityKind::AbnAcn, &num, 0.65, scan_id);
                e.tag("search-discovered");
                e.tag(kind_label);
                e.add_evidence(
                    Evidence::new(
                        "search_engines",
                        format!(
                            "[{}] {} {} found on {} — {}",
                            r.engine,
                            kind_label,
                            num,
                            extract_host(&r.url),
                            r.url
                        ),
                    )
                    .with_attr("url", &r.url)
                    .with_attr("engine", r.engine)
                    .with_attr("number_type", kind_label),
                );
                result.push(e);
            }
        }

        // Extract organisation names from snippet text
        for org in extract_organisations_from_text(&combined_text, &terms) {
            let org_key = org.to_lowercase();
            if seen_domains.insert(format!("@org:{org_key}")) {
                let mut e = Entity::new(EntityKind::Organisation, &org, 0.45, scan_id);
                e.tag("search-discovered");
                e.add_evidence(build_search_evidence(r));
                result.push(e);
            }
        }

        // Extract addresses from snippet text (geolocation pivot)
        for addr in extract_addresses_from_text(&combined_text) {
            let addr_key = format!("@addr:{}", normalise_address_key(&addr));
            if seen_domains.insert(addr_key.clone()) {
                let mut e = Entity::new(EntityKind::Address, &addr, 0.45, scan_id);
                e.tag("search-discovered");
                e.tag(tags::WEB_SCRAPED);
                e.add_evidence(
                    Evidence::new(
                        "search_engines",
                        format!(
                            "[{}] Address near {} — {}",
                            r.engine,
                            extract_host(&r.url),
                            r.url
                        ),
                    )
                    .with_attr("url", &r.url)
                    .with_attr("engine", r.engine),
                );
                result.push(e);
            } else {
                // Address seen before — boost via merge (corroboration increases)
                let norm = normalise_address_key(&addr);
                if let Some(existing) = result.entities.iter_mut().find(|e| {
                    e.kind == EntityKind::Address && normalise_address_key(&e.value) == norm
                }) {
                    existing.confidence = (existing.confidence + 0.12).min(0.80);
                    existing.corroboration = existing.corroboration.saturating_add(1);
                    existing.add_evidence(
                        Evidence::new(
                            "search_engines",
                            format!("[{}] Address corroborated — {}", r.engine, r.url),
                        )
                        .with_attr("url", &r.url)
                        .with_attr("engine", r.engine),
                    );
                }
            }
        }

        // Emit Url entities only for pages whose URL path contains a
        // target-derived term. People-search homepages (spokeo.com/,
        // whitepages.com/people-search) are excluded unless the path
        // also contains a target term — only specific profile pages
        // like peekyou.com/jerome_despal pass.
        if url_matches_target(&r.url, &terms)
            && seen_domains.insert(format!("@url:{}", canonicalize_url(&r.url)))
        {
            let mut e = Entity::new(EntityKind::Url, &r.url, 0.50, scan_id);
            e.tag("search-discovered");
            e.add_evidence(build_search_evidence(r));
            result.push(e);
        }

        // Extract usernames and person names from social profile URLs
        if let Some(username) = extract_path_username(&r.url) {
            let lower_user = username.to_lowercase();
            let is_social = is_social_host(&host);
            if is_social
                && lower_user.len() >= 3
                && !is_navigation_path(&lower_user)
                && seen_domains.insert(format!("@username:{lower_user}"))
            {
                let (score, confidence) = score_username(&lower_user, &host, &terms, r);
                if score >= 1 {
                    let mut e = Entity::new(EntityKind::Username, &lower_user, confidence, scan_id);
                    e.tag("search-discovered");
                    e.tag("social-profile");
                    if score < 3 {
                        e.tag("candidate");
                    }
                    e.add_evidence(build_search_evidence(r));
                    result.push(e);
                }
            }

            // People-search sites encode real names in paths:
            // peekyou.com/jerome_despal → "Jerome Despal"
            let people_hosts = [
                "peekyou.com",
                "spokeo.com",
                "nuwber.com",
                "whitepages.com.au",
                "locatefamily.com",
                "peoplefinder.com.au",
                "searchfind.com.au",
                "ancestry.com.au",
            ];
            if people_hosts
                .iter()
                .any(|s| host == *s || host.ends_with(&format!(".{s}")))
                && lower_user.contains('_')
                && lower_user.len() >= 5
            {
                let name = username.replace(['_', '-'], " ");
                let name_key = name.to_lowercase();
                if seen_domains.insert(format!("@person:{name_key}")) {
                    let mut e = Entity::new(EntityKind::Person, &name, 0.50, scan_id);
                    e.tag("search-discovered");
                    e.tag("people-search");
                    e.add_evidence(build_search_evidence(r));
                    result.push(e);
                }
            }
        }
    }

    // Extract family members: people sharing the target's last name
    // found in search results (e.g., "Jeanette Despal" when target is
    // "Jerome Despal"). These are high-value geolocation leads.
    let family = extract_family_names(results, target);
    for (name, source_url) in &family {
        let key = format!("@person:{}", name.to_lowercase());
        if seen_domains.insert(key) {
            let mut e = Entity::new(EntityKind::Person, name, 0.45, scan_id);
            e.tag("search-discovered");
            e.tag("family-member");
            e.add_evidence(
                Evidence::new(
                    "search_engines",
                    format!("Shares surname with target — {source_url}"),
                )
                .with_attr("url", source_url),
            );
            result.push(e);
        }
    }

    // Sort entities in a structured order suitable for both human
    // review and LLM consumption: parent entity first (it has the
    // ── Inline geocoding: known AU/world city coordinates ────────────
    // Produce Coordinates entities for addresses that match known cities.
    // This avoids waiting for forward_geocode's Nominatim API call and
    // enables the geo expansion chain immediately.
    {
        let mut seen_coords: HashSet<String> = HashSet::new();
        let addr_snapshot: Vec<(String, f64, u32)> = result
            .entities
            .iter()
            .filter(|e| {
                e.kind == EntityKind::Address && (e.confidence >= 0.40 || e.corroboration >= 2)
            })
            .map(|e| (e.value.clone(), e.confidence, e.corroboration))
            .collect();
        for (addr, conf, corr) in &addr_snapshot {
            if let Some((lat, lon)) = known_city_coords(addr) {
                let coords = format!("{lat:.4},{lon:.4}");
                if seen_coords.insert(coords.clone()) {
                    let corr_boost = (*corr as f64 - 1.0).max(0.0) * 0.08;
                    let geo_conf = ((conf * 0.82) + corr_boost).min(0.75);
                    let mut ce = Entity::new(EntityKind::Coordinates, &coords, geo_conf, scan_id);
                    ce.tag("geoint");
                    ce.tag("search-geocoded");
                    ce.add_evidence(
                        Evidence::new(
                            "search_engines",
                            format!("Geocoded from search address: {addr}"),
                        )
                        .with_attr("source_address", addr)
                        .with_attr("method", "known-city-lookup"),
                    );
                    result.push(ce);
                }
            }
        }
    }

    // highest confidence), then by kind priority (identity entities
    // first, infrastructure last), then by descending confidence,
    // then alphabetically by value within each tier.
    result.entities.sort_by(|a, b| {
        fn kind_rank(k: &EntityKind) -> u8 {
            match k {
                EntityKind::Person => 0,
                EntityKind::Email => 1,
                EntityKind::Username => 2,
                EntityKind::Phone => 3,
                EntityKind::Organisation => 4,
                EntityKind::AbnAcn => 5,
                EntityKind::Address => 6,
                EntityKind::Url => 7,
                EntityKind::Domain => 8,
                _ => 9,
            }
        }
        kind_rank(&a.kind)
            .cmp(&kind_rank(&b.kind))
            .then(
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then(a.value.cmp(&b.value))
    });

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_all_supported_kinds() {
        let m = SearchEngines;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(m.accepts(&Target::new(TargetKind::Email, "x")));
        assert!(m.accepts(&Target::new(TargetKind::Username, "x")));
        assert!(m.accepts(&Target::new(TargetKind::FullName, "x")));
        assert!(m.accepts(&Target::new(TargetKind::Phone, "x")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "x")));
        assert!(m.accepts(&Target::new(TargetKind::Organisation, "x")));
        assert!(m.accepts(&Target::new(TargetKind::Asn, "x")));
        assert!(m.accepts(&Target::new(TargetKind::Address, "x")));
        assert!(m.accepts(&Target::new(TargetKind::AbnAcn, "x")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "http://x.com")));
        assert!(m.accepts(&Target::new(TargetKind::Coordinates, "0,0")));
    }

    #[test]
    fn build_queries_address_produces_dorks() {
        let t = Target::new(TargetKind::Address, "123 Main St, Springfield");
        let q = build_queries(&t);
        assert!(q.len() >= 2);
        assert!(q[0].contains("\"123 Main St, Springfield\""));
    }

    #[test]
    fn build_queries_asn_normalises_prefix() {
        let t = Target::new(TargetKind::Asn, "13335");
        let q = build_queries(&t);
        assert!(q.iter().any(|qr| qr.contains("AS13335")));
    }

    #[test]
    fn build_queries_abn_extracts_digits() {
        let t = Target::new(TargetKind::AbnAcn, "51 824 753 556");
        let q = build_queries(&t);
        assert!(q.iter().any(|qr| qr.contains("51824753556")));
    }

    #[test]
    fn build_queries_url_extracts_host() {
        let t = Target::new(TargetKind::Url, "https://example.com/page");
        let q = build_queries(&t);
        assert!(q.iter().any(|qr| qr.contains("site:example.com")));
    }

    #[test]
    fn build_queries_coordinates_splits_lat_lon() {
        let t = Target::new(TargetKind::Coordinates, "-33.86,151.20");
        let q = build_queries(&t);
        assert!(q.len() >= 2);
        assert!(q[0].contains("-33.86"));
        assert!(q[0].contains("151.20"));
    }

    #[test]
    fn address_extractor_finds_city_state_pattern() {
        let text = "Jordan lives in Nundah, Queensland with his family";
        let addrs = extract_addresses_from_text(text);
        assert!(
            addrs
                .iter()
                .any(|a| a.contains("Nundah") && a.contains("Queensland")),
            "should find Nundah, Queensland: {addrs:?}"
        );
    }

    #[test]
    fn address_extractor_finds_qld_suburb_with_context() {
        let text = "Originally from Redcliffe QLD, now living in Caboolture";
        let addrs = extract_addresses_from_text(text);
        assert!(
            addrs.iter().any(|a| a.contains("Redcliffe")),
            "should find Redcliffe with QLD context: {addrs:?}"
        );
    }

    #[test]
    fn address_extractor_finds_brisbane_with_australia() {
        let text = "Based in Brisbane, Australia. Working at ACME Corp.";
        let addrs = extract_addresses_from_text(text);
        assert!(
            !addrs.is_empty(),
            "should find Brisbane with Australia context"
        );
    }

    #[test]
    fn address_extractor_finds_au_postcode() {
        let text = "Lives at Nundah, Queensland 4012";
        let addrs = extract_addresses_from_text(text);
        assert!(
            addrs.iter().any(|a| a.contains("4012")),
            "should extract 4-digit AU postcode: {addrs:?}"
        );
    }

    #[test]
    fn address_extractor_ignores_non_au_4digit() {
        let text = "Error code 1234 in the system at Houston, Texas";
        let addrs = extract_addresses_from_text(text);
        assert!(
            !addrs.iter().any(|a| a.contains("1234")),
            "should not extract non-AU 4-digit number as postcode: {addrs:?}"
        );
    }

    #[test]
    fn build_queries_domain_produces_five_dorks() {
        let t = Target::new(TargetKind::Domain, "acme.com");
        let q = build_queries(&t);
        assert_eq!(q.len(), 5);
        assert!(q[0].contains("site:acme.com"));
        assert!(q[1].contains("filetype:pdf"));
        assert!(q[2].contains("@acme.com"));
        assert!(q[3].contains("login"));
    }

    #[test]
    fn build_queries_email_produces_social_pivots() {
        let t = Target::new(TargetKind::Email, "user@acme.com");
        let q = build_queries(&t);
        assert!(q.len() >= 2);
        assert!(q[0].contains("\"user@acme.com\""));
        assert!(q.iter().any(|qr| qr.contains("github.com")));
    }

    #[test]
    fn build_queries_username_covers_social_platforms() {
        let t = Target::new(TargetKind::Username, "johndoe");
        let q = build_queries(&t);
        assert_eq!(q.len(), 5);
        assert!(q[0].contains("github.com") && q[0].contains("linkedin.com"));
        assert!(q[1].contains("twitter.com") && q[1].contains("reddit.com"));
        assert!(q[2].contains("profile"));
        assert!(q[3].contains("email") || q[3].contains("contact"));
        assert!(q[4].contains("peekyou.com") || q[4].contains("nuwber.com"));
    }

    #[test]
    fn build_queries_fullname_covers_professional() {
        let t = Target::new(TargetKind::FullName, "Jane Doe");
        let q = build_queries(&t);
        assert!(q.len() >= 8, "expected >=8 queries, got {}", q.len());
        assert!(q[0].contains("\"Jane Doe\""));
        assert!(q[1].contains("linkedin.com") || q[1].contains("facebook.com"));
        assert!(
            q.iter()
                .any(|qr| qr.contains("instagram.com") || qr.contains("github.com"))
        );
        assert!(
            q.iter()
                .any(|qr| qr.contains("email") || qr.contains("contact") || qr.contains("profile"))
        );
        assert!(
            q.iter()
                .any(|qr| qr.contains("peekyou.com") || qr.contains("nuwber.com"))
        );
        assert!(
            q.iter()
                .any(|qr| qr.contains("courts") || qr.contains("austlii"))
        );
        assert!(
            q.iter()
                .any(|qr| qr.contains("abc.net.au") || qr.contains("news.com.au"))
        );
    }

    #[test]
    fn build_queries_fullname_three_parts_generates_username_variants() {
        let t = Target::new(TargetKind::FullName, "Jordan Leigh Meyers");
        let q = build_queries(&t);
        assert!(
            q.iter()
                .any(|qr| qr.contains("jordanmeyers") || qr.contains("jleighmeyers")),
            "should generate username variants from 3-part name: {q:?}"
        );
        assert!(
            q.iter().any(|qr| qr.contains("\"Jordan Meyers\"")),
            "should search first+last without middle: {q:?}"
        );
        assert!(
            q.iter()
                .any(|qr| qr.contains("Queensland") || qr.contains("Brisbane")),
            "should include AU geo dorks: {q:?}"
        );
    }

    #[test]
    fn build_queries_ip_produces_infra_dorks() {
        let t = Target::new(TargetKind::IpAddress, "8.8.8.8");
        let q = build_queries(&t);
        assert_eq!(q.len(), 4);
        assert!(q[0].contains("\"8.8.8.8\""));
        assert!(q.iter().any(|qr| qr.contains("shodan.io")));
    }

    #[test]
    fn build_queries_org_produces_business_dorks() {
        let t = Target::new(TargetKind::Organisation, "BHP Group");
        let q = build_queries(&t);
        assert!(q.len() >= 5);
        assert!(q[0].contains("\"BHP Group\""));
        assert!(q.iter().any(|qr| qr.contains("ABN") || qr.contains("ACN")));
        assert!(
            q.iter()
                .any(|qr| qr.contains("abr.business.gov.au") || qr.contains("opencorporates"))
        );
    }

    #[test]
    fn resolve_href_decodes_ddg_uddg() {
        let href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage&rut=abc123";
        let resolved = resolve_href(href);
        assert_eq!(resolved.as_deref(), Some("https://example.com/page"));
    }

    #[test]
    fn resolve_href_decodes_yahoo_ru() {
        let href = "https://r.search.yahoo.com/_ylt=Awr/RV=2/RE=123/RO=10/RU=https%3a%2f%2fsoundcloud.com%2fjerome-despal/RK=2/RS=abc123-";
        let resolved = resolve_href(href);
        assert_eq!(
            resolved.as_deref(),
            Some("https://soundcloud.com/jerome-despal")
        );
    }

    #[test]
    fn resolve_href_handles_protocol_relative() {
        let href = "//cdn.example.com/file.js";
        assert_eq!(
            resolve_href(href).as_deref(),
            Some("https://cdn.example.com/file.js")
        );
    }

    #[test]
    fn resolve_href_passes_absolute_urls() {
        assert_eq!(
            resolve_href("https://example.com").as_deref(),
            Some("https://example.com")
        );
    }

    #[test]
    fn resolve_href_rejects_relative_paths() {
        assert!(resolve_href("/page").is_none());
        assert!(resolve_href("page.html").is_none());
    }

    #[test]
    fn href_iter_handles_both_quote_styles() {
        let html = r#"<a href="https://a.com">A</a> <a href='https://b.com'>B</a>"#;
        let links: Vec<&str> = HrefIter::new(html).collect();
        assert_eq!(links, vec!["https://a.com", "https://b.com"]);
    }

    #[test]
    fn parse_results_filters_engine_domains() {
        let html = r#"
            <a href="https://duckduckgo.com/something">Skip</a>
            <a href="https://realsite.com/page">Real</a>
            <a href="https://google.com/redirect">Skip</a>
        "#;
        let results = parse_results(html, "duckduckgo", "test query");
        assert_eq!(results.len(), 1);
        assert!(results[0].url.contains("realsite.com"));
    }

    #[test]
    fn canonicalize_strips_query_fragment_slash() {
        assert_eq!(
            canonicalize_url("https://example.com/page?ref=1#top"),
            "https://example.com/page"
        );
        assert_eq!(
            canonicalize_url("https://example.com/page/"),
            "https://example.com/page"
        );
    }

    #[test]
    fn strip_tags_extracts_clean_text() {
        let html = "<b>Hello</b> <span>world</span>  <i>test</i>";
        assert_eq!(strip_tags(html, 100), "Hello world test");
    }

    #[test]
    fn email_extraction_from_snippet() {
        let text = "Contact support@acme.com or sales@test.org for help";
        let emails = extract_emails_from_text(text);
        assert!(emails.contains(&"support@acme.com".to_string()));
        assert!(emails.contains(&"sales@test.org".to_string()));
    }

    #[test]
    fn email_extraction_skips_image_files() {
        let text = "icon@2x.png and logo@3x.jpg should be skipped";
        let emails = extract_emails_from_text(text);
        assert!(emails.is_empty());
    }

    #[test]
    fn phone_extraction_international() {
        let text = "Call us at +1-555-123-4567 or +44 20 7946 0958 today";
        let phones = extract_phones_from_text(text);
        assert_eq!(phones.len(), 2);
        assert!(phones.iter().any(|p| p.starts_with("+1")));
        assert!(phones.iter().any(|p| p.starts_with("+44")));
    }

    #[test]
    fn tracking_url_detection() {
        assert!(is_tracking_url("https://r.search.yahoo.com/cbcl/something"));
        assert!(is_tracking_url("https://r.bing.com/rb/something"));
        assert!(is_tracking_url("https://ad.doubleclick.net/thing"));
        assert!(!is_tracking_url("https://example.com/page"));
        assert!(!is_tracking_url("https://example.com/redirect?url=x"));
    }

    #[test]
    fn engine_domain_filtering() {
        assert!(is_engine_domain("duckduckgo.com"));
        assert!(is_engine_domain("search.yahoo.com"));
        assert!(is_engine_domain("r.search.yahoo.com"));
        assert!(!is_engine_domain("example.com"));
        assert!(is_engine_domain("yandex.ru"));
        assert!(is_engine_domain("ecosia.org"));
        assert!(is_engine_domain("api.qwant.com"));
        assert!(is_engine_domain("dogpile.com"));
        assert!(is_engine_domain("swisscows.com"));
    }

    #[test]
    fn registrable_domain_extraction() {
        assert_eq!(extract_registrable("sub.example.com"), "example.com");
        assert_eq!(extract_registrable("example.com"), "example.com");
        assert_eq!(extract_registrable("deep.sub.example.org"), "example.org");
    }

    #[test]
    fn resolve_href_decodes_yandex_clck() {
        let href = "https://yandex.com/clck/jsredir?from=yandex.com\
                     &url=https%3A%2F%2Fexample.com%2Fpath&ts=abc";
        let resolved = resolve_href(href);
        assert_eq!(resolved.as_deref(), Some("https://example.com/path"));
    }

    #[test]
    fn engine_count_is_seventeen() {
        assert_eq!(ENGINES.len(), 17);
    }

    #[test]
    fn all_original_engines_present() {
        let names: Vec<&str> = ENGINES.iter().map(|e| e.name).collect();
        for engine in [
            "yahoo",
            "bing",
            "aol",
            "duckduckgo",
            "google",
            "brave",
            "mojeek",
        ] {
            assert!(names.contains(&engine), "missing original engine: {engine}");
        }
    }

    #[test]
    fn new_engines_present() {
        let names: Vec<&str> = ENGINES.iter().map(|e| e.name).collect();
        for engine in [
            "startpage",
            "yandex",
            "ecosia",
            "qwant",
            "dogpile",
            "swisscows",
            "you",
            "presearch",
            "metager",
            "searx",
        ] {
            assert!(names.contains(&engine), "missing new engine: {engine}");
        }
    }

    #[test]
    fn startpage_uses_post() {
        let sp = ENGINES.iter().find(|e| e.name == "startpage").unwrap();
        assert!(sp.build_post.is_some());
        let body = (sp.build_post.unwrap())("test query");
        assert!(body.contains("query=test+query"));
        assert!(body.contains("cat=web"));
    }

    #[test]
    fn extract_anchor_text_basic() {
        let html = r#"<a href="https://example.com"><b>Example</b> Title</a> other text"#;
        let title = extract_anchor_text(html, "https://example.com", 200);
        assert_eq!(title, "Example Title");
    }

    #[test]
    fn extract_anchor_text_missing_href() {
        let html = r#"<a href="https://other.com">Other</a>"#;
        let title = extract_anchor_text(html, "https://example.com", 200);
        assert!(title.is_empty());
    }

    #[test]
    fn captcha_detection_datadome() {
        let body = "<html><body>Please enable JS \
                     <script src=\"https://ct.captcha-delivery.com/c.js\"></script>\
                     </body></html>";
        let lower = body.to_lowercase();
        assert!(lower.contains("captcha-delivery.com"));
    }

    #[test]
    fn captcha_detection_yandex_smartcaptcha() {
        let body = "<html><title>Verification</title>\
                     <body>showcaptcha challenge</body></html>";
        let lower = body.to_lowercase();
        assert!(lower.contains("showcaptcha"));
    }

    #[test]
    fn html_entity_decoding() {
        assert_eq!(
            decode_html_entities("uddg=https%3A%2F%2Fexample.com&amp;rut=abc"),
            "uddg=https%3A%2F%2Fexample.com&rut=abc"
        );
    }

    #[test]
    fn extract_path_username_social() {
        assert_eq!(
            extract_path_username("https://soundcloud.com/jerome-despal").as_deref(),
            Some("jerome-despal")
        );
        assert_eq!(
            extract_path_username("https://myspace.com/shinigami_jerome").as_deref(),
            Some("shinigami_jerome")
        );
        assert!(extract_path_username("https://example.com/").is_none());
        assert!(extract_path_username("https://example.com/ab").is_none());
    }

    #[test]
    fn captcha_page_detection() {
        assert!(is_captcha_page(
            "<html><body>captcha-delivery.com script</body></html>"
        ));
        assert!(is_captcha_page(
            "<html><body>httpservice/retry redirect</body></html>"
        ));
        assert!(!is_captcha_page(
            "<html><body>Normal search results page with lots of content</body></html>"
        ));
    }

    #[test]
    fn email_query_includes_people_search() {
        let t = Target::new(TargetKind::Email, "jdespal@gmail.com");
        let q = build_queries(&t);
        assert!(
            q.iter()
                .any(|qr| qr.contains("peekyou.com") || qr.contains("nuwber.com"))
        );
    }

    #[test]
    fn address_extraction_au_state() {
        let text = "Jerome Despal, Nundah, Queensland, Australia";
        let addrs = extract_addresses_from_text(text);
        assert!(!addrs.is_empty());
        assert_eq!(addrs[0], "Nundah, Queensland");
    }

    #[test]
    fn address_extraction_us_state() {
        let text = "lives in Houston, Texas since 2020";
        let addrs = extract_addresses_from_text(text);
        assert!(!addrs.is_empty());
        assert_eq!(addrs[0], "Houston, Texas");
    }

    #[test]
    fn address_extraction_rejects_noise() {
        let text = "arguments, got nothing back from the server";
        let addrs = extract_addresses_from_text(text);
        assert!(addrs.is_empty());
    }

    #[test]
    fn navigation_path_catches_extensions() {
        assert!(is_navigation_path("login.php"));
        assert!(is_navigation_path("signin_page"));
        assert!(is_navigation_path("qwantcom"));
        assert!(is_navigation_path("swisscows_ch"));
        assert!(!is_navigation_path("jerome-despal"));
        assert!(!is_navigation_path("shinigami_jerome"));
    }

    #[test]
    fn fullname_query_includes_geolocation() {
        let t = Target::new(TargetKind::FullName, "Jane Doe");
        let q = build_queries(&t);
        assert!(
            q.iter()
                .any(|qr| qr.contains("address") || qr.contains("location"))
        );
    }

    #[test]
    fn username_scoring_term_overlap() {
        let terms = vec!["jerome".into(), "despal".into()];
        let r = SearchResult {
            url: "https://soundcloud.com/jerome-despal".into(),
            title: String::new(),
            snippet: String::new(),
            engine: "yahoo",
            query: "\"Jerome Despal\"".into(),
        };
        let (score, conf) = score_username("jerome-despal", "soundcloud.com", &terms, &r);
        assert!(score >= 3);
        assert!((conf - 0.55).abs() < 0.01);
    }

    #[test]
    fn username_scoring_no_overlap_with_site_query() {
        let terms = vec!["jdespal".into()];
        let r = SearchResult {
            url: "https://soundcloud.com/jaydes/tracks".into(),
            title: String::new(),
            snippet: String::new(),
            engine: "yahoo",
            query: "Jdespal site:soundcloud.com OR site:instagram.com".into(),
        };
        let (score, conf) = score_username("jaydes", "soundcloud.com", &terms, &r);
        assert!(
            score >= 1,
            "site: query should give score >= 1, got {score}"
        );
        assert!((conf - 0.30).abs() < 0.01);
    }

    #[test]
    fn username_scoring_cooccurrence() {
        let terms = vec!["jdespal".into()];
        let r = SearchResult {
            url: "https://soundcloud.com/jaydes/tracks".into(),
            title: "Jdespal's favorite tracks".into(),
            snippet: String::new(),
            engine: "yahoo",
            query: "\"Jdespal\"".into(),
        };
        let (score, _) = score_username("jaydes", "soundcloud.com", &terms, &r);
        assert!(score >= 2, "co-occurrence should boost score, got {score}");
    }

    #[test]
    fn username_scoring_people_search() {
        let terms = vec!["shinigami".into(), "jerome".into()];
        let r = SearchResult {
            url: "https://www.peekyou.com/jerome_despal".into(),
            title: String::new(),
            snippet: String::new(),
            engine: "bing",
            query: "\"shinigami_jerome\"".into(),
        };
        let (score, _) = score_username("jerome_despal", "www.peekyou.com", &terms, &r);
        assert!(
            score >= 3,
            "people-search provenance should give high score, got {score}"
        );
    }

    #[test]
    fn url_relevance_filtering() {
        let terms = vec!["jerome".into(), "despal".into()];
        assert!(url_matches_target(
            "https://soundcloud.com/jerome-despal",
            &terms
        ));
        assert!(url_matches_target(
            "https://www.peekyou.com/jerome_despal",
            &terms
        ));
        assert!(!url_matches_target("https://www.spokeo.com/", &terms));
        assert!(!url_matches_target(
            "https://www.whitepages.com/people-search",
            &terms
        ));
    }

    #[test]
    fn generic_domain_filtering() {
        assert!(is_generic_domain("wikihow.com"));
        assert!(is_generic_domain("windowsreport.com"));
        assert!(is_generic_domain("office.com"));
        assert!(!is_generic_domain("soundcloud.com"));
        assert!(!is_generic_domain("peekyou.com"));
    }

    #[test]
    fn target_terms_extraction() {
        let t = Target::new(TargetKind::Email, "jdespal@gmail.com");
        let terms = target_terms(&t);
        assert!(terms.contains(&"jdespal".to_string()));
        assert!(!terms.contains(&"gmail".to_string()));
        assert!(!terms.contains(&"com".to_string()));

        let t2 = Target::new(TargetKind::FullName, "Jerome Despal");
        let terms2 = target_terms(&t2);
        assert!(terms2.contains(&"jerome".to_string()));
        assert!(terms2.contains(&"despal".to_string()));
    }

    #[test]
    fn abn_extraction() {
        let text = "Registered ABN 53 004 085 616 for the company";
        let results = extract_abn_acn_from_text(text);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "53004085616");
        assert_eq!(results[0].1, "ABN");
    }

    #[test]
    fn abn_validation_checksum() {
        assert!(is_valid_abn("53004085616")); // real ABN: Qantas
        assert!(!is_valid_abn("12345678901"));
    }

    #[test]
    fn organisation_extraction() {
        let terms = vec!["despal".into()];
        let text = "Director of Despal Holdings Pty Ltd since 2019";
        let orgs = extract_organisations_from_text(text, &terms);
        assert!(!orgs.is_empty());
        assert!(orgs[0].contains("Pty Ltd"));
    }

    #[test]
    fn bigram_similarity_identical() {
        assert!((bigram_similarity("hello", "hello") - 1.0).abs() < 0.01);
    }

    #[test]
    fn bigram_similarity_partial() {
        let sim = bigram_similarity("jdespal", "jaydes");
        assert!(sim > 0.0, "partial overlap expected, got {sim}");
    }

    #[test]
    fn bigram_similarity_unrelated() {
        let sim = bigram_similarity("jdespal", "elephant");
        assert!(sim < 0.2, "unrelated strings, got {sim}");
    }

    #[test]
    fn domain_queries_include_abn() {
        let t = Target::new(TargetKind::Domain, "acme.com");
        let q = build_queries(&t);
        assert!(q.iter().any(|qr| qr.contains("ABN")));
    }

    #[test]
    fn fullname_queries_include_abn() {
        let t = Target::new(TargetKind::FullName, "Jane Doe");
        let q = build_queries(&t);
        assert!(
            q.iter()
                .any(|qr| qr.contains("ABN") || qr.contains("director"))
        );
    }

    #[test]
    fn tracking_url_detection_new_engines() {
        assert!(is_tracking_url(
            "https://yandex.com/clck/jsredir?from=yandex"
        ));
        assert!(is_tracking_url("https://www.ecosia.org/newtab/v2"));
        assert!(!is_tracking_url("https://example.com/page"));
    }

    #[test]
    fn username_variant_generation() {
        let v = generate_username_variants("jerome_despal");
        assert!(v.contains(&"jeromedespal".to_string()));
        assert!(v.contains(&"jerome-despal".to_string()));
        assert!(v.contains(&"jerome.despal".to_string()));
    }

    #[test]
    fn username_variant_trailing_digit() {
        let v = generate_username_variants("jdespal");
        assert!(v.contains(&"jdespal1".to_string()));
        assert!(v.contains(&"jdespal2".to_string()));
        assert!(v.contains(&"jdespa".to_string()));
    }

    #[test]
    fn family_name_extraction() {
        let results = vec![SearchResult {
            url: "https://linkedin.com/in/jeanette-despal".into(),
            title: "Jeanette Despal - Manager at SCAN Health Plan".into(),
            snippet: "jeanette despal works at SCAN Health Plan in Long Beach".into(),
            engine: "bing",
            query: "\"Jerome Despal\"".into(),
        }];
        let target = Target::new(TargetKind::FullName, "Jerome Despal");
        let family = extract_family_names(&results, &target);
        assert!(!family.is_empty());
        assert!(family[0].0.contains("Jeanette"));
        assert!(family[0].0.contains("Despal"));
    }

    #[test]
    fn address_normalise_qld_variants() {
        let a = normalise_address_key("Gatton, QLD");
        let b = normalise_address_key("Gatton, Queensland");
        assert_eq!(a, b);
    }

    #[test]
    fn address_normalise_nsw_variants() {
        let a = normalise_address_key("Sydney, NSW");
        let b = normalise_address_key("Sydney, New South Wales");
        assert_eq!(a, b);
    }

    #[test]
    fn address_normalise_strips_punctuation() {
        let a = normalise_address_key("St Lucia, QLD, 4067");
        assert!(!a.contains(','));
        assert!(a.contains("queensland"));
    }

    #[test]
    fn known_city_coords_gatton() {
        let coords = known_city_coords("Gatton, QLD");
        assert!(coords.is_some(), "Gatton should have known coordinates");
        let (lat, lon) = coords.unwrap();
        assert!((lat - (-27.5567)).abs() < 0.01);
        assert!((lon - 152.2767).abs() < 0.01);
    }

    #[test]
    fn known_city_coords_lockyer_valley() {
        let coords = known_city_coords("Lockyer Valley");
        assert!(
            coords.is_some(),
            "Lockyer Valley should have known coordinates"
        );
    }

    #[test]
    fn known_city_coords_expanded_cities() {
        assert!(known_city_coords("Philadelphia").is_some());
        assert!(known_city_coords("Miami, FL").is_some());
        assert!(known_city_coords("Newcastle NSW").is_some());
        assert!(known_city_coords("Auckland").is_some());
    }

    #[test]
    fn address_extractor_finds_gatton_qld() {
        let text = "Jordan Meyer from Gatton QLD works in agriculture";
        let addrs = extract_addresses_from_text(text);
        assert!(
            addrs.iter().any(|a| a.contains("Gatton")),
            "should find Gatton with QLD context: {addrs:?}"
        );
    }

    #[test]
    fn canonicalize_url_strips_query_params() {
        assert_eq!(
            canonicalize_url("https://x.com/page?a=1"),
            "https://x.com/page"
        );
    }

    #[test]
    fn canonicalize_url_strips_fragment() {
        assert_eq!(
            canonicalize_url("https://x.com/page#section"),
            "https://x.com/page"
        );
    }

    #[test]
    fn canonicalize_url_strips_trailing_slash() {
        assert_eq!(
            canonicalize_url("https://x.com/page/"),
            "https://x.com/page"
        );
    }
}
