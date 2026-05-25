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

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};

pub struct SearchEngines;

const MAX_RESULTS_PER_ENGINE: usize = 20;
const INTER_ENGINE_MS: u64 = 400;

struct SearchResult {
    url: String,
    title: String,
    snippet: String,
    engine: &'static str,
    query: String,
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

            for engine in ENGINES {
                if ctx.cancel.is_cancelled() {
                    break;
                }
                if qi > 0 && dead_engines.contains(engine.name) {
                    continue;
                }
                let url = (engine.build_url)(query);
                let post_body = engine.build_post.map(|f| f(query));
                let before = all_results.len();
                if let Some(mut results) =
                    fetch_and_parse(&url, engine, query, post_body.as_deref()).await
                {
                    all_results.append(&mut results);
                } else if qi == 0 {
                    dead_engines.insert(engine.name);
                }
                if all_results.len() > before {
                    tokio::time::sleep(std::time::Duration::from_millis(INTER_ENGINE_MS)).await;
                }
            }
        }

        // ── Secondary pivot: extract usernames from result URLs and
        //    re-search on the top-3 most reliable engines ────────────
        if !ctx.cancel.is_cancelled() {
            let pivots = extract_username_pivots(&all_results, target);
            if !pivots.is_empty() {
                let reliable = [&ENGINES[0], &ENGINES[1], &ENGINES[5]]; // yahoo, bing, brave
                for pivot_query in pivots.iter().take(3) {
                    if ctx.cancel.is_cancelled() {
                        break;
                    }
                    for engine in &reliable {
                        if ctx.cancel.is_cancelled() {
                            break;
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

        let mut module_result = build_entities(target, &ctx.scan_id, &all_results);

        // ── API enrichment pass: batch-query OathNet for high-confidence
        //    discovered entities. Only fires when the API key is configured
        //    and we have entities worth enriching. Maximises value from
        //    free results before spending API credits. ──────────────────
        if !ctx.cancel.is_cancelled() {
            enrich_via_oathnet(ctx, &mut module_result).await;
        }

        Ok(module_result)
    }
}

// ─── Engine definitions ─────────────────────────────────────────────────────

struct EngineSpec {
    name: &'static str,
    build_url: fn(&str) -> String,
    build_post: Option<fn(&str) -> String>,
    /// Preferred User-Agent class for this engine.
    ua: &'static str,
    /// Fallback User-Agent to retry when the primary UA gets blocked.
    ua_alt: &'static str,
}

// All 13 engines are always tried. Blocked engines are detected and
// skipped in <1s via the interstitial detector in fetch_and_parse.
// Yahoo/Bing are most reliable from datacenter IPs. DDG/Google/Brave
// work best from residential IPs (Termux). AOL is Yahoo-powered (same
// /RU= format). Mojeek has an independent index.
//
// New engines (2026): Startpage (POST, Google-sourced), Yandex
// (independent Russian index), Ecosia (Bing-powered), Qwant (European
// privacy engine), Dogpile (System1 meta-aggregator), Swisscows
// (Swiss Bing-powered). These may be CAPTCHA-blocked from datacenter
// IPs but work from Termux residential connections.
const ENGINES: &[EngineSpec] = &[
    // ── Original 7 engines ──────────────────────────────────────────
    EngineSpec {
        name: "yahoo",
        build_url: |q| {
            format!(
                "https://search.yahoo.com/search?p={}&n=20",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        ua: crate::util::curl::UA_MOBILE,
        ua_alt: crate::util::curl::UA_DESKTOP,
    },
    EngineSpec {
        name: "bing",
        build_url: |q| {
            format!(
                "https://www.bing.com/search?q={}&count=30",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        ua: crate::util::curl::UA_MOBILE,
        ua_alt: crate::util::curl::UA_DESKTOP,
    },
    EngineSpec {
        name: "aol",
        build_url: |q| {
            format!(
                "https://search.aol.com/aol/search?q={}",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        ua: crate::util::curl::UA_MOBILE,
        ua_alt: crate::util::curl::UA_DESKTOP,
    },
    EngineSpec {
        name: "duckduckgo",
        build_url: |_q| "https://html.duckduckgo.com/html/".to_string(),
        build_post: Some(|q| format!("q={}&b=&kl=us-en&df=", crate::util::http::urlencode(q))),
        ua: crate::util::curl::UA_FIREFOX,
        ua_alt: crate::util::curl::UA_DESKTOP,
    },
    EngineSpec {
        name: "google",
        build_url: |q| {
            format!(
                "https://www.google.com/search?q={}&num=20",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        ua: crate::util::curl::UA_MOBILE,
        ua_alt: crate::util::curl::UA_DESKTOP,
    },
    EngineSpec {
        name: "brave",
        build_url: |q| {
            format!(
                "https://search.brave.com/search?q={}",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        ua: crate::util::curl::UA_DESKTOP,
        ua_alt: crate::util::curl::UA_SAFARI,
    },
    EngineSpec {
        name: "mojeek",
        build_url: |q| {
            format!(
                "https://www.mojeek.com/search?q={}",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        ua: crate::util::curl::UA_DESKTOP,
        ua_alt: crate::util::curl::UA_MOBILE,
    },
    // ── New engines (2026) ──────────────────────────────────────────
    EngineSpec {
        name: "startpage",
        build_url: |_q| "https://www.startpage.com/sp/search".to_string(),
        build_post: Some(|q| {
            format!(
                "query={}&cat=web&abp=1&abd=1&abe=1",
                crate::util::http::urlencode(q)
            )
        }),
        ua: crate::util::curl::UA_FIREFOX,
        ua_alt: crate::util::curl::UA_DESKTOP,
    },
    EngineSpec {
        name: "yandex",
        build_url: |q| {
            format!(
                "https://yandex.com/search/?text={}&lr=84",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        ua: crate::util::curl::UA_DESKTOP,
        ua_alt: crate::util::curl::UA_MOBILE,
    },
    EngineSpec {
        name: "ecosia",
        build_url: |q| {
            format!(
                "https://www.ecosia.org/search?method=index&q={}",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        ua: crate::util::curl::UA_FIREFOX,
        ua_alt: crate::util::curl::UA_SAFARI,
    },
    EngineSpec {
        name: "qwant",
        build_url: |q| {
            format!(
                "https://lite.qwant.com/?q={}&t=web",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        ua: crate::util::curl::UA_FIREFOX,
        ua_alt: crate::util::curl::UA_DESKTOP,
    },
    EngineSpec {
        name: "dogpile",
        build_url: |q| {
            format!(
                "https://www.dogpile.com/serp?q={}",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        ua: crate::util::curl::UA_DESKTOP,
        ua_alt: crate::util::curl::UA_SAFARI,
    },
    EngineSpec {
        name: "swisscows",
        build_url: |q| {
            format!(
                "https://swisscows.com/en/web?query={}",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        ua: crate::util::curl::UA_DESKTOP,
        ua_alt: crate::util::curl::UA_FIREFOX,
    },
];

// ─── API enrichment: OathNet batch breach lookups ──────────────────────────

const OATHNET_KEY_ENV: &str = "HUNTSMAN_OATHNET_KEY";
const OATHNET_ENDPOINT: &str = "https://oathnet.org/api/service/v2/breach/search";

#[derive(serde::Deserialize)]
struct OathEnvelope {
    data: Option<OathData>,
}

#[derive(serde::Deserialize)]
struct OathData {
    #[serde(default)]
    items: Vec<OathItem>,
}

#[derive(serde::Deserialize)]
struct OathItem {
    #[serde(default)]
    dbname: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    phone: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

async fn enrich_via_oathnet(ctx: &ModuleContext, result: &mut ModuleResult) {
    let key = match ctx.key_opt(OATHNET_KEY_ENV) {
        Some(k) if !k.is_empty() => k,
        _ => return,
    };

    // Collect high-confidence emails and usernames (PROBABLE tier,
    // confidence ≥ 0.50) worth spending API credits on.
    let mut emails: Vec<String> = Vec::new();
    let mut usernames: Vec<String> = Vec::new();
    for e in &result.entities {
        if e.confidence < 0.50 {
            continue;
        }
        match e.kind {
            EntityKind::Email => {
                if emails.len() < 10 {
                    emails.push(e.value.clone());
                }
            }
            EntityKind::Username => {
                if usernames.len() < 5 {
                    usernames.push(e.value.clone());
                }
            }
            _ => {}
        }
    }

    if emails.is_empty() && usernames.is_empty() {
        return;
    }

    let scan_id = result
        .entities
        .first()
        .map(|e| e.scan_id.clone())
        .unwrap_or_default();

    for email in &emails {
        if ctx.cancel.is_cancelled() {
            break;
        }
        if let Some(hits) = oathnet_lookup(&ctx.http, key, "email", email).await {
            apply_breach_evidence(result, email, &hits, &scan_id);
        }
    }

    for uname in &usernames {
        if ctx.cancel.is_cancelled() {
            break;
        }
        if let Some(hits) = oathnet_lookup(&ctx.http, key, "username", uname).await {
            apply_breach_evidence(result, uname, &hits, &scan_id);
        }
    }
}

async fn oathnet_lookup(
    http: &reqwest::Client,
    key: &str,
    field: &str,
    value: &str,
) -> Option<Vec<OathItem>> {
    let param = format!("{field}[]");
    let resp = http
        .get(OATHNET_ENDPOINT)
        .header("x-api-key", key)
        .query(&[(param.as_str(), value), ("page_size", "20")])
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let env: OathEnvelope = resp.json().await.ok()?;
    let data = env.data?;
    if data.items.is_empty() {
        return None;
    }
    Some(data.items)
}

fn apply_breach_evidence(
    result: &mut ModuleResult,
    lookup_value: &str,
    items: &[OathItem],
    scan_id: &str,
) {
    let total = items.len();
    let top_dbs: Vec<&str> = items
        .iter()
        .filter_map(|i| i.dbname.as_deref())
        .take(5)
        .collect();
    let summary = format!(
        "OathNet breach: {total} record(s) for {lookup_value} — {}",
        if top_dbs.is_empty() {
            "no dbnames".to_string()
        } else {
            top_dbs.join(", ")
        }
    );

    // Tag the existing entity with breach data if it matches
    let lookup_lower = lookup_value.to_lowercase();
    for e in &mut result.entities {
        if e.value.to_lowercase() == lookup_lower {
            e.tag(tags::BREACH);
            e.tag("oathnet-enriched");
            if e.confidence < 0.70 {
                e.confidence = 0.70;
            }
            e.add_evidence(
                Evidence::new("search_engines:oathnet", &summary)
                    .with_attr("breach_hits", total.to_string())
                    .with_attr("top_dbnames", top_dbs.join(", "))
                    .with_attr("lookup_value", lookup_value),
            );
        }
    }

    let mut seen: HashSet<String> = result
        .entities
        .iter()
        .map(|e| e.value.to_lowercase())
        .collect();
    let mut new_ents: Vec<Entity> = Vec::new();
    for item in items {
        let db = item.dbname.as_deref().unwrap_or("unknown");
        if let Some(email) = &item.email {
            let lower = email.to_lowercase();
            if lower.contains('@') && lower.len() >= 5 && seen.insert(lower) {
                let mut e = Entity::new(EntityKind::Email, email, 0.65, scan_id);
                e.tag(tags::BREACH);
                e.tag("oathnet-enriched");
                e.add_evidence(
                    Evidence::new(
                        "search_engines:oathnet",
                        format!("Breach record linked to {lookup_value}"),
                    )
                    .with_attr("dbname", db),
                );
                new_ents.push(e);
            }
        }
        if let Some(uname) = &item.username {
            let lower = uname.to_lowercase();
            if lower.len() >= 3 && !is_navigation_path(&lower) && seen.insert(lower) {
                let mut e = Entity::new(EntityKind::Username, uname, 0.60, scan_id);
                e.tag(tags::BREACH);
                e.tag("oathnet-enriched");
                e.add_evidence(
                    Evidence::new(
                        "search_engines:oathnet",
                        format!("Breach username linked to {lookup_value}"),
                    )
                    .with_attr("dbname", db),
                );
                new_ents.push(e);
            }
        }
        if let Some(phone) = &item.phone
            && phone.len() >= 7
            && seen.insert(phone.to_lowercase())
        {
            let mut e = Entity::new(EntityKind::Phone, phone, 0.60, scan_id);
            e.tag(tags::BREACH);
            e.tag("oathnet-enriched");
            e.add_evidence(Evidence::new(
                "search_engines:oathnet",
                format!("Breach phone linked to {lookup_value}"),
            ));
            new_ents.push(e);
        }
        if let Some(name) = &item.name {
            let t = name.trim();
            if t.len() >= 4 && t.contains(' ') && seen.insert(t.to_lowercase()) {
                let mut e = Entity::new(EntityKind::Person, t, 0.55, scan_id);
                e.tag(tags::BREACH);
                e.tag("oathnet-enriched");
                e.add_evidence(Evidence::new(
                    "search_engines:oathnet",
                    format!("Breach name linked to {lookup_value}"),
                ));
                new_ents.push(e);
            }
        }
        if let Some(ip) = &item.ip
            && ip.contains('.')
            && ip.len() >= 7
            && seen.insert(ip.clone())
        {
            let mut e = Entity::new(EntityKind::IpAddress, ip, 0.50, scan_id);
            e.tag(tags::BREACH);
            e.tag("oathnet-enriched");
            e.add_evidence(Evidence::new(
                "search_engines:oathnet",
                format!("Breach IP linked to {lookup_value}"),
            ));
            new_ents.push(e);
        }
    }
    result.extend(new_ents);
}

// ─── Query generation ───────────────────────────────────────────────────────

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
            let domain = v.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
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
                q.push(format!(
                    "{first} {last} site:instagram.com OR site:github.com OR site:reddit.com"
                ));
                q.push(format!("\"{v}\" email OR contact OR profile"));
                q.push(format!(
                    "\"{v}\" site:peekyou.com OR site:spokeo.com \
                     OR site:nuwber.com OR site:pipl.com"
                ));
                q.push(format!("\"{v}\" address OR location OR city OR suburb"));
                q.push(format!("\"{v}\" ABN OR ACN OR \"Pty Ltd\" OR director"));
            }
            q
        }
        TargetKind::Phone => vec![format!("\"{v}\"")],
        _ => Vec::new(),
    }
}

// ─── Secondary pivot: extract usernames from discovered URLs ────────────────

/// Extract potential username pivots from search results. Social
/// profile URLs contain usernames in their path that can be used
/// as secondary search seeds to find cross-platform identity links.
fn extract_username_pivots(results: &[SearchResult], target: &Target) -> Vec<String> {
    let social_hosts = [
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

    let terms = target_terms(target);
    let mut seen = HashSet::new();
    let target_lower = target.value.to_lowercase();
    let mut pivots = Vec::new();

    for r in results {
        let host = extract_host(&r.url);
        if !social_hosts
            .iter()
            .any(|s| host == *s || host.ends_with(&format!(".{s}")))
        {
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

fn extract_path_username(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let segments: Vec<&str> = parsed.path_segments()?.filter(|s| !s.is_empty()).collect();
    let candidate = segments.first()?;
    if candidate.len() >= 3
        && candidate.len() <= 40
        && candidate
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        Some(candidate.to_string())
    } else {
        None
    }
}

// ─── Fetch + parse ──────────────────────────────────────────────────────────

/// Outcome of a single fetch attempt. Distinguishes "engine responded
/// but was blocked" (worth retrying with alt UA) from "engine is
/// unreachable" (retrying wastes the timeout budget).
enum FetchOutcome {
    Body(String),
    Blocked,
    Unreachable,
}

/// Attempt to fetch search results, retrying once with an alternate
/// User-Agent only when the engine responded but was blocked — never
/// when the engine is completely unreachable (saves ~10s per dead engine).
async fn fetch_and_parse(
    url: &str,
    engine: &EngineSpec,
    query: &str,
    post_body: Option<&str>,
) -> Option<Vec<SearchResult>> {
    match try_fetch(url, engine.ua, post_body).await {
        FetchOutcome::Body(body) => {
            let results = parse_results(&body, engine.name, query);
            if !results.is_empty() {
                return Some(results);
            }
        }
        FetchOutcome::Unreachable => return None,
        FetchOutcome::Blocked => {}
    }

    if engine.ua != engine.ua_alt
        && let FetchOutcome::Body(body) = try_fetch(url, engine.ua_alt, post_body).await
    {
        let results = parse_results(&body, engine.name, query);
        if !results.is_empty() {
            return Some(results);
        }
    }

    None
}

async fn try_fetch(url: &str, ua: &str, post_body: Option<&str>) -> FetchOutcome {
    let body = if let Some(data) = post_body {
        crate::util::curl::fetch_post_with_ua(url, data, 8_000, ua).await
    } else {
        crate::util::curl::fetch_with_ua(url, 8_000, ua).await
    };
    let body = match body {
        Some(b) => b,
        None => return FetchOutcome::Unreachable,
    };
    if body.len() < 500 {
        return FetchOutcome::Unreachable;
    }
    if is_captcha_page(&body) {
        return FetchOutcome::Blocked;
    }
    FetchOutcome::Body(body)
}

/// Detect CAPTCHA/interstitial pages that contain no real results.
fn is_captcha_page(body: &str) -> bool {
    let lower = body.to_lowercase();
    lower.contains("anomaly-modal")
        || lower.contains("unusual traffic")
        || lower.contains("are not a robot")
        || (lower.contains("consent") && lower.contains("before you continue"))
        || lower.contains("httpservice/retry")
        || lower.contains("captcha-delivery.com")
        || lower.contains("showcaptcha")
        || lower.contains("smartcaptcha")
        || lower.contains("challenges.cloudflare.com")
        || (lower.contains("just a moment") && lower.contains("cloudflare"))
}

fn parse_results(html: &str, engine: &'static str, query: &str) -> Vec<SearchResult> {
    let mut results = Vec::new();
    let mut seen_urls: HashSet<String> = HashSet::new();

    // Primary: extract from href= attributes (works for Yahoo/DDG/Brave)
    for href in HrefIter::new(html) {
        if results.len() >= MAX_RESULTS_PER_ENGINE {
            break;
        }
        let url = match resolve_href(href) {
            Some(u) if !u.is_empty() => u,
            _ => continue,
        };
        add_result(
            &url,
            html,
            href,
            engine,
            query,
            &mut seen_urls,
            &mut results,
        );
    }

    // Secondary: extract from <cite> tags (Bing puts display URLs here)
    for cite_url in CiteIter::new(html) {
        if results.len() >= MAX_RESULTS_PER_ENGINE {
            break;
        }
        let url = if cite_url.starts_with("http") {
            cite_url.to_string()
        } else {
            format!("https://{cite_url}")
        };
        add_result(
            &url,
            html,
            cite_url,
            engine,
            query,
            &mut seen_urls,
            &mut results,
        );
    }

    // Tertiary: extract from Google /url?q= redirect links
    for google_url in GoogleUrlIter::new(html) {
        if results.len() >= MAX_RESULTS_PER_ENGINE {
            break;
        }
        add_result(
            google_url,
            html,
            google_url,
            engine,
            query,
            &mut seen_urls,
            &mut results,
        );
    }

    results
}

fn add_result(
    url: &str,
    html: &str,
    anchor: &str,
    engine: &'static str,
    query: &str,
    seen: &mut HashSet<String>,
    results: &mut Vec<SearchResult>,
) {
    // URL-decode percent-encoded URLs (from Google /url?q=, Yahoo /RU=, etc.)
    let decoded = url::form_urlencoded::parse(url.as_bytes())
        .next()
        .map(|(k, _)| k.into_owned())
        .unwrap_or_else(|| url.to_string());
    let url = if decoded.starts_with("http") {
        &decoded
    } else {
        return;
    };

    let host = extract_host(url);
    if host.is_empty() || is_engine_domain(&host) {
        return;
    }
    if is_tracking_url(url) {
        return;
    }
    // Deduplicate by domain+path (strip query/fragment for dedup only)
    let dedup_key = canonicalize_url(url);
    if !seen.insert(dedup_key) {
        return;
    }
    let title = {
        let t = extract_anchor_text(html, anchor, 200);
        if t.len() >= 4 {
            t
        } else {
            extract_surrounding_text(html, anchor, 200)
        }
    };
    let snippet = extract_snippet_near(html, anchor, 400);
    results.push(SearchResult {
        url: url.to_string(),
        title,
        snippet,
        engine,
        query: query.to_string(),
    });
}

/// Extracts URLs from `<cite>` tags (Bing's result format).
struct CiteIter<'a> {
    remaining: &'a str,
}

impl<'a> CiteIter<'a> {
    fn new(html: &'a str) -> Self {
        Self { remaining: html }
    }
}

impl<'a> Iterator for CiteIter<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let start = self.remaining.find("<cite")?;
            self.remaining = &self.remaining[start..];
            let gt = self.remaining.find('>')?;
            self.remaining = &self.remaining[gt + 1..];
            let end = self.remaining.find("</cite>")?;
            let content = &self.remaining[..end];
            self.remaining = &self.remaining[end + 7..];
            // Bing cite format: "https://example.com › path › ..."
            // Extract the domain part before the first " ›"
            let clean = content.split(" ›").next().unwrap_or(content).trim();
            if clean.contains('.') && clean.len() > 4 && !clean.contains('<') {
                return Some(clean);
            }
        }
    }
}

/// Extracts URLs from Google's `/url?q=<encoded>&sa=` redirect pattern.
struct GoogleUrlIter<'a> {
    remaining: &'a str,
}

impl<'a> GoogleUrlIter<'a> {
    fn new(html: &'a str) -> Self {
        Self { remaining: html }
    }
}

impl<'a> Iterator for GoogleUrlIter<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let idx = self.remaining.find("/url?q=")?;
            self.remaining = &self.remaining[idx + 7..];
            let end = self
                .remaining
                .find('&')
                .or_else(|| self.remaining.find('"'))?;
            let encoded = &self.remaining[..end];
            self.remaining = &self.remaining[end..];
            if encoded.starts_with("http") && !encoded.contains("google.") {
                return Some(encoded);
            }
        }
    }
}

/// Decode common HTML entities in href values. Search engines
/// (especially DDG) emit `&amp;` instead of `&` inside href attrs.
fn decode_html_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

/// Resolve an href into a clean URL, decoding engine-specific redirects.
fn resolve_href(href: &str) -> Option<String> {
    let href = &decode_html_entities(href);

    // DuckDuckGo wraps URLs: //duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com&rut=...
    if href.contains("uddg=") {
        return extract_url_param(href, "uddg=");
    }

    // Yandex wraps URLs: //yandex.com/clck/jsredir?...&url=https%3A%2F%2Fexample.com&...
    if href.contains("yandex.com/clck") && href.contains("url=") {
        return extract_url_param(href, "url=");
    }

    // Yahoo wraps URLs: /RU=https%3a%2f%2fexample.com/RK=.../RS=...
    if href.contains("/RU=") {
        return href
            .split("/RU=")
            .nth(1)
            .and_then(|rest| rest.split("/R").next())
            .and_then(|encoded| {
                let decoded: String = url::form_urlencoded::parse(encoded.as_bytes())
                    .next()
                    .map(|(k, _)| k.into_owned())
                    .unwrap_or_else(|| encoded.to_string());
                if decoded.starts_with("http") {
                    Some(decoded)
                } else {
                    None
                }
            });
    }

    // Protocol-relative
    if href.starts_with("//") {
        return Some(format!("https:{href}"));
    }

    // Absolute HTTP(S)
    if href.starts_with("http://") || href.starts_with("https://") {
        return Some(href.to_string());
    }

    None
}

fn extract_url_param(href: &str, param: &str) -> Option<String> {
    href.split(param)
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .map(|encoded| {
            url::form_urlencoded::parse(encoded.as_bytes())
                .next()
                .map(|(k, _)| k.into_owned())
                .unwrap_or_else(|| encoded.to_string())
        })
}

// ─── HTML iteration ─────────────────────────────────────────────────────────

struct HrefIter<'a> {
    remaining: &'a str,
}

impl<'a> HrefIter<'a> {
    fn new(html: &'a str) -> Self {
        Self { remaining: html }
    }
}

impl<'a> Iterator for HrefIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let idx = self.remaining.find("href=")?;
            self.remaining = &self.remaining[idx + 5..];

            let quote = match self.remaining.as_bytes().first()? {
                b'"' | b'\'' => self.remaining.as_bytes()[0],
                _ => continue,
            };
            self.remaining = &self.remaining[1..];
            let end = self.remaining.find(quote as char)?;
            let href = &self.remaining[..end];
            self.remaining = &self.remaining[end + 1..];

            if href.is_empty()
                || href.starts_with('#')
                || href.starts_with("javascript:")
                || href.starts_with("mailto:")
                || href.starts_with("tel:")
                || href.starts_with("data:")
            {
                continue;
            }
            return Some(href);
        }
    }
}

// ─── URL helpers ────────────────────────────────────────────────────────────

fn extract_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
        .unwrap_or_default()
}

const ENGINE_DOMAINS: &[&str] = &[
    "duckduckgo.com",
    "startpage.com",
    "mojeek.com",
    "brave.com",
    "yahoo.com",
    "bing.com",
    "google.com",
    "yandex.com",
    "yandex.ru",
    "yandex.net",
    "yimg.com",
    "search.yahoo.com",
    "r.search.yahoo.com",
    "cc.bingj.com",
    "aol.com",
    "search.aol.com",
    "oath.com",
    "gstatic.com",
    "googleapis.com",
    "googleusercontent.com",
    "schema.org",
    "w3.org",
    "imgs.search.brave.com",
    "ecosia.org",
    "qwant.com",
    "api.qwant.com",
    "dogpile.com",
    "swisscows.com",
    "system1.com",
    "flocdn.com",
    "cookielaw.org",
    "onetrust.com",
    "syndicatedsearch.goog",
    "microsoftonline.com",
    "msn.com",
    // Engine-adjacent infrastructure that appears in their chrome
    "teleguard.com",
    "shdw.me",
    "unpkg.com",
    "torproject.org",
    "mastodon.social",
    "discord.com",
    "apple.com",
    "play.google.com",
    "apps.apple.com",
    "itunes.apple.com",
    "microsoft.com",
    "support.microsoft.com",
];

fn is_engine_domain(host: &str) -> bool {
    ENGINE_DOMAINS
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

/// Domains that are generic infrastructure / unrelated to any target.
/// These appear in search result pages from engine chrome, ads, or
/// generic navigation links, never as OSINT-relevant findings.
fn is_generic_domain(domain: &str) -> bool {
    const GENERIC: &[&str] = &[
        "amazonaws.com",
        "androidpolice.com",
        "britannica.com",
        "builtin.com",
        "christiantoday.com",
        "cloudflare.com",
        "co.za",
        "contactout.com",
        "dol.gov",
        "dpd.com",
        "emailsherlock.com",
        "f6s.com",
        "fitfit.fitness",
        "forbes.com",
        "gardenweb.com",
        "hexomatic.com",
        "hunter.io",
        "littlecaesars.com",
        "mapquest.com",
        "martindale.com",
        "nolo.com",
        "office.com",
        "outlook.com",
        "reversecontact.com",
        "stvincentipa.com",
        "tomba.io",
        "usps.com",
        "wikihow.com",
        "windowsreport.com",
        "zoominfo.com",
    ];
    GENERIC.contains(&domain)
}

fn is_tracking_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.contains("r.search.yahoo.com")
        || lower.contains("duckduckgo.com/y.js")
        || lower.contains("clickserve")
        || lower.contains("ad.doubleclick")
        || lower.contains("googleads")
        || lower.contains("r.bing.com")
        || lower.contains("th.bing.com")
        || lower.contains("cc.bingj.com")
        || lower.contains("yandex.com/clck")
        || lower.contains("ecosia.org/newtab")
        || lower.contains("dogpile.com/click")
        || lower.contains("swisscows.com/api")
        || lower.contains("/privacy-policy")
        || lower.contains("/terms-of-use")
        || lower.contains("/terms-of-service")
        || lower.contains("guce.yahoo.com")
        || lower.contains("guce.aol.com")
        || lower.contains("advertising.yahoo.com")
        || lower.contains("feedback.yahoo.com")
}

fn is_navigation_path(s: &str) -> bool {
    const EXACT: &[&str] = &[
        "about",
        "api",
        "browse",
        "business",
        "careers",
        "company",
        "contact",
        "create",
        "events",
        "explore",
        "features",
        "feed",
        "groups",
        "help",
        "home",
        "jobs",
        "legal",
        "live",
        "log-in",
        "marketplace",
        "media",
        "messenger",
        "music",
        "myspace",
        "news",
        "notifications",
        "people",
        "photos",
        "popular",
        "posts",
        "privacy",
        "reel",
        "reels",
        "settings",
        "shorts",
        "status",
        "stories",
        "support",
        "tag",
        "tags",
        "terms",
        "topics",
        "tpm",
        "trends",
        "video",
        "videos",
        "watch",
        "web",
        "wiki",
    ];
    const CONTAINS: &[&str] = &[
        "login",
        "signup",
        "signin",
        "signout",
        "logout",
        "register",
        "getstarted",
        "official",
        "dogpile",
        "swisscows",
        "qwant",
        "instagram",
        "facebook",
        "twitter",
        "youtube",
        "tiktok",
        "ecosia",
        ".php",
        ".html",
        ".asp",
    ];
    EXACT.contains(&s)
        || s.starts_with("search")
        || s.starts_with("public")
        || s.starts_with("upload")
        || s.starts_with("discover")
        || CONTAINS.iter().any(|n| s.contains(n))
}

/// Extract the meaningful search terms from a target value.
/// For email: uses the local part (before @). For names: each word.
/// Filters to ≥3 chars and lowercases. Used by every relevance gate.
fn target_terms(target: &Target) -> Vec<String> {
    let seed = match target.kind {
        TargetKind::Email => target.value.split('@').next().unwrap_or(""),
        _ => &target.value,
    };
    seed.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3)
        .map(String::from)
        .collect()
}

/// Check whether a URL's path contains any target term (≥4 chars).
fn url_matches_target(url: &str, terms: &[String]) -> bool {
    let path = url::Url::parse(url)
        .ok()
        .map(|u| u.path().to_lowercase())
        .unwrap_or_default();
    if path.len() < 4 {
        return false;
    }
    terms
        .iter()
        .filter(|w| w.len() >= 4)
        .any(|w| path.contains(w.as_str()))
}

/// Score how strongly a discovered username is connected to the target.
/// Uses multiple independent signals — a username that shares no terms
/// with the seed can still be validated through co-occurrence, people-
/// search provenance, or search-engine contextual linking.
///
/// Returns (score, confidence):
///   score ≥ 3 → strong: 0.55 confidence (PROBABLE tier)
///   score 1-2 → weak:   0.30 confidence (CANDIDATE tier)
///   score 0   → drop:   not emitted
fn score_username(
    username: &str,
    host: &str,
    terms: &[String],
    result: &SearchResult,
) -> (u8, f64) {
    let mut score: u8 = 0;

    // Signal 1: direct term overlap (strongest)
    let parts: Vec<String> = username
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3)
        .map(String::from)
        .collect();
    if terms.iter().any(|t| {
        parts
            .iter()
            .any(|p| p == t || p.contains(t.as_str()) || t.contains(p.as_str()))
    }) {
        score += 3;
    }

    // Signal 2: people-search provenance — the site specialises in
    // linking identities, so any username it connects to the target
    // has high implicit credibility
    let people_search = [
        "peekyou.com",
        "spokeo.com",
        "nuwber.com",
        "whitepages.com",
        "thatsthem.com",
    ];
    if people_search.iter().any(|ps| host.ends_with(ps)) {
        score += 3;
    }

    // Signal 3: co-occurrence — a target term (≥4 chars) appears
    // in the same snippet/title as this username, meaning the search
    // engine's result page explicitly associates both
    let text = format!("{} {}", result.title, result.snippet).to_lowercase();
    if terms
        .iter()
        .filter(|t| t.len() >= 4)
        .any(|t| text.contains(t.as_str()))
    {
        score += 2;
    }

    // Signal 4: platform-targeted query — the query used site:
    // for this exact platform, meaning the engine specifically
    // matched the target to this profile on this platform
    let ql = result.query.to_lowercase();
    let host_base = host
        .trim_start_matches("www.")
        .trim_start_matches("m.")
        .trim_start_matches("mobile.");
    if ql.contains(&format!("site:{host_base}")) {
        score += 1;
    }

    // Signal 5: semantic similarity — the username is structurally
    // similar to a target term even without exact substring match.
    // "jaydes" ↔ "jdespal" have partial bigram overlap. Threshold
    // 0.25 catches abbreviations and character-transposed aliases.
    if score == 0 {
        let seed = match terms.first() {
            Some(s) => s.as_str(),
            None => "",
        };
        if bigram_similarity(username, seed) >= 0.25 {
            score += 1;
        }
    }

    let confidence = if score >= 3 { 0.55 } else { 0.30 };
    (score, confidence)
}

fn canonicalize_url(url: &str) -> String {
    let base = url.split('?').next().unwrap_or(url);
    let base = base.split('#').next().unwrap_or(base);
    base.trim_end_matches('/').to_string()
}

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

fn extract_anchor_text(html: &str, href: &str, max_len: usize) -> String {
    let search_dq = format!("href=\"{href}\"");
    let search_sq = format!("href='{href}'");
    let pos = match html.find(&search_dq).or_else(|| html.find(&search_sq)) {
        Some(p) => p,
        None => return String::new(),
    };
    let after_href = &html[pos..];
    let gt = match after_href.find('>') {
        Some(g) => pos + g + 1,
        None => return String::new(),
    };
    let rest = &html[gt..];
    let end_tag = rest.find("</a>").or_else(|| rest.find("</A>"));
    let end = match end_tag {
        Some(e) => gt + e,
        None => return String::new(),
    };
    strip_tags(&html[gt..end], max_len)
}

fn extract_surrounding_text(html: &str, anchor: &str, max_len: usize) -> String {
    let pos = match html.find(anchor) {
        Some(p) => p,
        None => return String::new(),
    };
    let start = floor_char_boundary(html, pos.saturating_sub(300));
    let end = ceil_char_boundary(html, (pos + anchor.len() + 300).min(html.len()));
    strip_tags(&html[start..end], max_len)
}

fn extract_snippet_near(html: &str, anchor: &str, max_len: usize) -> String {
    let raw = match html.find(anchor) {
        Some(p) => p + anchor.len(),
        None => return String::new(),
    };
    let pos = ceil_char_boundary(html, raw);
    let end = ceil_char_boundary(html, (pos + 800).min(html.len()));
    strip_tags(&html[pos..end], max_len)
}

fn strip_tags(html: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(max_len);
    let mut in_tag = false;
    for c in html.chars() {
        if out.len() >= max_len {
            break;
        }
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => {
                if c.is_whitespace() {
                    if !out.ends_with(' ') && !out.is_empty() {
                        out.push(' ');
                    }
                } else {
                    out.push(c);
                }
            }
            _ => {}
        }
    }
    out.trim().to_string()
}

// ─── Entity building ────────────────────────────────────────────────────────

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
            .map(|s| s.len() as u32)
            .unwrap_or(1);

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
            if seen_domains.insert(format!("@addr:{}", addr.to_lowercase())) {
                let mut e = Entity::new(EntityKind::Address, &addr, 0.40, scan_id);
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
            let social_hosts = [
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
                "tiktok.com",
                "pinterest.com",
                "linktr.ee",
            ];
            let lower_user = username.to_lowercase();
            let is_social = social_hosts
                .iter()
                .any(|s| host == *s || host.ends_with(&format!(".{s}")));
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
            let people_hosts = ["peekyou.com", "spokeo.com", "nuwber.com"];
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

    // Sort entities in a structured order suitable for both human
    // review and LLM consumption: parent entity first (it has the
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

fn extract_registrable(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        host.to_string()
    }
}

/// Build a clean, structured evidence entry from a search result.
/// Every evidence entry includes the full navigable URL so the user
/// can click through to verify the finding.
fn build_search_evidence(r: &SearchResult) -> Evidence {
    let title_clean: String = r.title.chars().take(200).collect();
    let snippet_clean: String = r.snippet.chars().take(400).collect();

    let summary = if !title_clean.is_empty() {
        format!("[{}] {} — {}", r.engine, title_clean.trim(), r.url)
    } else {
        format!("[{}] {}", r.engine, r.url)
    };

    let mut ev = Evidence::new("search_engines", summary)
        .with_attr("url", &r.url)
        .with_attr("engine", r.engine)
        .with_attr("query", &r.query);
    if !title_clean.is_empty() {
        ev = ev.with_attr("page_title", title_clean.trim());
    }
    if !snippet_clean.is_empty() {
        ev = ev.with_attr("snippet", snippet_clean.trim());
    }

    let kp = extract_key_phrase(&snippet_clean, &r.query);
    if !kp.is_empty() {
        ev = ev.with_attr("key_phrase", &kp);
    }
    ev
}

/// Extract the most relevant sentence fragment from a snippet by
/// finding the clause that overlaps most with the query terms.
fn extract_key_phrase(snippet: &str, query: &str) -> String {
    if snippet.len() < 10 {
        return String::new();
    }
    let query_words: HashSet<String> = query
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3)
        .map(String::from)
        .collect();
    if query_words.is_empty() {
        return String::new();
    }

    let mut best = "";
    let mut best_score = 0usize;
    for clause in snippet.split(['.', '!', '?', '|']) {
        let clause = clause.trim();
        if clause.len() < 8 || clause.len() > 200 {
            continue;
        }
        let score = clause
            .to_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| query_words.contains(*w))
            .count();
        if score > best_score {
            best_score = score;
            best = clause;
        }
    }
    if best_score >= 1 {
        best.to_string()
    } else {
        String::new()
    }
}

/// Extract "City, State" patterns from text for geolocation.
/// Only matches when a comma-separated city name precedes a known
/// state/territory name, and the city portion starts with an uppercase
/// letter (filters out random sentence fragments).
fn extract_addresses_from_text(text: &str) -> Vec<String> {
    const STATES: &[&str] = &[
        "Queensland",
        "New South Wales",
        "Victoria",
        "Tasmania",
        "South Australia",
        "Western Australia",
        "Northern Territory",
        "NSW",
        "QLD",
        "VIC",
        "TAS",
        "ACT",
        "Alabama",
        "Alaska",
        "Arizona",
        "Arkansas",
        "California",
        "Colorado",
        "Connecticut",
        "Delaware",
        "Florida",
        "Georgia",
        "Hawaii",
        "Idaho",
        "Illinois",
        "Indiana",
        "Iowa",
        "Kansas",
        "Kentucky",
        "Louisiana",
        "Maine",
        "Maryland",
        "Massachusetts",
        "Michigan",
        "Minnesota",
        "Mississippi",
        "Missouri",
        "Montana",
        "Nebraska",
        "Nevada",
        "New Hampshire",
        "New Jersey",
        "New Mexico",
        "New York",
        "North Carolina",
        "North Dakota",
        "Ohio",
        "Oklahoma",
        "Oregon",
        "Pennsylvania",
        "Rhode Island",
        "South Carolina",
        "South Dakota",
        "Tennessee",
        "Texas",
        "Utah",
        "Vermont",
        "Virginia",
        "Washington",
        "West Virginia",
        "Wisconsin",
        "Wyoming",
    ];

    let mut addrs = Vec::new();
    for state in STATES {
        let mut search_from = 0;
        while let Some(pos) = text[search_from..].find(state) {
            let abs = search_from + pos;
            search_from = abs + state.len();

            // Need ", State" — check for comma before the state name
            let before = text[..abs].trim_end();
            if !before.ends_with(',') {
                continue;
            }
            // Extract the city name between the nearest prior comma
            // (or start of text) and the comma before the state name.
            // "Jerome Despal, Nundah, Queensland" → "Nundah"
            // "lives in Houston, Texas" → "Houston"
            let pre_comma = before.trim_end_matches(',').trim();
            let last_segment = match pre_comma.rfind(',') {
                Some(i) => pre_comma[i + 1..].trim(),
                None => {
                    let words: Vec<&str> = pre_comma.split_whitespace().collect();
                    let mut n = 0;
                    for w in words.iter().rev() {
                        if w.starts_with(|c: char| c.is_ascii_uppercase()) {
                            n += 1;
                        } else {
                            break;
                        }
                    }
                    if n == 0 {
                        continue;
                    }
                    let start_idx = words.len() - n;
                    &pre_comma[pre_comma.find(words[start_idx]).unwrap_or(0)..]
                }
            };
            let city = last_segment.trim();
            if city.len() < 2
                || city.len() > 40
                || !city.starts_with(|c: char| c.is_ascii_uppercase())
            {
                continue;
            }
            if !city
                .chars()
                .all(|c| c.is_alphanumeric() || c == ' ' || c == '-')
            {
                continue;
            }
            let addr = format!("{city}, {state}");
            addrs.push(addr);
        }
    }
    addrs
}

/// Extract Australian Business Numbers (11 digits) and Australian
/// Company Numbers (9 digits) from text. ABNs are formatted as
/// "XX XXX XXX XXX" or "XXXXXXXXXXX"; ACNs as "XXX XXX XXX".
/// Returns (value, kind_label) pairs.
fn extract_abn_acn_from_text(text: &str) -> Vec<(String, &'static str)> {
    let mut results = Vec::new();
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        let mut digits = Vec::new();
        while i < len && (bytes[i].is_ascii_digit() || bytes[i] == b' ') {
            if bytes[i].is_ascii_digit() {
                digits.push(bytes[i]);
            }
            i += 1;
        }
        if digits.len() == 11 {
            let num: String = digits.iter().map(|&b| b as char).collect();
            if is_valid_abn(&num) {
                let before = text[..start].to_lowercase();
                if before.ends_with("abn")
                    || before.ends_with("abn ")
                    || before.ends_with("abn: ")
                    || before.ends_with("business number ")
                {
                    results.push((num, "ABN"));
                }
            }
        } else if digits.len() == 9 {
            let num: String = digits.iter().map(|&b| b as char).collect();
            let before = text[..start].to_lowercase();
            if before.ends_with("acn")
                || before.ends_with("acn ")
                || before.ends_with("acn: ")
                || before.ends_with("company number ")
            {
                results.push((num, "ACN"));
            }
        }
    }
    results
}

fn is_valid_abn(s: &str) -> bool {
    if s.len() != 11 {
        return false;
    }
    let weights = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 11 {
        return false;
    }
    let mut sum = 0u32;
    for (i, &w) in weights.iter().enumerate() {
        let d = if i == 0 {
            digits[i].wrapping_sub(1)
        } else {
            digits[i]
        };
        sum += d * w;
    }
    sum.is_multiple_of(89)
}

/// Extract organisation names from text. Looks for patterns like
/// "Pty Ltd", "Inc", "LLC", "Corporation" near the target context.
fn extract_organisations_from_text(text: &str, terms: &[String]) -> Vec<String> {
    let suffixes = [
        " Pty Ltd",
        " Pty. Ltd.",
        " Pty Limited",
        " Inc.",
        " Inc",
        " LLC",
        " Ltd",
        " Ltd.",
        " Limited",
        " Corporation",
        " Corp.",
        " Corp",
        " Co.",
    ];
    let mut orgs = Vec::new();
    let lower = text.to_lowercase();
    for suffix in &suffixes {
        let sl = suffix.to_lowercase();
        let mut from = 0;
        while let Some(pos) = lower[from..].find(&sl) {
            let abs = from + pos;
            from = abs + sl.len();
            // Walk backwards to find the start of the org name
            let before = &text[..abs];
            let name_start = before
                .rfind([',', '.', ';', '(', '\n'])
                .map(|i| i + 1)
                .unwrap_or(abs.saturating_sub(60));
            let org = text[name_start..abs + suffix.len()].trim();
            if org.len() >= 5
                && org.starts_with(|c: char| c.is_ascii_uppercase())
                && terms
                    .iter()
                    .any(|t| org.to_lowercase().contains(t.as_str()))
            {
                orgs.push(org.to_string());
            }
        }
    }
    orgs
}

/// Semantic similarity between two strings using character bigram
/// overlap (Dice coefficient). Returns 0.0–1.0.
fn bigram_similarity(a: &str, b: &str) -> f64 {
    fn bigrams(s: &str) -> Vec<(char, char)> {
        let chars: Vec<char> = s.to_lowercase().chars().collect();
        chars.windows(2).map(|w| (w[0], w[1])).collect()
    }
    let ba = bigrams(a);
    let bb = bigrams(b);
    if ba.is_empty() || bb.is_empty() {
        return 0.0;
    }
    let matches = ba.iter().filter(|bg| bb.contains(bg)).count();
    (2 * matches) as f64 / (ba.len() + bb.len()) as f64
}

fn extract_emails_from_text(text: &str) -> Vec<String> {
    let mut emails = Vec::new();
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        if bytes[i] != b'@' || i == 0 || i + 1 >= len {
            i += 1;
            continue;
        }
        if !is_email_local_char(bytes[i - 1]) || !bytes[i + 1].is_ascii_alphanumeric() {
            i += 1;
            continue;
        }
        let mut local_start = i;
        while local_start > 0 && is_email_local_char(bytes[local_start - 1]) {
            local_start -= 1;
        }
        let mut domain_end = i + 1;
        while domain_end < len && is_domain_char(bytes[domain_end]) {
            domain_end += 1;
        }
        while domain_end > i + 1 && bytes[domain_end - 1] == b'.' {
            domain_end -= 1;
        }
        let domain = &text[i + 1..domain_end];
        if domain.contains('.') && domain.len() > 3 && (domain_end - local_start) <= 254 {
            let email = text[local_start..domain_end].to_lowercase();
            if !email.ends_with(".png")
                && !email.ends_with(".jpg")
                && !email.ends_with(".gif")
                && !email.ends_with(".css")
            {
                emails.push(email);
            }
        }
        i = domain_end;
    }
    emails
}

fn extract_phones_from_text(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut phones = Vec::new();
    let mut i = 0;
    while i < len {
        if bytes[i] == b'+' && i + 8 < len && bytes[i + 1].is_ascii_digit() {
            let start = i;
            i += 1;
            let mut digits = 0u32;
            while i < len
                && (bytes[i].is_ascii_digit()
                    || bytes[i] == b'-'
                    || bytes[i] == b' '
                    || bytes[i] == b'('
                    || bytes[i] == b')')
            {
                if bytes[i].is_ascii_digit() {
                    digits += 1;
                }
                i += 1;
            }
            if (7..=15).contains(&digits) {
                let cleaned: String = text[start..i]
                    .chars()
                    .filter(|c| c.is_ascii_digit() || *c == '+')
                    .collect();
                phones.push(cleaned);
            }
        } else {
            i += 1;
        }
    }
    phones
}

fn is_email_local_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b == b'+'
}

fn is_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_domain_email_username_fullname_phone() {
        let m = SearchEngines;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(m.accepts(&Target::new(TargetKind::Email, "x")));
        assert!(m.accepts(&Target::new(TargetKind::Username, "x")));
        assert!(m.accepts(&Target::new(TargetKind::FullName, "x")));
        assert!(m.accepts(&Target::new(TargetKind::Phone, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "x")));
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
        assert_eq!(q.len(), 7);
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
    fn engine_count_is_thirteen() {
        assert_eq!(ENGINES.len(), 13);
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
}
