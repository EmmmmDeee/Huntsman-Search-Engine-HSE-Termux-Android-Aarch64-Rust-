use super::helpers::*;
use super::{EngineSpec, MAX_RESULTS_PER_ENGINE, SearchResult};
use crate::modules::oathnet_pro::key_harvest::identify_api_key;

/// How many distinct egress IPs to rotate through per engine before giving up
/// on a blocked/unreachable fetch. Bounded so a scan stays fast even when a lot
/// of pooled proxies have died.
const MAX_PROXY_ROTATIONS: usize = 4;

pub(super) async fn fetch_and_parse(
    url: &str,
    engine: &EngineSpec,
    query: &str,
    post_body: Option<&str>,
) -> Option<Vec<SearchResult>> {
    match try_fetch(engine.name, url, engine.ua, post_body).await {
        FetchOutcome::Body(body) => {
            scan_body_for_keys(&body);
            let results = parse_results(&body, engine.name, query);
            if !results.is_empty() {
                return Some(results);
            }
        }
        FetchOutcome::Unreachable => return None,
        FetchOutcome::Blocked => {}
    }

    if engine.ua != engine.ua_alt
        && let FetchOutcome::Body(body) =
            try_fetch(engine.name, url, engine.ua_alt, post_body).await
    {
        let results = parse_results(&body, engine.name, query);
        if !results.is_empty() {
            return Some(results);
        }
    }

    None
}

pub(super) async fn try_fetch(
    resource: &str,
    url: &str,
    ua: &str,
    post_body: Option<&str>,
) -> FetchOutcome {
    let body = if let Some(data) = post_body {
        crate::util::curl::fetch_post_with_ua(url, data, 8_000, ua).await
    } else {
        crate::util::curl::fetch_with_ua(url, 8_000, ua).await
    };

    // Direct fetch decisive? (≥500 bytes of non-CAPTCHA HTML = real results.)
    match body {
        Some(b) if b.len() >= 500 && !is_captcha_page(&b) => return FetchOutcome::Body(b),
        Some(b) if b.len() >= 500 => return FetchOutcome::Blocked, // CAPTCHA/interstitial
        _ => {}
    }

    // Direct failed/blocked → go through a proxy.
    // 1) An explicit `HUNTSMAN_SEARCH_PROXY` always wins (single attempt).
    if let Some(proxy) = std::env::var("HUNTSMAN_SEARCH_PROXY")
        .ok()
        .filter(|p| !p.is_empty())
    {
        return match crate::util::curl::fetch_via_proxy(url, 8_000, ua, &proxy).await {
            Some(b) if b.len() >= 500 && !is_captcha_page(&b) => FetchOutcome::Body(b),
            Some(_) => FetchOutcome::Blocked,
            None => FetchOutcome::Unreachable,
        };
    }

    // 2) Intelligent rotation: spread this engine's retries across the
    //    validated pool, resting any egress IP the engine CAPTCHAs/blocks (so
    //    we don't keep hammering a flagged IP), preferring a region-matched
    //    proxy when `HUNTSMAN_REGION` is set.
    let region = std::env::var("HUNTSMAN_REGION").ok();
    let router = crate::util::proxy::global_router();
    let mut rotated = false;
    let mut saw_page = false;
    for _ in 0..MAX_PROXY_ROTATIONS {
        let Some(px) = router.pick(resource, region.as_deref()) else {
            break; // pool empty or every proxy resting for this engine
        };
        rotated = true;
        match crate::util::curl::fetch_via_proxy(url, 8_000, ua, &px.url()).await {
            Some(b) if b.len() >= 500 && !is_captcha_page(&b) => {
                router.report_success(resource, &px.addr);
                return FetchOutcome::Body(b);
            }
            Some(_) => {
                // Reached the engine but got a CAPTCHA/short page: this IP is
                // flagged. Rest it ~10 min for this engine, then rotate on.
                saw_page = true;
                router.report_block(resource, &px.addr, 600);
            }
            None => router.report_block(resource, &px.addr, 120), // proxy dead
        }
    }

    // 3) Rotation exhausted (or no pool): blocked if any proxy reached the
    //    engine, otherwise unreachable. With no pool this matches the old
    //    no-proxy path exactly.
    if rotated && saw_page {
        FetchOutcome::Blocked
    } else {
        FetchOutcome::Unreachable
    }
}

/// Detect CAPTCHA/interstitial pages that contain no real results.
pub(super) fn is_captcha_page(body: &str) -> bool {
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

pub(super) fn parse_results(html: &str, engine: &'static str, query: &str) -> Vec<SearchResult> {
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

pub(super) fn add_result(
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
        .map_or_else(|| url.to_string(), |(k, _)| k.into_owned());
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
    let snippet = extract_snippet_near(html, anchor, 800);
    results.push(SearchResult {
        url: url.to_string(),
        title,
        snippet,
        engine,
        query: query.to_string(),
    });
}

/// Extracts URLs from `<cite>` tags (Bing's result format).
pub(super) struct CiteIter<'a> {
    remaining: &'a str,
}

impl<'a> CiteIter<'a> {
    pub(super) fn new(html: &'a str) -> Self {
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
pub(super) struct GoogleUrlIter<'a> {
    remaining: &'a str,
}

impl<'a> GoogleUrlIter<'a> {
    pub(super) fn new(html: &'a str) -> Self {
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

fn scan_body_for_keys(body: &str) {
    let pool = crate::util::key_pool::global_pool();
    for word in body.split(|c: char| {
        c.is_whitespace() || c == '"' || c == '\'' || c == '`' || c == '>' || c == '<'
    }) {
        let trimmed = word.trim();
        if trimmed.len() >= 16
            && trimmed.len() <= 200
            && let Some((service, key_val)) = identify_api_key(trimmed)
        {
            let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
            entry.status = crate::util::key_pool::KeyStatus::Untested;
            entry.notes = Some("Search engine result page".into());
            pool.add(service, entry);
        }
    }
}
