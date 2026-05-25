//! Multi-engine search scraping — 5 search engines, zero API keys.
//!
//! Queries DuckDuckGo, Brave, Startpage (Google-sourced), Mojeek,
//! and Yahoo (Bing-powered) with a comprehensive set of OSINT dork
//! queries and extracts entities from result URLs and snippets.
//!
//! Engine selection (from Exa research on CAPTCHA resistance):
//!   - DuckDuckGo HTML: most reliable, no JS, `uddg` redirect decoded
//!   - Startpage: Google-sourced, CAPTCHA-resistant POST endpoint
//!   - Mojeek: independent index, CAPTCHA-resistant
//!   - Brave: independent index, broad international coverage
//!   - Yahoo: Bing-powered, broad crawl coverage
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
        45_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let queries = build_queries(target);
        if queries.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut all_results: Vec<SearchResult> = Vec::new();

        for query in &queries {
            if ctx.cancel.is_cancelled() {
                break;
            }

            for engine in ENGINES {
                if ctx.cancel.is_cancelled() {
                    break;
                }
                let url = (engine.build_url)(query);
                if let Some(mut results) = fetch_and_parse(&ctx.http, &url, engine.name, query).await {
                    all_results.append(&mut results);
                }
                tokio::time::sleep(std::time::Duration::from_millis(INTER_ENGINE_MS)).await;
            }
        }

        Ok(build_entities(target, &ctx.scan_id, &all_results))
    }
}

// ─── Engine definitions ─────────────────────────────────────────────────────

struct EngineSpec {
    name: &'static str,
    build_url: fn(&str) -> String,
}

const ENGINES: &[EngineSpec] = &[
    EngineSpec {
        name: "duckduckgo",
        build_url: |q| format!(
            "https://html.duckduckgo.com/html/?q={}",
            crate::util::http::urlencode(q)
        ),
    },
    EngineSpec {
        name: "startpage",
        build_url: |q| format!(
            "https://www.startpage.com/sp/search?query={}",
            crate::util::http::urlencode(q)
        ),
    },
    EngineSpec {
        name: "mojeek",
        build_url: |q| format!(
            "https://www.mojeek.com/search?q={}",
            crate::util::http::urlencode(q)
        ),
    },
    EngineSpec {
        name: "brave",
        build_url: |q| format!(
            "https://search.brave.com/search?q={}",
            crate::util::http::urlencode(q)
        ),
    },
    EngineSpec {
        name: "yahoo",
        build_url: |q| format!(
            "https://search.yahoo.com/search?p={}",
            crate::util::http::urlencode(q)
        ),
    },
];

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
        ],
        TargetKind::Email => {
            let domain = v.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
            let local = v.split('@').next().unwrap_or("");
            let mut q = vec![format!("\"{v}\"")];
            if !domain.is_empty() {
                q.push(format!("\"{v}\" site:pastebin.com OR site:github.com OR site:linkedin.com"));
            }
            if local.len() >= 3 {
                q.push(format!("\"{local}\" site:linkedin.com OR site:twitter.com"));
            }
            q
        }
        TargetKind::Username => vec![
            format!("\"{v}\" site:github.com OR site:linkedin.com"),
            format!("\"{v}\" site:twitter.com OR site:reddit.com OR site:medium.com"),
            format!("\"{v}\" profile OR account"),
        ],
        TargetKind::FullName => vec![
            format!("\"{v}\" site:linkedin.com OR site:twitter.com"),
            format!("\"{v}\" resume OR cv OR portfolio"),
            format!("\"{v}\""),
        ],
        TargetKind::Phone => vec![
            format!("\"{v}\""),
        ],
        _ => Vec::new(),
    }
}

// ─── Fetch + parse ──────────────────────────────────────────────────────────

async fn fetch_and_parse(
    http: &reqwest::Client,
    url: &str,
    engine: &'static str,
    query: &str,
) -> Option<Vec<SearchResult>> {
    let resp = http.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().await.ok()?;
    if body.len() < 500 {
        return None;
    }
    Some(parse_results(&body, engine, query))
}

fn parse_results(html: &str, engine: &'static str, query: &str) -> Vec<SearchResult> {
    let mut results = Vec::new();
    let mut seen_urls: HashSet<String> = HashSet::new();

    for href in HrefIter::new(html) {
        if results.len() >= MAX_RESULTS_PER_ENGINE {
            break;
        }

        let url = resolve_href(href);
        let url = match url.as_deref() {
            Some(u) if !u.is_empty() => u.to_string(),
            _ => continue,
        };

        let host = extract_host(&url);
        if host.is_empty() || is_engine_domain(&host) {
            continue;
        }
        if is_tracking_url(&url) {
            continue;
        }

        let canonical = canonicalize_url(&url);
        if !seen_urls.insert(canonical.clone()) {
            continue;
        }

        let title = extract_surrounding_text(html, href, 200);
        let snippet = extract_snippet_near(html, href, 400);

        results.push(SearchResult {
            url: canonical,
            title,
            snippet,
            engine,
            query: query.to_string(),
        });
    }
    results
}

/// Resolve an href into a clean URL, decoding engine-specific redirects.
fn resolve_href(href: &str) -> Option<String> {
    // DuckDuckGo wraps URLs: //duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com&rut=...
    if href.contains("uddg=") {
        return href.split("uddg=")
            .nth(1)
            .and_then(|rest| rest.split('&').next())
            .map(|encoded| url::form_urlencoded::parse(encoded.as_bytes())
                .next()
                .map(|(k, _)| k.into_owned())
                .unwrap_or_else(|| encoded.to_string()));
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
    "duckduckgo.com", "startpage.com", "mojeek.com",
    "brave.com", "yahoo.com", "bing.com", "google.com",
    "yandex.com", "yimg.com", "search.yahoo.com",
    "r.search.yahoo.com", "cc.bingj.com",
];

fn is_engine_domain(host: &str) -> bool {
    ENGINE_DOMAINS.iter().any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

fn is_tracking_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.contains("/redirect")
        || lower.contains("r.search.yahoo")
        || lower.contains("duckduckgo.com/y.js")
        || lower.contains("/url?")
        || lower.contains("clickserve")
        || lower.contains("ad.doubleclick")
        || lower.contains("googleads")
}

fn canonicalize_url(url: &str) -> String {
    let base = url.split('?').next().unwrap_or(url);
    let base = base.split('#').next().unwrap_or(base);
    base.trim_end_matches('/').to_string()
}

fn extract_surrounding_text(html: &str, anchor: &str, max_len: usize) -> String {
    let pos = match html.find(anchor) {
        Some(p) => p,
        None => return String::new(),
    };
    let start = pos.saturating_sub(300);
    let end = (pos + anchor.len() + 300).min(html.len());
    strip_tags(&html[start..end], max_len)
}

fn extract_snippet_near(html: &str, anchor: &str, max_len: usize) -> String {
    let pos = match html.find(anchor) {
        Some(p) => p + anchor.len(),
        None => return String::new(),
    };
    let end = (pos + 800).min(html.len());
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

fn build_entities(
    target: &Target,
    scan_id: &str,
    results: &[SearchResult],
) -> ModuleResult {
    let mut result = ModuleResult::new();
    if results.is_empty() {
        return result;
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

        if is_subdomain && seen_domains.insert(host.clone()) {
            let mut e = Entity::new(EntityKind::Domain, &host, 0.70, scan_id);
            e.tag(tags::SUBDOMAIN);
            e.tag("search-discovered");
            let mut ev = Evidence::new("search_engines", format!("Subdomain via {} search", r.engine))
                .with_attr("source_url", &r.url)
                .with_attr("engine", r.engine)
                .with_attr("query", &r.query);
            if !r.title.is_empty() {
                ev = ev.with_attr("page_title", &r.title);
            }
            if !r.snippet.is_empty() {
                let snip: String = r.snippet.chars().take(300).collect();
                ev = ev.with_attr("snippet", snip);
            }
            e.add_evidence(ev);
            result.push(e);
        } else if target_domain.as_ref().is_none_or(|td| domain != *td)
            && seen_domains.insert(domain.clone())
        {
            let mut e = Entity::new(EntityKind::Domain, &domain, 0.45, scan_id);
            e.tag(tags::EXTERNAL);
            e.tag("search-discovered");
            let mut ev = Evidence::new("search_engines", format!("Linked domain via {} search", r.engine))
                .with_attr("source_url", &r.url)
                .with_attr("engine", r.engine)
                .with_attr("query", &r.query);
            if !r.title.is_empty() {
                ev = ev.with_attr("page_title", &r.title);
            }
            e.add_evidence(ev);
            result.push(e);
        }

        // Extract emails from snippet text
        for email in extract_emails_from_text(&r.snippet) {
            if seen_emails.insert(email.clone()) {
                let mut e = Entity::new(EntityKind::Email, &email, 0.60, scan_id);
                e.tag(tags::WEB_SCRAPED);
                e.tag("search-discovered");
                e.add_evidence(
                    Evidence::new("search_engines", format!("Email in {} snippet", r.engine))
                        .with_attr("engine", r.engine)
                        .with_attr("source_url", &r.url)
                        .with_attr("query", &r.query),
                );
                result.push(e);
            }
        }

        // Extract phones from snippet text
        for phone in extract_phones_from_text(&r.snippet) {
            if seen_phones.insert(phone.clone()) {
                let mut e = Entity::new(EntityKind::Phone, &phone, 0.55, scan_id);
                e.tag(tags::WEB_SCRAPED);
                e.tag("search-discovered");
                e.add_evidence(
                    Evidence::new("search_engines", format!("Phone in {} snippet", r.engine))
                        .with_attr("engine", r.engine)
                        .with_attr("source_url", &r.url),
                );
                result.push(e);
            }
        }
    }

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
            if !email.ends_with(".png") && !email.ends_with(".jpg")
                && !email.ends_with(".gif") && !email.ends_with(".css")
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
    fn build_queries_domain_produces_four_dorks() {
        let t = Target::new(TargetKind::Domain, "acme.com");
        let q = build_queries(&t);
        assert_eq!(q.len(), 4);
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
        assert!(q.iter().any(|qr| qr.contains("pastebin.com") || qr.contains("github.com")));
    }

    #[test]
    fn build_queries_username_covers_social_platforms() {
        let t = Target::new(TargetKind::Username, "johndoe");
        let q = build_queries(&t);
        assert_eq!(q.len(), 3);
        assert!(q[0].contains("github.com") && q[0].contains("linkedin.com"));
        assert!(q[1].contains("twitter.com") && q[1].contains("reddit.com"));
        assert!(q[2].contains("profile"));
    }

    #[test]
    fn build_queries_fullname_covers_professional() {
        let t = Target::new(TargetKind::FullName, "Jane Doe");
        let q = build_queries(&t);
        assert_eq!(q.len(), 3);
        assert!(q[0].contains("linkedin.com"));
        assert!(q[1].contains("resume") || q[1].contains("cv"));
    }

    #[test]
    fn resolve_href_decodes_ddg_uddg() {
        let href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage&rut=abc123";
        let resolved = resolve_href(href);
        assert_eq!(resolved.as_deref(), Some("https://example.com/page"));
    }

    #[test]
    fn resolve_href_handles_protocol_relative() {
        let href = "//cdn.example.com/file.js";
        assert_eq!(resolve_href(href).as_deref(), Some("https://cdn.example.com/file.js"));
    }

    #[test]
    fn resolve_href_passes_absolute_urls() {
        assert_eq!(resolve_href("https://example.com").as_deref(), Some("https://example.com"));
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
        assert_eq!(canonicalize_url("https://example.com/page?ref=1#top"), "https://example.com/page");
        assert_eq!(canonicalize_url("https://example.com/page/"), "https://example.com/page");
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
        assert!(is_tracking_url("https://example.com/redirect?url=x"));
        assert!(is_tracking_url("https://ad.doubleclick.net/thing"));
        assert!(!is_tracking_url("https://example.com/page"));
    }

    #[test]
    fn engine_domain_filtering() {
        assert!(is_engine_domain("duckduckgo.com"));
        assert!(is_engine_domain("search.yahoo.com"));
        assert!(is_engine_domain("r.search.yahoo.com"));
        assert!(!is_engine_domain("example.com"));
    }

    #[test]
    fn registrable_domain_extraction() {
        assert_eq!(extract_registrable("sub.example.com"), "example.com");
        assert_eq!(extract_registrable("example.com"), "example.com");
        assert_eq!(extract_registrable("deep.sub.example.org"), "example.org");
    }
}
