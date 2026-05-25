//! Multi-engine search scraping — 5 search engines, zero API keys.
//!
//! Queries DuckDuckGo, Brave, Startpage (Google-sourced), Mojeek,
//! and Yahoo (Bing-powered) with OSINT-targeted dork queries and
//! extracts entities from result URLs and snippets.
//!
//! Engine selection rationale (from Exa research):
//!   - DuckDuckGo HTML: most reliable, no JS needed, no CAPTCHA
//!   - Startpage: Google-sourced results, CAPTCHA-resistant
//!   - Mojeek: independent index, CAPTCHA-resistant
//!   - Brave: independent index, good coverage
//!   - Yahoo: Bing-powered, broad coverage
//!
//! Entity production:
//!   - Domain entities from result URLs (subdomains, linked sites)
//!   - Email entities from snippet text
//!   - Url entities for notable result pages
//!
//! These entities feed back into expansion, triggering dns_resolver,
//! crtsh, web_crawler, whois, and the full infrastructure stack.

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

const MAX_RESULTS_PER_ENGINE: usize = 15;
const INTER_ENGINE_MS: u64 = 300;

struct SearchResult {
    url: String,
    title: String,
    snippet: String,
    engine: &'static str,
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
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        30_000
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

            let engines: Vec<fn(&str) -> (String, &'static str)> = vec![
                |q| (format!("https://html.duckduckgo.com/html/?q={}", crate::util::http::urlencode(q)), "duckduckgo"),
                |q| (format!("https://www.startpage.com/sp/search?query={}", crate::util::http::urlencode(q)), "startpage"),
                |q| (format!("https://www.mojeek.com/search?q={}", crate::util::http::urlencode(q)), "mojeek"),
                |q| (format!("https://search.brave.com/search?q={}", crate::util::http::urlencode(q)), "brave"),
                |q| (format!("https://search.yahoo.com/search?p={}", crate::util::http::urlencode(q)), "yahoo"),
            ];

            for make_url in &engines {
                if ctx.cancel.is_cancelled() {
                    break;
                }
                let (url, engine_name) = make_url(query);
                if let Some(results) = fetch_and_parse(&ctx.http, &url, engine_name).await {
                    all_results.extend(results);
                }
                tokio::time::sleep(std::time::Duration::from_millis(INTER_ENGINE_MS)).await;
            }
        }

        Ok(build_entities(target, &ctx.scan_id, &all_results))
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
            format!("\"{v}\" email OR contact"),
        ],
        TargetKind::Email => vec![
            format!("\"{v}\""),
        ],
        TargetKind::Username => vec![
            format!("\"{v}\""),
        ],
        TargetKind::FullName => vec![
            format!("\"{v}\""),
        ],
        _ => Vec::new(),
    }
}

async fn fetch_and_parse(
    http: &reqwest::Client,
    url: &str,
    engine: &'static str,
) -> Option<Vec<SearchResult>> {
    let resp = http.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = resp.text().await.ok()?;
    if body.len() < 500 {
        return None;
    }
    Some(parse_results(&body, engine))
}

fn parse_results(html: &str, engine: &'static str) -> Vec<SearchResult> {
    let mut results = Vec::new();
    let mut seen_urls: HashSet<String> = HashSet::new();

    let engine_domains = [
        "duckduckgo.com", "startpage.com", "mojeek.com",
        "brave.com", "yahoo.com", "bing.com", "google.com",
        "yandex.com", "yimg.com", "duckduckgo.com",
    ];

    for href in HrefIter::new(html) {
        if results.len() >= MAX_RESULTS_PER_ENGINE {
            break;
        }

        let url = if href.starts_with("//") {
            format!("https:{href}")
        } else if href.starts_with("http://") || href.starts_with("https://") {
            href.to_string()
        } else {
            continue;
        };

        let host = extract_host(&url);
        if host.is_empty() || engine_domains.iter().any(|d| host.ends_with(d)) {
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
        let snippet = extract_snippet_near(html, href, 300);

        results.push(SearchResult {
            url: canonical,
            title,
            snippet,
            engine,
        });
    }
    results
}

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
            let idx = self.remaining.find("href=\"")?;
            self.remaining = &self.remaining[idx + 6..];
            let end = self.remaining.find('"')?;
            let href = &self.remaining[..end];
            self.remaining = &self.remaining[end + 1..];

            if href.is_empty()
                || href.starts_with('#')
                || href.starts_with("javascript:")
                || href.starts_with("mailto:")
            {
                continue;
            }
            return Some(href);
        }
    }
}

fn extract_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
        .unwrap_or_default()
}

fn is_tracking_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.contains("/redirect") || lower.contains("r.search.yahoo")
        || lower.contains("duckduckgo.com/y.js")
        || lower.contains("/url?") || lower.contains("clickserve")
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
    let start = pos.saturating_sub(200);
    let end = (pos + anchor.len() + 200).min(html.len());
    let region = &html[start..end];
    strip_tags(region, max_len)
}

fn extract_snippet_near(html: &str, anchor: &str, max_len: usize) -> String {
    let pos = match html.find(anchor) {
        Some(p) => p + anchor.len(),
        None => return String::new(),
    };
    let end = (pos + 600).min(html.len());
    let region = &html[pos..end];
    strip_tags(region, max_len)
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
    let target_domain = match target.kind {
        TargetKind::Domain => Some(target.value.to_lowercase()),
        TargetKind::Email => target.value.rsplit_once('@').map(|(_, d)| d.to_lowercase()),
        _ => None,
    };

    let engines_hit: HashSet<&str> = results.iter().map(|r| r.engine).collect();

    let mut parent = target.to_entity(0.82, scan_id);
    parent.tag("search-enriched");
    let engines_str: Vec<&str> = engines_hit.iter().copied().collect();
    parent.add_evidence(
        Evidence::new(
            "search_engines",
            format!(
                "Search engines found {} result(s) across {} engine(s)",
                results.len(),
                engines_hit.len()
            ),
        )
        .with_attr("result_count", results.len().to_string())
        .with_attr("engines", engines_str.join(", ")),
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
            let mut ev = Evidence::new("search_engines", format!("Subdomain found via {}", r.engine))
                    .with_attr("source_url", &r.url)
                    .with_attr("engine", r.engine);
            if !r.title.is_empty() {
                ev = ev.with_attr("title", &r.title);
            }
            e.add_evidence(ev);
            result.push(e);
        } else if target_domain.as_ref().is_none_or(|td| domain != *td) && seen_domains.insert(domain.clone()) {
            let mut e = Entity::new(EntityKind::Domain, &domain, 0.45, scan_id);
            e.tag(tags::EXTERNAL);
            e.tag("search-discovered");
            let mut ev = Evidence::new("search_engines", format!("Linked domain found via {}", r.engine))
                    .with_attr("source_url", &r.url)
                    .with_attr("engine", r.engine);
            if !r.title.is_empty() {
                ev = ev.with_attr("title", &r.title);
            }
            e.add_evidence(ev);
            result.push(e);
        }

        for email in extract_emails_from_text(&r.snippet) {
            if seen_emails.insert(email.clone()) {
                let mut e = Entity::new(EntityKind::Email, &email, 0.60, scan_id);
                e.tag(tags::WEB_SCRAPED);
                e.tag("search-discovered");
                e.add_evidence(
                    Evidence::new("search_engines", format!("Email found in {} snippet", r.engine))
                        .with_attr("engine", r.engine),
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
        if !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'.' && bytes[i - 1] != b'_' {
            i += 1;
            continue;
        }
        let mut local_start = i;
        while local_start > 0
            && (bytes[local_start - 1].is_ascii_alphanumeric()
                || bytes[local_start - 1] == b'.'
                || bytes[local_start - 1] == b'_'
                || bytes[local_start - 1] == b'-'
                || bytes[local_start - 1] == b'+')
        {
            local_start -= 1;
        }
        let mut domain_end = i + 1;
        while domain_end < len
            && (bytes[domain_end].is_ascii_alphanumeric()
                || bytes[domain_end] == b'.'
                || bytes[domain_end] == b'-')
        {
            domain_end += 1;
        }
        while domain_end > i + 1 && bytes[domain_end - 1] == b'.' {
            domain_end -= 1;
        }
        let domain = &text[i + 1..domain_end];
        if domain.contains('.') && domain.len() > 3 && (domain_end - local_start) <= 254 {
            let email = text[local_start..domain_end].to_lowercase();
            if !email.ends_with(".png") && !email.ends_with(".jpg") {
                emails.push(email);
            }
        }
        i = domain_end;
    }
    emails
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_domain_email_username_fullname() {
        let m = SearchEngines;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(m.accepts(&Target::new(TargetKind::Email, "x")));
        assert!(m.accepts(&Target::new(TargetKind::Username, "x")));
        assert!(m.accepts(&Target::new(TargetKind::FullName, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "x")));
    }

    #[test]
    fn build_queries_domain() {
        let t = Target::new(TargetKind::Domain, "acme.com");
        let q = build_queries(&t);
        assert_eq!(q.len(), 2);
        assert!(q[0].contains("site:acme.com"));
    }

    #[test]
    fn build_queries_email() {
        let t = Target::new(TargetKind::Email, "user@acme.com");
        let q = build_queries(&t);
        assert_eq!(q.len(), 1);
        assert!(q[0].contains("\"user@acme.com\""));
    }

    #[test]
    fn href_iter_extracts_urls() {
        let html = r#"<a href="https://example.com/page">Link</a> <a href="https://other.org">Other</a>"#;
        let links: Vec<&str> = HrefIter::new(html).collect();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0], "https://example.com/page");
    }

    #[test]
    fn parse_results_filters_engine_domains() {
        let html = r#"
            <a href="https://duckduckgo.com/something">Skip</a>
            <a href="https://realsite.com/page">Real</a>
            <a href="https://google.com/redirect">Skip</a>
        "#;
        let results = parse_results(html, "duckduckgo");
        assert_eq!(results.len(), 1);
        assert!(results[0].url.contains("realsite.com"));
    }

    #[test]
    fn canonicalize_strips_query_and_fragment() {
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
    fn strip_tags_extracts_text() {
        let html = "<b>Hello</b> <span>world</span>";
        assert_eq!(strip_tags(html, 100), "Hello world");
    }

    #[test]
    fn email_extraction_from_snippet() {
        let text = "Contact support@acme.com for help";
        let emails = extract_emails_from_text(text);
        assert_eq!(emails, vec!["support@acme.com"]);
    }

    #[test]
    fn tracking_url_detection() {
        assert!(is_tracking_url("https://r.search.yahoo.com/cbcl/something"));
        assert!(is_tracking_url("https://example.com/redirect?url=x"));
        assert!(!is_tracking_url("https://example.com/page"));
    }

    #[test]
    fn registrable_domain_extraction() {
        assert_eq!(extract_registrable("sub.example.com"), "example.com");
        assert_eq!(extract_registrable("example.com"), "example.com");
    }
}
