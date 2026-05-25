use std::collections::{HashSet, VecDeque};

use async_trait::async_trait;
use url::Url;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};

pub struct WebCrawler;

const MAX_PAGES: usize = 60;
const MAX_DEPTH: u32 = 3;
const BODY_CAP: usize = 65_536;
const INTER_REQUEST_MS: u64 = 200;

const BINARY_EXTENSIONS: &[&str] = &[
    "png", "gif", "jpg", "jpeg", "tiff", "tif", "webp", "svg", "ico", "pdf", "doc", "docx", "xls",
    "xlsx", "ppt", "pptx", "csv", "zip", "gz", "tar", "bz2", "rar", "7z", "iso", "mp3", "mp4",
    "avi", "mov", "flv", "mpg", "mpeg", "mkv", "wmv", "exe", "bin", "dmg", "msi", "deb", "rpm",
    "woff", "woff2", "ttf", "eot", "otf", "css", "map",
];

const NOTABLE_PAGES_CAP: usize = 20;
const NOTABLE_PAGE_TYPES: &[&str] = &["login_form", "file_upload", "admin_panel", "api_reference"];

struct CrawlState {
    visited: HashSet<String>,
    queue: VecDeque<(String, u32)>,
    pages_fetched: usize,
    disallow_rules: Vec<String>,
    result: ModuleResult,
    // Aggregated discovery
    external_domains: HashSet<String>,
    subdomains: HashSet<String>,
    emails: HashSet<String>,
    phones: HashSet<String>,
    frameworks: HashSet<&'static str>,
    page_types: HashSet<&'static str>,
    security_headers: Vec<(&'static str, bool)>,
    internal_links: usize,
    external_links: usize,
    notable_pages: Vec<String>,
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
        matches!(t.kind, TargetKind::Domain)
    }

    fn max_timeout_ms(&self) -> u64 {
        60_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let domain = target.value.trim().to_lowercase();
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }

        let seed = resolve_seed(&ctx.http, &domain).await?;

        let seed_url = Url::parse(&seed)
            .map_err(|e| Error::module("web_crawler", format!("bad seed URL: {e}")))?;
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
            frameworks: HashSet::new(),
            page_types: HashSet::new(),
            security_headers: Vec::new(),
            internal_links: 0,
            external_links: 0,
            notable_pages: Vec::new(),
        };

        fetch_robots(&ctx.http, &seed_url, &mut state.disallow_rules).await;

        state.queue.push_back((seed, 0));

        while let Some((url, depth)) = state.queue.pop_front() {
            if state.pages_fetched >= MAX_PAGES || ctx.cancel.is_cancelled() {
                break;
            }
            if state.visited.contains(&url) {
                continue;
            }
            state.visited.insert(url.clone());

            if is_disallowed(&url, &state.disallow_rules) {
                continue;
            }

            let resp = match ctx.http.get(&url).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let status = resp.status();
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

            let body = match resp.text().await {
                Ok(b) => {
                    if b.len() > BODY_CAP {
                        b[..BODY_CAP].to_string()
                    } else {
                        b
                    }
                }
                Err(_) => continue,
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

            if depth < MAX_DEPTH {
                extract_links(&body, &url, &base_host, &domain, &mut state);
            }

            if state.pages_fetched < MAX_PAGES {
                tokio::time::sleep(std::time::Duration::from_millis(INTER_REQUEST_MS)).await;
            }
        }

        build_entities(&domain, &base_host, &ctx.scan_id, &mut state);

        // Stealer-log cross-reference for the crawled domain
        let oathnet_key = crate::util::oathnet::resolve_key(ctx.key_opt(crate::util::oathnet::KEY_ENV));
        if !ctx.cancel.is_cancelled() {
            if let Ok(stealer_items) = crate::util::oathnet::search(
                oathnet_key,
                crate::util::oathnet::paths::STEALER,
                "domain",
                &target.value,
                20,
            ).await {
                if !stealer_items.is_empty() {
                    // Tag the parent domain entity
                    for e in &mut state.result.entities {
                        if e.kind == EntityKind::Domain
                            && e.value.to_lowercase() == target.value.to_lowercase()
                        {
                            e.tag(tags::STEALER_LOG);
                            e.tag(tags::COMPROMISED_SERVICE);
                            e.add_evidence(
                                Evidence::new(
                                    "web_crawler:oathnet",
                                    format!("{} stolen credential(s) reference {}", stealer_items.len(), target.value),
                                )
                                .with_attr("stealer_hits", stealer_items.len().to_string()),
                            );
                            break;
                        }
                    }

                    // Extract emails from stealer records
                    for item in stealer_items.iter().take(10) {
                        if let Some(emails) = item.get("email").and_then(|v| v.as_array()) {
                            for email_val in emails.iter().take(3) {
                                if let Some(email) = email_val.as_str()
                                    && email.contains('@')
                                    && email.len() >= 5
                                {
                                    let mut e = Entity::new(
                                        EntityKind::Email,
                                        email,
                                        0.55,
                                        &ctx.scan_id,
                                    );
                                    e.tag(tags::BREACH);
                                    e.tag(tags::STEALER_LOG);
                                    e.tag("oathnet-enriched");
                                    e.add_evidence(
                                        Evidence::new(
                                            "web_crawler:oathnet",
                                            format!("Credential stolen from {}", target.value),
                                        )
                                        .with_attr("source", "stealer"),
                                    );
                                    state.result.push(e);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(state.result)
    }
}

async fn resolve_seed(http: &reqwest::Client, domain: &str) -> Result<String> {
    for scheme in ["https", "http"] {
        let url = format!("{scheme}://{domain}/");
        match http.head(&url).send().await {
            Ok(r) if r.status().is_success() || r.status().is_redirection() => {
                return Ok(r.url().as_str().to_string());
            }
            _ => continue,
        }
    }
    Err(Error::module(
        "web_crawler",
        format!("{domain}: neither HTTPS nor HTTP responded"),
    ))
}

async fn fetch_robots(http: &reqwest::Client, seed: &Url, rules: &mut Vec<String>) {
    let robots_url = format!(
        "{}://{}/robots.txt",
        seed.scheme(),
        seed.host_str().unwrap_or("")
    );
    let Ok(resp) = http.get(&robots_url).send().await else {
        return;
    };
    if !resp.status().is_success() {
        return;
    }
    let Ok(body) = resp.text().await else { return };
    let mut in_wildcard_agent = false;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let lower = trimmed.to_lowercase();
        if lower.starts_with("user-agent:") {
            let agent = lower.strip_prefix("user-agent:").unwrap_or("").trim();
            in_wildcard_agent = agent == "*" || agent.contains("huntsman");
        } else if in_wildcard_agent
            && lower.starts_with("disallow:")
            && let Some(path) = trimmed.split_once(':').map(|(_, p)| p.trim())
            && !path.is_empty()
        {
            rules.push(path.to_string());
        }
    }
}

fn is_disallowed(url: &str, rules: &[String]) -> bool {
    let path = Url::parse(url)
        .ok()
        .map(|u| u.path().to_string())
        .unwrap_or_default();
    rules.iter().any(|r| path.starts_with(r))
}

fn is_binary_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    let path = lower.split('?').next().unwrap_or(&lower);
    BINARY_EXTENSIONS
        .iter()
        .any(|ext| path.ends_with(&format!(".{ext}")))
}

fn extract_links(
    body: &str,
    current_url: &str,
    base_host: &str,
    target_domain: &str,
    state: &mut CrawlState,
) {
    let base = match Url::parse(current_url) {
        Ok(u) => u,
        Err(_) => return,
    };

    for cap in LinkIter::new(body) {
        let resolved = match base.join(cap) {
            Ok(u) => u,
            Err(_) => continue,
        };

        let scheme = resolved.scheme();
        if scheme != "http" && scheme != "https" {
            continue;
        }

        let host = match resolved.host_str() {
            Some(h) => h.to_lowercase(),
            None => continue,
        };

        let clean = format!("{}://{}{}", scheme, host, resolved.path());

        if is_binary_url(&clean) {
            continue;
        }

        if host == base_host || host.ends_with(&format!(".{base_host}")) {
            state.internal_links += 1;
            if host != base_host && host.ends_with(&format!(".{target_domain}")) {
                state.subdomains.insert(host.clone());
            }
            if !state.visited.contains(&clean) && state.visited.len() < MAX_PAGES * 2 {
                let depth = current_url.matches('/').count().min(MAX_DEPTH as usize) as u32;
                state.queue.push_back((clean, depth + 1));
            }
        } else {
            state.external_links += 1;
            if let Some(dom) = extract_registrable_domain(&host) {
                state.external_domains.insert(dom);
            }
        }
    }
}

struct LinkIter<'a> {
    remaining: &'a str,
}

impl<'a> LinkIter<'a> {
    fn new(html: &'a str) -> Self {
        Self { remaining: html }
    }
}

impl<'a> Iterator for LinkIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let idx = self.remaining.find("href=")?;
            self.remaining = &self.remaining[idx + 5..];

            let (quote, rest) = if self.remaining.starts_with('"') {
                ('"', &self.remaining[1..])
            } else if self.remaining.starts_with('\'') {
                ('\'', &self.remaining[1..])
            } else {
                continue;
            };

            let end = match rest.find(quote) {
                Some(e) => e,
                None => continue,
            };

            let href = &rest[..end];
            self.remaining = &rest[end + 1..];

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

fn extract_registrable_domain(host: &str) -> Option<String> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        Some(format!(
            "{}.{}",
            parts[parts.len() - 2],
            parts[parts.len() - 1]
        ))
    } else {
        None
    }
}

fn extract_emails(body: &str, emails: &mut HashSet<String>) {
    let bytes = body.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        if bytes[i] != b'@' || i == 0 || i + 1 >= len {
            i += 1;
            continue;
        }
        if !is_email_char(bytes[i - 1]) || !bytes[i + 1].is_ascii_alphanumeric() {
            i += 1;
            continue;
        }
        let mut local_start = i;
        while local_start > 0 && is_email_char(bytes[local_start - 1]) {
            local_start -= 1;
        }
        let mut domain_end = i + 1;
        while domain_end < len && is_domain_char(bytes[domain_end]) {
            domain_end += 1;
        }
        while domain_end > i + 1 && bytes[domain_end - 1] == b'.' {
            domain_end -= 1;
        }
        let local = &body[local_start..i];
        let domain = &body[i + 1..domain_end];
        if !local.is_empty()
            && domain.contains('.')
            && domain.len() > 3
            && domain_end - local_start <= 254
        {
            let lower = body[local_start..domain_end].to_lowercase();
            if !lower.ends_with(".png")
                && !lower.ends_with(".jpg")
                && !lower.ends_with(".gif")
                && !lower.ends_with(".css")
                && !lower.ends_with(".js")
            {
                emails.insert(lower);
            }
        }
        i = domain_end;
    }
}

fn is_email_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b == b'+'
}

fn is_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
}

fn extract_phones(body: &str, phones: &mut HashSet<String>) {
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' && i + 8 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            let start = i;
            i += 1;
            let mut digits = 0u32;
            while i < bytes.len()
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
                let raw = &body[start..i];
                let cleaned: String = raw
                    .chars()
                    .filter(|c| c.is_ascii_digit() || *c == '+')
                    .collect();
                phones.insert(cleaned);
            }
        } else {
            i += 1;
        }
    }
}

fn detect_frameworks(body: &str, found: &mut HashSet<&'static str>) {
    let lower = body.to_lowercase();
    let checks: &[(&str, &'static str)] = &[
        ("wp-content/", "WordPress"),
        ("wp-includes/", "WordPress"),
        ("/wp-json/", "WordPress"),
        ("jquery", "jQuery"),
        ("bootstrap", "Bootstrap"),
        ("react", "React"),
        ("reactdom", "React"),
        ("__next", "Next.js"),
        ("_next/static", "Next.js"),
        ("__nuxt", "Nuxt.js"),
        ("vue.js", "Vue.js"),
        ("vue.min.js", "Vue.js"),
        ("angular", "Angular"),
        ("ng-app", "Angular"),
        ("ng-controller", "Angular"),
        ("ember", "Ember.js"),
        ("drupal", "Drupal"),
        ("/sites/default/files", "Drupal"),
        ("joomla", "Joomla"),
        ("/administrator/", "Joomla"),
        ("laravel", "Laravel"),
        ("csrftoken", "Django"),
        ("django", "Django"),
        ("rails", "Ruby on Rails"),
        ("turbolinks", "Ruby on Rails"),
        ("tailwindcss", "Tailwind CSS"),
        ("material-ui", "Material UI"),
        ("mui", "Material UI"),
        ("foundation.js", "ZURB Foundation"),
        ("mootools", "MooTools"),
        ("dojo", "Dojo"),
        ("extjs", "ExtJS"),
        ("ext.js", "ExtJS"),
        ("yui", "YUI"),
        ("prototype.js", "Prototype"),
        ("backbone", "Backbone.js"),
        ("svelte", "Svelte"),
        ("astro", "Astro"),
        ("gatsby", "Gatsby"),
        ("shopify", "Shopify"),
        ("cdn.shopify.com", "Shopify"),
        ("squarespace", "Squarespace"),
        ("wix.com", "Wix"),
        ("webflow", "Webflow"),
        ("cloudflare", "Cloudflare"),
        ("htmx", "HTMX"),
        ("alpinejs", "Alpine.js"),
        ("alpine.js", "Alpine.js"),
    ];

    for (pattern, name) in checks {
        if lower.contains(pattern) {
            found.insert(name);
        }
    }
}

fn detect_page_types(body: &str, types: &mut HashSet<&'static str>) {
    let lower = body.to_lowercase();

    if lower.contains("<form") {
        types.insert("has_forms");

        if lower.contains("type=\"password\"") || lower.contains("type='password'") {
            types.insert("login_form");
        }
        if lower.contains("type=\"file\"") || lower.contains("type='file'") {
            types.insert("file_upload");
        }
    }

    if lower.contains("/admin") || lower.contains("administrator") || lower.contains("dashboard") {
        types.insert("admin_panel");
    }

    if lower.contains("<script") {
        types.insert("javascript");
    }

    if lower.contains("api-key") || lower.contains("apikey") || lower.contains("api_key") {
        types.insert("api_reference");
    }
}

fn audit_security_headers(
    headers: &reqwest::header::HeaderMap,
    results: &mut Vec<(&'static str, bool)>,
) {
    let checks: &[(&'static str, &str)] = &[
        ("Strict-Transport-Security", "strict-transport-security"),
        ("Content-Security-Policy", "content-security-policy"),
        ("X-Frame-Options", "x-frame-options"),
        ("X-Content-Type-Options", "x-content-type-options"),
        ("Permissions-Policy", "permissions-policy"),
        ("Referrer-Policy", "referrer-policy"),
    ];
    for (label, header_name) in checks {
        results.push((label, headers.get(*header_name).is_some()));
    }
}

fn build_entities(domain: &str, _base_host: &str, scan_id: &str, state: &mut CrawlState) {
    let mut entity = Entity::new(EntityKind::Domain, domain, 0.90, scan_id);
    entity.tag(tags::WEB);
    entity.tag(tags::CRAWLED);

    for fw in &state.frameworks {
        entity.tag(format!("tech:{}", fw.to_lowercase().replace(' ', "-")));
    }
    for pt in &state.page_types {
        entity.tag(format!("page:{pt}"));
    }

    let missing_headers: Vec<&str> = state
        .security_headers
        .iter()
        .filter(|(_, present)| !present)
        .map(|(name, _)| *name)
        .collect();
    entity.tag_if(!missing_headers.is_empty(), tags::MISSING_SECURITY_HEADERS);

    let mut ev = Evidence::new(
        "web_crawler",
        format!(
            "Crawled {domain}: {} pages, {} internal links, {} external links",
            state.pages_fetched, state.internal_links, state.external_links
        ),
    )
    .with_attr("pages_crawled", state.pages_fetched.to_string())
    .with_attr("internal_links", state.internal_links.to_string())
    .with_attr("external_links", state.external_links.to_string())
    .with_attr("max_depth", MAX_DEPTH.to_string());

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

    for sub in &state.subdomains {
        let mut e = Entity::new(EntityKind::Domain, sub.as_str(), 0.82, scan_id);
        e.tag(tags::WEB);
        e.tag(tags::SUBDOMAIN);
        e.add_evidence(
            Evidence::new(
                "web_crawler",
                format!("Subdomain discovered by crawling {domain}"),
            )
            .with_attr("parent_domain", domain),
        );
        state.result.push(e);
    }

    for ext in &state.external_domains {
        let mut e = Entity::new(EntityKind::Domain, ext.as_str(), 0.50, scan_id);
        e.tag(tags::EXTERNAL);
        e.add_evidence(
            Evidence::new(
                "web_crawler",
                format!("External domain linked from {domain}"),
            )
            .with_attr("source_domain", domain),
        );
        state.result.push(e);
    }

    for email in &state.emails {
        let mut e = Entity::new(EntityKind::Email, email.as_str(), 0.75, scan_id);
        e.tag(tags::WEB_SCRAPED);
        e.add_evidence(
            Evidence::new("web_crawler", format!("Email found on {domain}"))
                .with_attr("source_domain", domain),
        );
        state.result.push(e);
    }

    for phone in &state.phones {
        let mut e = Entity::new(EntityKind::Phone, phone.as_str(), 0.65, scan_id);
        e.tag(tags::WEB_SCRAPED);
        e.add_evidence(
            Evidence::new("web_crawler", format!("Phone found on {domain}"))
                .with_attr("source_domain", domain),
        );
        state.result.push(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_domain_only() {
        let m = WebCrawler;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn timeout_is_60s() {
        assert_eq!(WebCrawler.max_timeout_ms(), 60_000);
    }

    #[test]
    fn link_iter_extracts_hrefs() {
        let html = concat!(
            r#"<a href="https://example.com/page1">Link 1</a>"#,
            r#" <a href='/page2'>Link 2</a>"#,
            r##" <a href="#anchor">Skip</a>"##,
            r#" <a href="javascript:void(0)">Skip</a>"#,
            r#" <a href="mailto:x@y.com">Skip</a>"#,
        );
        let links: Vec<&str> = LinkIter::new(html).collect();
        assert_eq!(links, vec!["https://example.com/page1", "/page2"]);
    }

    #[test]
    fn link_iter_handles_empty_and_malformed() {
        let html = r#"<a href="">empty</a><a href>no quote</a>"#;
        let links: Vec<&str> = LinkIter::new(html).collect();
        assert!(links.is_empty());
    }

    #[test]
    fn email_extraction() {
        let body = "Contact us at support@acme.com or sales@test.org for info";
        let mut emails = HashSet::new();
        extract_emails(body, &mut emails);
        assert!(emails.contains("support@acme.com"));
        assert!(emails.contains("sales@test.org"));
    }

    #[test]
    fn email_extraction_skips_image_extensions() {
        let body = "icon@2x.png and logo@3x.jpg should be skipped";
        let mut emails = HashSet::new();
        extract_emails(body, &mut emails);
        assert!(emails.is_empty());
    }

    #[test]
    fn phone_extraction() {
        let body = "Call us at +1-555-123-4567 or +44 20 7946 0958";
        let mut phones = HashSet::new();
        extract_phones(body, &mut phones);
        assert_eq!(phones.len(), 2);
        assert!(phones.iter().any(|p| p.contains("+1555")));
    }

    #[test]
    fn framework_detection_wordpress() {
        let mut found = HashSet::new();
        detect_frameworks(
            "<link rel='stylesheet' href='/wp-content/themes/foo/style.css'>",
            &mut found,
        );
        assert!(found.contains("WordPress"));
    }

    #[test]
    fn framework_detection_react_and_nextjs() {
        let mut found = HashSet::new();
        detect_frameworks(
            r#"<div id="__next"><script src="/_next/static/chunks/main.js"></script></div>"#,
            &mut found,
        );
        assert!(found.contains("Next.js"));
    }

    #[test]
    fn framework_detection_multiple() {
        let mut found = HashSet::new();
        let body = "<script src='/jquery.min.js'></script><link href='bootstrap.css'><script src='vue.js'></script>";
        detect_frameworks(body, &mut found);
        assert!(found.contains("jQuery"));
        assert!(found.contains("Bootstrap"));
        assert!(found.contains("Vue.js"));
    }

    #[test]
    fn page_type_detection() {
        let mut types = HashSet::new();
        let body =
            r#"<form method="POST"><input type="password" name="pw"><input type="file"></form>"#;
        detect_page_types(body, &mut types);
        assert!(types.contains("has_forms"));
        assert!(types.contains("login_form"));
        assert!(types.contains("file_upload"));
    }

    #[test]
    fn page_type_admin_detection() {
        let mut types = HashSet::new();
        detect_page_types("<a href='/admin/dashboard'>Admin</a>", &mut types);
        assert!(types.contains("admin_panel"));
    }

    #[test]
    fn security_header_audit() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "strict-transport-security",
            "max-age=31536000".parse().unwrap(),
        );
        headers.insert("x-frame-options", "DENY".parse().unwrap());

        let mut results = Vec::new();
        audit_security_headers(&headers, &mut results);

        let hsts = results
            .iter()
            .find(|(n, _)| *n == "Strict-Transport-Security");
        assert_eq!(hsts, Some(&("Strict-Transport-Security", true)));

        let csp = results
            .iter()
            .find(|(n, _)| *n == "Content-Security-Policy");
        assert_eq!(csp, Some(&("Content-Security-Policy", false)));
    }

    #[test]
    fn binary_url_filtering() {
        assert!(is_binary_url("https://example.com/image.png"));
        assert!(is_binary_url("https://example.com/doc.pdf?v=2"));
        assert!(is_binary_url("https://example.com/font.woff2"));
        assert!(!is_binary_url("https://example.com/page"));
        assert!(!is_binary_url("https://example.com/about.html"));
    }

    #[test]
    fn robots_disallow_check() {
        let rules = vec!["/admin/".to_string(), "/private".to_string()];
        assert!(is_disallowed("https://example.com/admin/users", &rules));
        assert!(is_disallowed("https://example.com/private", &rules));
        assert!(!is_disallowed("https://example.com/about", &rules));
    }

    #[test]
    fn registrable_domain_extraction() {
        assert_eq!(
            extract_registrable_domain("www.example.com"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_registrable_domain("cdn.assets.example.org"),
            Some("example.org".into())
        );
        assert_eq!(extract_registrable_domain("localhost"), None);
    }
}
