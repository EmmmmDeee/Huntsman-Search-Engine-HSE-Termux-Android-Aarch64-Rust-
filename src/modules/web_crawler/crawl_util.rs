use super::{CrawlState, MAX_PAGES, MAX_DEPTH, BINARY_EXTENSIONS};
use std::collections::HashSet;
use url::Url;
use crate::core::error::{Error, Result};

pub(super) async fn resolve_seed(http: &reqwest::Client, domain: &str) -> Result<String> {
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

pub(super) async fn fetch_robots(http: &reqwest::Client, seed: &Url, rules: &mut Vec<String>) {
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

pub(super) fn is_disallowed(url: &str, rules: &[String]) -> bool {
    let path = Url::parse(url)
        .ok()
        .map(|u| u.path().to_string())
        .unwrap_or_default();
    rules.iter().any(|r| path.starts_with(r))
}

pub(super) fn is_binary_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    let path = lower.split('?').next().unwrap_or(&lower);
    BINARY_EXTENSIONS
        .iter()
        .any(|ext| path.ends_with(&format!(".{ext}")))
}

pub(super) fn extract_links(
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

pub(super) struct LinkIter<'a> {
    remaining: &'a str,
}

impl<'a> LinkIter<'a> {
    pub(super) fn new(html: &'a str) -> Self {
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

pub(super) fn extract_registrable_domain(host: &str) -> Option<String> {
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

pub(super) fn extract_emails(body: &str, emails: &mut HashSet<String>) {
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

pub(super) fn is_email_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b == b'+'
}

pub(super) fn is_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
}

pub(super) fn extract_phones(body: &str, phones: &mut HashSet<String>) {
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

pub(super) fn detect_frameworks(body: &str, found: &mut HashSet<&'static str>) {
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

pub(super) fn detect_page_types(body: &str, types: &mut HashSet<&'static str>) {
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

pub(super) fn audit_security_headers(
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

