use super::{BINARY_EXTENSIONS, CrawlState, MAX_DEPTH, MAX_PAGES};
use crate::core::error::{Error, Result};
use std::collections::HashSet;
use std::time::Duration;
use url::Url;

const CONFIG_LEAK_PATHS: &[&str] = &[
    // Plain env files (highest yield in practice)
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.staging",
    "/.env.development",
    "/.env.backup",
    "/.env.old",
    "/.env.bak",
    "/.env.save",
    "/.env.dist",
    "/.env.example",
    "/.env.sample",
    "/env.js",
    "/api/.env",
    "/admin/.env",
    "/private/.env",
    "/backend/.env",
    "/server/.env",
    // Generic config files often committed
    "/config.js",
    "/config.json",
    "/settings.json",
    "/secrets.json",
    "/secrets.yml",
    "/secrets.yaml",
    "/credentials.json",
    "/credentials.yml",
    "/keys.json",
    "/keys.txt",
    "/configuration.json",
    // VCS / IDE leaks (often contain remote URLs with embedded credentials)
    "/.git/config",
    "/.git/HEAD",
    "/.git/logs/HEAD",
    "/.gitconfig",
    "/.gitlab-ci.yml",
    "/.svn/entries",
    "/.hg/hgrc",
    "/.vscode/settings.json",
    "/.idea/workspace.xml",
    // WordPress
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config.php.save",
    "/wp-config.php.swp",
    "/wp-config.php~",
    // Cloud + container credentials
    "/.aws/credentials",
    "/.aws/config",
    "/.docker/config.json",
    "/.kube/config",
    "/terraform.tfstate",
    "/terraform.tfvars",
    "/.terraform/terraform.tfstate",
    "/serverless.yml",
    // Framework-specific exposed config
    "/api/config",
    "/api/env",
    "/api/v1/config",
    "/api/settings",
    "/_next/server/pages/_app.js",
    "/build/.env",
    "/dist/.env",
    "/static/.env",
    "/assets/.env",
    "/.next/required-server-files.json",
    // Debug + introspection endpoints (often leak env)
    "/debug",
    "/debug/vars",
    "/debug/pprof",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/info.php",
    "/.well-known/security.txt",
    "/.htpasswd",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    // Package manifests (sometimes carry tokens in scripts/registries)
    "/package.json",
    "/composer.json",
    "/.npmrc",
    "/.yarnrc",
    "/.yarnrc.yml",
    "/pip.conf",
    // CI/CD config
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.override.yml",
    "/.travis.yml",
    "/.circleci/config.yml",
    "/Jenkinsfile",
    "/.github/workflows",
    "/.drone.yml",
    "/buildspec.yml",
    "/bitbucket-pipelines.yml",
    // API surface (sometimes returns introspection / GraphQL schema with secrets)
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/graphql",
    "/graphiql",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/configprops",
    "/actuator/heapdump",
    // Backup files
    "/backup.sql",
    "/db.sql",
    "/dump.sql",
    "/backup.zip",
    "/backup.tar.gz",
];

/// One leak discovery: (path_relative_to_host_root, body_byte_count,
/// list of (service_name, raw_key_value) found in the body).
pub(super) type LeakHit = (String, usize, Vec<(&'static str, String)>);

/// Probe ~100 common config-file paths in parallel for exposed secrets.
///
/// Returns the (path, byte_count, services_found) tuples for any paths
/// that yielded data, so the caller can emit ApiKey entities and tag
/// the parent Domain. Operates on the HOST ROOT regardless of the
/// seed URL's path component — `/.env` is always at the host apex.
///
/// Bounded concurrency (16 simultaneous requests) prevents overwhelming
/// the target or our own connection pool. Each request has a 3s budget.
pub(super) async fn probe_config_leaks(
    http: &reqwest::Client,
    seed_url: &str,
    domain: &str,
) -> Vec<LeakHit> {
    use tokio::sync::Semaphore;
    use tokio::task::JoinSet;

    // Always probe at the host root — extract scheme://host/ from seed.
    let host_root = match url::Url::parse(seed_url) {
        Ok(u) => format!("{}://{}", u.scheme(), u.host_str().unwrap_or(domain)),
        Err(_) => seed_url.trim_end_matches('/').to_string(),
    };

    let timeout = Duration::from_millis(3000);
    let sem = std::sync::Arc::new(Semaphore::new(16));
    let mut set: JoinSet<Option<LeakHit>> = JoinSet::new();

    for path in CONFIG_LEAK_PATHS {
        let url = format!("{host_root}{path}");
        let http = http.clone();
        let sem = std::sync::Arc::clone(&sem);
        let path_static = *path;
        let domain_owned = domain.to_string();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            let resp = tokio::time::timeout(timeout, http.get(&url).send())
                .await
                .ok()?
                .ok()?;
            if resp.status().as_u16() != 200 {
                return None;
            }
            let ct = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            if ct.contains("text/html") && !path_static.ends_with(".html") {
                return None;
            }
            let body = resp.text().await.ok()?;
            if body.len() < 10 || body.len() > 1_000_000 {
                return None;
            }
            if body.contains("<html") || body.contains("<!DOCTYPE") {
                return None;
            }
            tracing::info!(
                domain = %domain_owned, path = path_static, bytes = body.len(),
                "config_leak: exposed file discovered"
            );
            // Scan body for keys AND emit any matches as (service, masked_key)
            // tuples for the caller to convert into ApiKey entities.
            // Shared token rules (delimiters + length window) with the every-body
            // scanner, so the two can't drift. A leaked config file is a
            // high-signal context, so unlike `found_keys` this classifier is the
            // generic-inclusive `identify_api_key` (a bare 32/64-hex token in a
            // committed `.env` is very likely a real key, not a password hash).
            let mut found = Vec::new();
            for t in crate::util::found_keys::key_tokens(&body, crate::util::found_keys::MAX_TOKEN)
            {
                if let Some((service, key_val)) =
                    crate::modules::oathnet_pro::key_harvest::identify_api_key(t)
                {
                    found.push((service, key_val.to_string()));
                }
            }
            // Also feed the global pool (existing behaviour).
            crate::util::http::scan_for_api_keys_with_source(
                &body,
                &format!("config_leak:{domain_owned}{path_static}"),
            );
            Some((path_static.to_string(), body.len(), found))
        });
    }

    let mut results = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(r)) = joined {
            results.push(r);
        }
    }
    results
}

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

        if crate::util::domains::is_or_subdomain_of(&host, base_host) {
            state.internal_links += 1;
            if host != base_host
                && crate::util::domains::is_proper_subdomain_of(&host, target_domain)
            {
                state.subdomains.insert(host.clone());
            }
            // SSRF egress guard: never enqueue a link whose host is a
            // private/reserved IP literal, even when it matches the seed host
            // (which would require the seed itself to be internal). Mirrors the
            // guard in the crawl loop so the queue never holds an unfetchable
            // internal address.
            if !state.visited.contains(&clean)
                && state.visited.len() < MAX_PAGES * 2
                && !crate::util::preflight::url_host_is_private(&clean)
            {
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
    crate::util::domains::registrable_domain(host)
}

/// File extensions that turn an `@`-bearing asset filename — retina sprites
/// (`logo@2x.webp`), icon fonts, stylesheets — into a bogus "email". The scan
/// drops a candidate whose tail matches one, cutting false positives.
/// **Deliberately excludes extensions that are also real gTLDs**: `.zip` and
/// `.mov` were delegated in 2023, so `someone@archive.zip` is a real address and
/// must NOT be filtered.
const ASSET_EXTENSIONS: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tiff", ".css", ".js",
    ".mjs", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf",
];

/// Extract web-analytics / tracking identifiers from page HTML. A tracking ID
/// shared across otherwise-unrelated sites is strong evidence of common
/// ownership — the "affiliate" pivot. **Pure regex over the page body, no API.**
/// Collects `(canonical_id, provider)`; bare-numeric IDs are provider-prefixed so
/// two providers can't collide on the same number. Capped so a hostile page can't
/// flood the set.
pub(super) fn extract_tracking_ids(body: &str, out: &mut HashSet<(String, String)>) {
    use regex::Regex;
    use std::sync::OnceLock;
    // (regex, provider, capture-group, prefix-for-bare-numeric-ids)
    static PATS: OnceLock<Vec<(Regex, &'static str, usize, &'static str)>> = OnceLock::new();
    let pats = PATS.get_or_init(|| {
        let c = |re: &str| Regex::new(re).expect("valid tracking-id regex");
        vec![
            (c(r"\bUA-\d{4,10}-\d{1,4}\b"), "google-analytics", 0, ""),
            (c(r"\bG-[A-Z0-9]{8,12}\b"), "google-analytics-4", 0, ""),
            (c(r"\bGTM-[A-Z0-9]{4,10}\b"), "google-tag-manager", 0, ""),
            (c(r"\bca-pub-\d{10,20}\b"), "google-adsense", 0, ""),
            (
                c(r#"fbq\(\s*['"]init['"]\s*,\s*['"](\d{6,20})['"]"#),
                "facebook-pixel",
                1,
                "fb-pixel:",
            ),
            (c(r"ym\(\s*(\d{5,12})\s*,"), "yandex-metrica", 1, "yandex:"),
            (c(r"hjid\s*[:=]\s*(\d{4,10})"), "hotjar", 1, "hotjar:"),
        ]
    });
    const CAP: usize = 64;
    for (re, provider, grp, prefix) in pats {
        for caps in re.captures_iter(body) {
            if out.len() >= CAP {
                return;
            }
            if let Some(m) = caps.get(*grp) {
                let value = if prefix.is_empty() {
                    m.as_str().to_string()
                } else {
                    format!("{prefix}{}", m.as_str())
                };
                out.insert((value, (*provider).to_string()));
            }
        }
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
        let domain = &body[i + 1..domain_end];
        // `domain.len() > 3` cheaply rejects a too-short TLD (`x@y.z`); the
        // `<= 254` cap is the RFC 5321 address-length ceiling (the validator caps
        // the local part but not the whole address). All chars here are ASCII, so
        // the lowercased length equals `domain_end - local_start`.
        if domain.contains('.') && domain.len() > 3 && domain_end - local_start <= 254 {
            let lower = body[local_start..domain_end].to_lowercase();
            // Share the canonical email-syntax definition (one '@', sane local,
            // no edge/consecutive dots) instead of the old ad-hoc local-non-empty
            // check, so the crawler can't surface `a..b@x.com` / `a@.x.com` /
            // oversized-local artifacts that validation rejects everywhere else.
            if crate::core::validation::validate_email_syntax(&lower).valid
                && !ASSET_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
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
        // A leading `+` must be followed by a valid E.164 country-code digit
        // (1-9). Rejecting `+0…` drops the false positives the old `is_ascii_digit`
        // check let through (e.g. `+01020103` scraped from concatenated page
        // numbers) without affecting any real international number.
        if bytes[i] == b'+' && i + 8 < bytes.len() && matches!(bytes[i + 1], b'1'..=b'9') {
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_digit()
                    || bytes[i] == b'-'
                    || bytes[i] == b' '
                    || bytes[i] == b'('
                    || bytes[i] == b')')
            {
                i += 1;
            }
            let cleaned: String = body[start..i]
                .chars()
                .filter(|c| c.is_ascii_digit() || *c == '+')
                .collect();
            // Accept only what the canonical E.164 validator accepts (8-15 digits
            // after the `+`) — the same definition the rest of the system uses, so
            // the crawler can't surface a too-short "+1 234567" that validation
            // would reject everywhere else.
            if crate::core::validation::validate_phone_e164(&cleaned).valid {
                phones.insert(cleaned);
            }
        } else {
            i += 1;
        }
    }
}

pub(super) fn extract_api_keys_from_body(body: &str, domain: &str) {
    use crate::modules::oathnet_pro::key_harvest::identify_api_key;

    let pool = crate::util::key_pool::global_pool();
    for word in body.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '`') {
        let trimmed = word.trim();
        if trimmed.len() < 16 || trimmed.len() > 200 {
            continue;
        }
        if let Some((service, key_val)) = identify_api_key(trimmed) {
            let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
            entry.notes = Some(format!("Web-scraped from {domain}"));
            entry.status = crate::util::key_pool::KeyStatus::Untested;
            entry.discovered_at = Some(crate::core::entity::unix_now());
            entry.discovered_by = Some(format!("web_crawler:{domain}"));
            if pool.add(service, entry) {
                tracing::info!(
                    service,
                    domain,
                    "API key discovered in page body (web_crawler)"
                );
            }
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

// ---------------------------------------------------------------------------
// Tests — pure parsers were previously uncovered; these lock in their
// observed behaviour as a regression guard (the crawler and several other
// modules rely on this extraction logic).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::module::ModuleResult;
    use reqwest::header::HeaderMap;
    use std::collections::VecDeque;

    fn empty_state() -> CrawlState {
        CrawlState {
            visited: HashSet::new(),
            queue: VecDeque::new(),
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
        }
    }

    #[test]
    fn extract_tracking_ids_finds_analytics_anchors() {
        let html = r#"
            <script>gtag('config','UA-123456-1');</script>
            <script async src="https://www.googletagmanager.com/gtag/js?id=G-ABCDE12345"></script>
            <!-- GTM-XYZ12 -->
            <ins class="adsbygoogle" data-ad-client="ca-pub-1234567890123456"></ins>
            <script>fbq('init', '987654321098765');</script>
            <script>ym(12345678, "init", {});</script>
            <script>hjid:1234567,hjsv:6</script>
        "#;
        let mut ids = HashSet::new();
        extract_tracking_ids(html, &mut ids);
        let got: std::collections::BTreeSet<&str> = ids.iter().map(|(v, _)| v.as_str()).collect();
        for want in [
            "UA-123456-1",
            "G-ABCDE12345",
            "GTM-XYZ12",
            "ca-pub-1234567890123456",
            "fb-pixel:987654321098765",
            "yandex:12345678",
            "hotjar:1234567",
        ] {
            assert!(got.contains(want), "missing {want}: {got:?}");
        }
        // A page with no analytics yields nothing.
        let mut none = HashSet::new();
        extract_tracking_ids("<html><body>plain</body></html>", &mut none);
        assert!(none.is_empty());
    }

    #[test]
    fn link_iter_extracts_only_real_hrefs() {
        let html = r##"<a href="/a">x</a> <a href='https://b.com/c'>y</a>
            <a href="#frag">z</a> <a href="mailto:e@x.com">m</a>
            <a href="javascript:void(0)">j</a> <a href="">empty</a> <a>noattr</a>"##;
        let links: Vec<&str> = LinkIter::new(html).collect();
        assert_eq!(links, vec!["/a", "https://b.com/c"]);
    }

    #[test]
    fn registrable_domain_takes_last_two_labels() {
        assert_eq!(
            extract_registrable_domain("www.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            extract_registrable_domain("example.com").as_deref(),
            Some("example.com")
        );
        // Multi-label public suffixes are handled via util::domains'
        // curated table (not a full PSL): a.b.co.uk → b.co.uk, the registrable
        // domain, rather than the bare suffix co.uk.
        assert_eq!(
            extract_registrable_domain("a.b.co.uk").as_deref(),
            Some("b.co.uk")
        );
        assert_eq!(extract_registrable_domain("localhost"), None);
    }

    #[test]
    fn binary_url_detection() {
        assert!(is_binary_url("https://x.com/file.pdf"));
        assert!(is_binary_url("https://x.com/IMG.PNG")); // case-insensitive
        assert!(is_binary_url("https://x.com/a.zip?v=2")); // query stripped
        assert!(!is_binary_url("https://x.com/page"));
        assert!(!is_binary_url("https://x.com/article.html"));
    }

    #[test]
    fn disallowed_matches_path_prefix() {
        let rules = vec!["/admin".to_string(), "/private/".to_string()];
        assert!(is_disallowed("https://x.com/admin/panel", &rules));
        assert!(is_disallowed("https://x.com/private/x", &rules));
        assert!(!is_disallowed("https://x.com/public", &rules));
        // Unparseable input → empty path → no rule matches (never panics).
        assert!(!is_disallowed("not a url", &rules));
    }

    #[test]
    fn email_extraction_filters_assets_and_dedups() {
        let mut emails = HashSet::new();
        extract_emails(
            "reach John.Doe@Example.com or sales@a.co — skip logo@2x.png and x@y.z",
            &mut emails,
        );
        assert!(emails.contains("john.doe@example.com")); // lowercased
        assert!(emails.contains("sales@a.co"));
        assert!(!emails.iter().any(|e| e.ends_with(".png"))); // image excluded
        assert!(!emails.contains("x@y.z")); // domain ≤3 chars rejected

        let mut dup = HashSet::new();
        extract_emails("a@b.com a@b.com", &mut dup);
        assert_eq!(dup.len(), 1);
    }

    #[test]
    fn email_extraction_rejects_syntactically_invalid_candidates() {
        // Routed through the canonical validator, malformed runs the byte-scan
        // can grab (consecutive dots, an edge dot) are no longer surfaced, while
        // an ordinary address alongside them still is.
        let mut emails = HashSet::new();
        extract_emails(
            "bad john..doe@example.com and .lead@example.com and trail.@example.com \
             but good real.person@example.com",
            &mut emails,
        );
        assert!(emails.contains("real.person@example.com"));
        assert!(!emails.contains("john..doe@example.com")); // consecutive dots
        assert!(!emails.contains(".lead@example.com")); // leading dot
        assert!(!emails.contains("trail.@example.com")); // trailing-dot local
    }

    #[test]
    fn email_extraction_filters_modern_asset_extensions_but_not_gtlds() {
        let mut emails = HashSet::new();
        extract_emails(
            "sprites logo@2x.webp icon@3x.svg hero@2x.jpeg fav@2x.ico font@1x.woff2 \
             — but real ops@acme.com and archive lover@backups.zip stay",
            &mut emails,
        );
        // Retina/asset filenames the old 5-extension filter missed are now dropped.
        for asset in [
            "logo@2x.webp",
            "icon@3x.svg",
            "hero@2x.jpeg",
            "fav@2x.ico",
            "font@1x.woff2",
        ] {
            assert!(!emails.contains(asset), "asset leaked as email: {asset}");
        }
        // Real addresses survive — including the `.zip` gTLD, which must NOT be
        // mistaken for a file extension.
        assert!(emails.contains("ops@acme.com"));
        assert!(emails.contains("lover@backups.zip"));
    }

    #[test]
    fn phone_extraction_bounds_digit_count() {
        let mut phones = HashSet::new();
        extract_phones(
            "call +1 415 555 2671 or +44 20 7946 0958, skip +123, junk +01020103",
            &mut phones,
        );
        assert!(phones.contains("+14155552671"));
        assert!(phones.iter().any(|p| p.starts_with("+44")));
        assert!(!phones.iter().any(|p| p.len() < 8)); // +123 is too short to qualify
        // E.164 country codes never start with 0 — `+0…` is a scrape artifact.
        assert!(!phones.iter().any(|p| p.starts_with("+0")));

        // Acceptance now goes through the canonical E.164 validator, so a 7-digit
        // "+X" (below the 8-digit E.164 minimum) is rejected here just as it is
        // everywhere else — no more crawler-only too-short numbers.
        let mut short = HashSet::new();
        extract_phones("ring +1 234567 now", &mut short); // 7 digits
        assert!(
            short.is_empty(),
            "7-digit number should be rejected: {short:?}"
        );
        let mut ok = HashSet::new();
        extract_phones("ring +1 2345678 now", &mut ok); // 8 digits
        assert!(ok.contains("+12345678"));
    }

    #[test]
    fn extractors_are_utf8_safe_on_adversarial_multibyte_html() {
        // These run on untrusted, possibly hostile page bodies. The byte-scan
        // indexes `body` directly, so the invariant is: multibyte UTF-8 around a
        // match must never split a code point (no panic), a valid ASCII match is
        // still recovered, and the non-ASCII runs themselves yield nothing.
        let mut emails = HashSet::new();
        // 2-/3-/4-byte chars (é, 日本語, 𝔘) abut and surround a real ASCII email,
        // including a multibyte char immediately before the local part.
        extract_emails(
            "日本語语alice@example.com café résumé 𝔘 contact:bob@test.co 日本語",
            &mut emails,
        );
        assert!(emails.contains("alice@example.com"), "got {emails:?}");
        assert!(emails.contains("bob@test.co"), "got {emails:?}");
        assert_eq!(
            emails.len(),
            2,
            "multibyte noise must not fabricate: {emails:?}"
        );

        // A large delimiter-free multibyte blob with no '@' must not panic and
        // must yield nothing (bounded, char-boundary-safe scan).
        let blob = "日本語".repeat(50_000);
        let mut none = HashSet::new();
        extract_emails(&blob, &mut none);
        assert!(none.is_empty());

        // Phones: a real E.164 number surrounded by multibyte text.
        let mut phones = HashSet::new();
        extract_phones("☎ 日本 +1 415 555 2671 語 résumé", &mut phones);
        assert!(phones.contains("+14155552671"), "got {phones:?}");
        let mut pnone = HashSet::new();
        extract_phones(&blob, &mut pnone); // must not panic
        assert!(pnone.is_empty());
    }

    #[test]
    fn char_class_predicates() {
        assert!(
            is_email_char(b'a')
                && is_email_char(b'.')
                && is_email_char(b'+')
                && is_email_char(b'_')
        );
        assert!(!is_email_char(b'@') && !is_email_char(b' '));
        assert!(is_domain_char(b'z') && is_domain_char(b'.') && is_domain_char(b'-'));
        assert!(!is_domain_char(b'_') && !is_domain_char(b'@'));
    }

    #[test]
    fn framework_detection_and_dedup() {
        let mut f = HashSet::new();
        detect_frameworks(
            "<link href='/wp-content/x.css'> jQuery here and /wp-includes/y",
            &mut f,
        );
        assert!(f.contains("WordPress"));
        assert!(f.contains("jQuery"));
        // Two WordPress markers collapse to one entry.
        assert_eq!(f.iter().filter(|&&n| n == "WordPress").count(), 1);

        let mut r = HashSet::new();
        detect_frameworks("import React from 'react'", &mut r);
        assert!(r.contains("React"));
    }

    #[test]
    fn page_type_detection() {
        let mut t = HashSet::new();
        detect_page_types(
            r#"<form><input type="password"><input type="file"></form><script>x</script> /admin apikey"#,
            &mut t,
        );
        for want in [
            "has_forms",
            "login_form",
            "file_upload",
            "javascript",
            "admin_panel",
            "api_reference",
        ] {
            assert!(t.contains(want), "missing page type: {want}");
        }
        let mut none = HashSet::new();
        detect_page_types("<p>plain text</p>", &mut none);
        assert!(none.is_empty());
    }

    #[test]
    fn security_header_audit_reports_presence() {
        let mut h = HeaderMap::new();
        h.insert(
            "content-security-policy",
            "default-src 'self'".parse().unwrap(),
        );
        h.insert("x-frame-options", "DENY".parse().unwrap());
        let mut results = Vec::new();
        audit_security_headers(&h, &mut results);
        assert_eq!(results.len(), 6);
        let map: std::collections::HashMap<_, _> = results.into_iter().collect();
        assert!(map["Content-Security-Policy"]);
        assert!(map["X-Frame-Options"]);
        assert!(!map["Strict-Transport-Security"]);
        assert!(!map["Referrer-Policy"]);
    }

    #[test]
    fn extract_links_classifies_internal_external_and_subdomains() {
        let mut state = empty_state();
        let body = r#"<a href="/about">a</a><a href="https://sub.example.com/x">b</a>
            <a href="https://other.org/page">c</a><a href="/logo.png">d</a>
            <a href="ftp://example.com/f">e</a>"#;
        extract_links(
            body,
            "https://example.com/",
            "example.com",
            "example.com",
            &mut state,
        );

        // /about (apex) + sub.example.com (subdomain) are internal.
        assert_eq!(state.internal_links, 2);
        assert!(state.subdomains.contains("sub.example.com"));
        // other.org is external.
        assert_eq!(state.external_links, 1);
        assert!(state.external_domains.contains("other.org"));
        // /about is queued; binary asset and non-http scheme are not.
        assert!(
            state
                .queue
                .iter()
                .any(|(u, _)| u.as_str() == "https://example.com/about")
        );
        assert!(!state.queue.iter().any(|(u, _)| u.contains("logo.png")));
        assert!(!state.queue.iter().any(|(u, _)| u.starts_with("ftp")));
    }

    #[test]
    fn extract_links_refuses_private_ip_literal_links() {
        // Worst case for the SSRF guard: the seed host IS the cloud-metadata
        // literal, so the same-host filter would otherwise enqueue its links.
        // The explicit egress guard must keep the queue empty regardless.
        let mut state = empty_state();
        let body = r#"<a href="/latest/meta-data/iam/security-credentials/">creds</a>
            <a href="http://127.0.0.1:8080/admin">loopback</a>"#;
        extract_links(
            body,
            "http://169.254.169.254/",
            "169.254.169.254",
            "169.254.169.254",
            &mut state,
        );
        assert!(
            state.queue.is_empty(),
            "private/reserved IP-literal links must never be enqueued, got {:?}",
            state.queue
        );
    }
}
