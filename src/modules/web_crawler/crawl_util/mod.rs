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
            // Cap the (untrusted) body at 1 MB while reading — `read_body_capped`
            // streams and stops, so an oversize page is bounded in memory instead
            // of fully buffered by `resp.text()` and then rejected. A body that
            // hits the cap (len == 1 MB) is treated as "too big", as before.
            const STATIC_BODY_CAP: usize = 1_000_000;
            let body = crate::util::http::read_body_capped(resp, STATIC_BODY_CAP).await?;
            if body.len() < 10 || body.len() >= STATIC_BODY_CAP {
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
    // robots.txt from an arbitrary host is untrusted; cap the read at 512 KB
    // (orders of magnitude above any real robots file) so a hostile "robots.txt"
    // can't OOM the device via resp.text() buffering the whole body.
    let Some(body) = crate::util::http::read_body_capped(resp, 512 * 1024).await else {
        return;
    };
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
    // Borrow the parsed path instead of allocating a `String`; `Url` owns the
    // backing buffer for the duration of this call.
    let parsed = Url::parse(url).ok();
    let path = parsed.as_ref().map(|u| u.path()).unwrap_or("");
    rules.iter().any(|r| path.starts_with(r))
}

pub(super) fn is_binary_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    let path = lower.split('?').next().unwrap_or(&lower);
    // Match `.<ext>` without allocating a `format!(".{ext}")` per extension:
    // require the suffix `<ext>` preceded by a literal `.`.
    BINARY_EXTENSIONS.iter().any(|ext| {
        path.len() > ext.len()
            && path.as_bytes()[path.len() - ext.len() - 1] == b'.'
            && path.ends_with(ext)
    })
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

    // The enqueued depth depends only on `current_url`, not on the individual
    // link, so compute it once instead of re-scanning the URL for every match.
    let child_depth =
        (current_url.matches('/').count().min(MAX_DEPTH as usize) as u32).saturating_add(1);

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
            // SSRF egress guard: never enqueue a link whose host is a
            // private/reserved IP literal, even when it matches the seed host
            // (which would require the seed itself to be internal). Mirrors the
            // guard in the crawl loop so the queue never holds an unfetchable
            // internal address.
            if !state.visited.contains(&clean)
                && state.visited.len() < MAX_PAGES * 2
                && !crate::util::preflight::url_host_is_private(&clean)
            {
                state.queue.push_back((clean, child_depth));
            }
            if host != base_host
                && crate::util::domains::is_proper_subdomain_of(&host, target_domain)
            {
                // `host` is not used again on this branch, so move it into the
                // set instead of cloning.
                state.subdomains.insert(host);
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
// Static tag helpers — eliminate per-iteration heap allocations for the
// most common tag prefixes. Known values return `&'static str`; unknown
// values fall back to `format!` (uncommon path, e.g. novel frameworks
// discovered at runtime — not possible today since `frameworks` is a
// `HashSet<&'static str>` populated only from the static `checks` table
// in `detect_frameworks`, but the fallback keeps future additions safe).
// ---------------------------------------------------------------------------

/// Return the `tech:<name>` tag string for a framework fingerprint.
///
/// All values in the static [`detect_frameworks`] check table are covered.
/// An unknown entry (unreachable with the current table) falls back to
/// a heap-allocated `String` via `format!`.
pub(super) fn tech_tag(fw: &'static str) -> std::borrow::Cow<'static, str> {
    let s: Option<&'static str> = match fw {
        "WordPress" => Some("tech:wordpress"),
        "jQuery" => Some("tech:jquery"),
        "Bootstrap" => Some("tech:bootstrap"),
        "React" => Some("tech:react"),
        "Next.js" => Some("tech:next.js"),
        "Nuxt.js" => Some("tech:nuxt.js"),
        "Vue.js" => Some("tech:vue.js"),
        "Angular" => Some("tech:angular"),
        "Ember.js" => Some("tech:ember.js"),
        "Drupal" => Some("tech:drupal"),
        "Joomla" => Some("tech:joomla"),
        "Laravel" => Some("tech:laravel"),
        "Django" => Some("tech:django"),
        "Ruby on Rails" => Some("tech:ruby-on-rails"),
        "Tailwind CSS" => Some("tech:tailwind-css"),
        "Material UI" => Some("tech:material-ui"),
        "ZURB Foundation" => Some("tech:zurb-foundation"),
        "MooTools" => Some("tech:mootools"),
        "Dojo" => Some("tech:dojo"),
        "ExtJS" => Some("tech:extjs"),
        "YUI" => Some("tech:yui"),
        "Prototype" => Some("tech:prototype"),
        "Backbone.js" => Some("tech:backbone.js"),
        "Svelte" => Some("tech:svelte"),
        "Astro" => Some("tech:astro"),
        "Gatsby" => Some("tech:gatsby"),
        "Shopify" => Some("tech:shopify"),
        "Squarespace" => Some("tech:squarespace"),
        "Wix" => Some("tech:wix"),
        "Webflow" => Some("tech:webflow"),
        "Cloudflare" => Some("tech:cloudflare"),
        "HTMX" => Some("tech:htmx"),
        "Alpine.js" => Some("tech:alpine.js"),
        "config-leak-detected" => Some("tech:config-leak-detected"),
        _ => None,
    };
    match s {
        Some(tag) => std::borrow::Cow::Borrowed(tag),
        None => std::borrow::Cow::Owned(format!("tech:{}", fw.to_lowercase().replace(' ', "-"))),
    }
}

/// Return the `page:<type>` tag string for a page-type classification.
///
/// All values emitted by [`detect_page_types`] are covered; the function
/// returns a `&'static str` in every reachable case.
pub(super) fn page_tag(pt: &'static str) -> &'static str {
    match pt {
        "has_forms" => "page:has_forms",
        "login_form" => "page:login_form",
        "file_upload" => "page:file_upload",
        "admin_panel" => "page:admin_panel",
        "javascript" => "page:javascript",
        "api_reference" => "page:api_reference",
        // Unreachable with the current `detect_page_types` table; included
        // so any future addition causes a compile-time miss rather than a
        // silent wrong tag.
        _ => pt,
    }
}

/// Return the `service:<name>` tag string for a known API-key service.
///
/// Service names come from `identify_api_key` / `key_harvest`, which
/// returns `&'static str`. Known names map to a pre-built static tag;
/// unknowns fall back to a heap-allocated `String`.
pub(super) fn service_tag(service: &'static str) -> std::borrow::Cow<'static, str> {
    let s: Option<&'static str> = match service {
        "openai" => Some("service:openai"),
        "anthropic" => Some("service:anthropic"),
        "github" => Some("service:github"),
        "stripe" => Some("service:stripe"),
        "aws" => Some("service:aws"),
        "google" => Some("service:google"),
        "sendgrid" => Some("service:sendgrid"),
        "twilio" => Some("service:twilio"),
        "slack" => Some("service:slack"),
        "mailgun" => Some("service:mailgun"),
        "shopify" => Some("service:shopify"),
        "digitalocean" => Some("service:digitalocean"),
        "heroku" => Some("service:heroku"),
        "npm" => Some("service:npm"),
        "firebase" => Some("service:firebase"),
        "square" => Some("service:square"),
        "paypal" => Some("service:paypal"),
        "coinbase" => Some("service:coinbase"),
        "braintree" => Some("service:braintree"),
        "cloudflare" => Some("service:cloudflare"),
        "datadog" => Some("service:datadog"),
        "newrelic" => Some("service:newrelic"),
        "sentry" => Some("service:sentry"),
        "okta" => Some("service:okta"),
        "auth0" => Some("service:auth0"),
        "jwt" => Some("service:jwt"),
        "azure" => Some("service:azure"),
        "gcp" => Some("service:gcp"),
        "huggingface" => Some("service:huggingface"),
        "groq" => Some("service:groq"),
        "cohere" => Some("service:cohere"),
        "mistral" => Some("service:mistral"),
        "replicate" => Some("service:replicate"),
        "stability-ai" => Some("service:stability-ai"),
        "xai" => Some("service:xai"),
        "shodan" => Some("service:shodan"),
        "censys" => Some("service:censys"),
        "hunter" => Some("service:hunter"),
        "proxycurl" => Some("service:proxycurl"),
        "hibp" => Some("service:hibp"),
        "dehashed" => Some("service:dehashed"),
        "securitytrails" => Some("service:securitytrails"),
        "abuseipdb" => Some("service:abuseipdb"),
        "virustotal" => Some("service:virustotal"),
        "greynoise" => Some("service:greynoise"),
        "ipinfo" => Some("service:ipinfo"),
        "maxmind" => Some("service:maxmind"),
        "telegram" => Some("service:telegram"),
        "discord" => Some("service:discord"),
        "mapbox" => Some("service:mapbox"),
        "algolia" => Some("service:algolia"),
        "mailchimp" => Some("service:mailchimp"),
        "hubspot" => Some("service:hubspot"),
        "salesforce" => Some("service:salesforce"),
        "zendesk" => Some("service:zendesk"),
        "intercom" => Some("service:intercom"),
        "segment" => Some("service:segment"),
        "amplitude" => Some("service:amplitude"),
        "mixpanel" => Some("service:mixpanel"),
        _ => None,
    };
    match s {
        Some(tag) => std::borrow::Cow::Borrowed(tag),
        None => std::borrow::Cow::Owned(format!("service:{service}")),
    }
}

/// Return the `roi:<label>` tag string for a [`crate::util::key_roi::KeyRoi`] tier.
///
/// Only three variants exist; all map to `&'static str` with no allocation.
pub(super) fn roi_tag(roi: crate::util::key_roi::KeyRoi) -> &'static str {
    match roi {
        crate::util::key_roi::KeyRoi::Terminal => "roi:terminal",
        crate::util::key_roi::KeyRoi::Expansion => "roi:expansion",
        crate::util::key_roi::KeyRoi::Multiplier => "roi:multiplier",
    }
}

// ---------------------------------------------------------------------------
// Tests — pure parsers were previously uncovered; these lock in their
// observed behaviour as a regression guard (the crawler and several other
// modules rely on this extraction logic).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
