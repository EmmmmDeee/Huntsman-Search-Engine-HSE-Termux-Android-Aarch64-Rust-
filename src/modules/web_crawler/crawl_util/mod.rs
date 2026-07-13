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
                if let Some((service, key_val)) = crate::util::key_harvest::identify_api_key(t) {
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
    let path = parsed.as_ref().map_or("", url::Url::path);
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
        // Require the same alphabetic-TLD validity the canonical `EMAIL_RE` and its
        // sibling byte-scanner `util::extract::page_emails` enforce, single-sourced
        // through `host_has_alpha_tld`, so this third page byte-scanner cannot be more
        // permissive than they are: it rejects an IP-literal host (`admin@10.0.0.1`),
        // a numeric pseudo-TLD (`user@host.123`) and a 1-char TLD (`user@host.c`) that
        // the old `contains('.') && len > 3` gate admitted as bogus `Email` entities.
        // The `<= 254` cap is the RFC 5321 address-length ceiling (the syntax validator
        // caps the local part but not the whole address). All chars here are ASCII, so
        // the lowercased length equals `domain_end - local_start`.
        if crate::util::extract::host_has_alpha_tld(domain) && domain_end - local_start <= 254 {
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
    // Match the canonical `EMAIL_RE` local class `[A-Za-z0-9._%+-]` (includes `%`) so
    // this byte-scanner doesn't truncate a `%`-containing mailbox at the `%` — the
    // same class its `util::extract::page_emails` twin uses.
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+' | b'%')
}

pub(super) fn is_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
}

pub(super) fn extract_phones(body: &str, phones: &mut HashSet<String>) {
    crate::util::phone::scan_phones(body, usize::MAX, |p| {
        phones.insert(p);
    });
}

pub(super) fn extract_api_keys_from_body(body: &str, domain: &str) {
    use crate::util::found_keys::{MAX_TOKEN, key_tokens};
    use crate::util::key_harvest::identify_api_key;

    let pool = crate::util::key_pool::global_pool();
    for trimmed in key_tokens(body, MAX_TOKEN) {
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
    // All search patterns below are lowercase ASCII, so `find_ascii_ci` against the
    // RAW body (memchr/NEON, PR #220) is equivalent to the old `lower.contains(p)`
    // — but without allocating a Unicode-lowercased copy of up to a 64 KB crawled
    // body on every fetched page.
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
        if crate::util::str_util::find_ascii_ci(body, pattern).is_some() {
            found.insert(name);
        }
    }
}

pub(super) fn detect_page_types(body: &str, types: &mut HashSet<&'static str>) {
    use crate::util::str_util::find_ascii_ci;
    let has = |pat: &str| find_ascii_ci(body, pat).is_some();

    if has("<form") {
        types.insert("has_forms");

        if has("type=\"password\"") || has("type='password'") {
            types.insert("login_form");
        }
        if has("type=\"file\"") || has("type='file'") {
            types.insert("file_upload");
        }
    }

    if has("/admin") || has("administrator") || has("dashboard") {
        types.insert("admin_panel");
    }

    if has("<script") {
        types.insert("javascript");
    }

    if has("api-key") || has("apikey") || has("api_key") {
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
    include!("tests.rs");
}
