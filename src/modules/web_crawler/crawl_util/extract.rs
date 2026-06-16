//! Pure content extractors for the web crawler.
//!
//! Everything here is a side-effect-free parser over a page body or header
//! map: emails, phone numbers, social-media handles, web-analytics tracking
//! ids, in-body API keys, framework fingerprints, page-type flags, and the
//! security-header audit. None of these touch the network; the network /
//! link-discovery half lives in [`super::discovery`]. Pure functions keep the
//! unit tests in `tests.rs` fast and deterministic.

use std::collections::HashSet;

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
pub(crate) fn extract_tracking_ids(body: &str, out: &mut HashSet<(String, String)>) {
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

pub(crate) fn extract_emails(body: &str, emails: &mut HashSet<String>) {
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

pub(crate) fn is_email_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b == b'+'
}

pub(crate) fn is_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
}

pub(crate) fn extract_phones(body: &str, phones: &mut HashSet<String>) {
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

/// Social-media platforms whose public profile URLs follow the canonical
/// `host[/sub]/<handle>` shape, paired with the path prefixes that introduce a
/// handle and the reserved path segments that are *not* user handles (help
/// pages, share intents, hashtags, …). Matching is done over `href` targets so
/// we only surface profiles the site actually links to — far lower noise than a
/// free-text `@name` scan.
struct SocialRule {
    /// Canonical platform label, used as the handle's `(platform)` tag.
    platform: &'static str,
    /// Host substrings that identify the platform (matched case-insensitively
    /// against the URL host, e.g. `twitter.com`, `x.com`).
    hosts: &'static [&'static str],
    /// Path segments that precede a handle (`""` = handle is the first path
    /// segment, e.g. `twitter.com/<handle>`; `"in"` = `linkedin.com/in/<h>`).
    prefixes: &'static [&'static str],
    /// First path segments that are platform routes, never user handles.
    reserved: &'static [&'static str],
}

const SOCIAL_RULES: &[SocialRule] = &[
    SocialRule {
        platform: "twitter",
        hosts: &["twitter.com", "x.com"],
        prefixes: &[""],
        reserved: &[
            "home",
            "search",
            "explore",
            "share",
            "intent",
            "hashtag",
            "i",
            "settings",
            "login",
            "signup",
            "messages",
            "notifications",
            "compose",
            "tos",
            "privacy",
        ],
    },
    SocialRule {
        platform: "instagram",
        hosts: &["instagram.com"],
        prefixes: &[""],
        reserved: &[
            "p",
            "reel",
            "reels",
            "explore",
            "stories",
            "accounts",
            "about",
            "developer",
            "directory",
            "tv",
        ],
    },
    SocialRule {
        platform: "linkedin",
        hosts: &["linkedin.com"],
        prefixes: &["in", "company", "school"],
        reserved: &["feed", "jobs", "learning", "help", "legal", "pulse"],
    },
    SocialRule {
        platform: "facebook",
        hosts: &["facebook.com", "fb.com"],
        prefixes: &[""],
        reserved: &[
            "sharer",
            "share",
            "login",
            "help",
            "policies",
            "pages",
            "groups",
            "events",
            "watch",
            "marketplace",
            "gaming",
            "profile.php",
            "dialog",
            "tr",
        ],
    },
    SocialRule {
        platform: "github",
        hosts: &["github.com"],
        prefixes: &[""],
        reserved: &[
            "about",
            "features",
            "pricing",
            "marketplace",
            "explore",
            "topics",
            "trending",
            "collections",
            "sponsors",
            "login",
            "join",
            "settings",
            "notifications",
            "search",
            "orgs",
            "apps",
        ],
    },
    SocialRule {
        platform: "youtube",
        hosts: &["youtube.com"],
        prefixes: &["c", "channel", "user"],
        reserved: &["watch", "embed", "results", "feed", "playlist", "shorts"],
    },
    SocialRule {
        platform: "tiktok",
        hosts: &["tiktok.com"],
        prefixes: &[""],
        reserved: &[
            "foryou",
            "following",
            "explore",
            "live",
            "tag",
            "music",
            "video",
            "search",
        ],
    },
    SocialRule {
        platform: "telegram",
        hosts: &["t.me", "telegram.me"],
        prefixes: &[""],
        reserved: &["s", "joinchat", "share", "addstickers", "iv"],
    },
    SocialRule {
        platform: "mastodon",
        hosts: &["mastodon.social", "mas.to", "fosstodon.org"],
        prefixes: &[""],
        reserved: &["about", "explore", "public", "auth", "settings"],
    },
];

/// A scraped social profile: `(platform, handle)`. The handle keeps any leading
/// `@` stripped and is lowercased so the same account linked twice (or as both
/// `@h` and `/h`) collapses to one entry.
pub(crate) type SocialHandle = (&'static str, String);

/// Extract social-media profile handles from `href` targets in the page body.
///
/// Reuses [`super::discovery::LinkIter`] so it sees exactly the links the
/// crawler would — `mailto:`/`tel:`/anchors are already filtered out. For each
/// link whose host matches a known platform and whose path matches that
/// platform's profile shape, the leading handle segment is captured (minus
/// reserved routes). Capped so a link-farm page can't flood the set.
pub(crate) fn extract_social_handles(body: &str, out: &mut HashSet<SocialHandle>) {
    const CAP: usize = 64;
    for href in super::discovery::LinkIter::new(body) {
        if out.len() >= CAP {
            return;
        }
        if let Some(handle) = parse_social_handle(href) {
            out.insert(handle);
        }
    }
}

/// Parse a single URL into `(platform, handle)` if it is a recognised social
/// profile link. Pure and allocation-light; the hot path (non-social link)
/// returns before any allocation.
fn parse_social_handle(url: &str) -> Option<SocialHandle> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);

    let rule = SOCIAL_RULES.iter().find(|r| r.hosts.contains(&host))?;

    let mut segments = parsed
        .path_segments()?
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return None;
    }

    // Resolve the handle segment: either the first segment (prefix == "") or the
    // segment immediately after a recognised prefix (linkedin.com/in/<h>).
    let first = segments.remove(0);
    let candidate = if rule.prefixes.iter().any(|p| p.is_empty()) && !first.eq_ignore_ascii_case("")
    {
        // First-segment handle, but the first segment might itself be a prefix
        // (e.g. youtube `c`/`channel`). Prefer an explicit prefix match.
        if rule
            .prefixes
            .iter()
            .any(|p| !p.is_empty() && p.eq_ignore_ascii_case(first))
        {
            segments.first().copied()?
        } else {
            first
        }
    } else if rule
        .prefixes
        .iter()
        .any(|p| !p.is_empty() && p.eq_ignore_ascii_case(first))
    {
        segments.first().copied()?
    } else {
        return None;
    };

    let handle = candidate.trim_start_matches('@').to_lowercase();
    if !is_plausible_handle(&handle) {
        return None;
    }
    if rule
        .reserved
        .iter()
        .any(|r| r.eq_ignore_ascii_case(&handle))
    {
        return None;
    }
    Some((rule.platform, handle))
}

/// A handle is 1-64 chars of letters, digits, `_`, `.`, or `-` — the union of
/// the platforms' allowed character sets. Anything else (a file with a dot
/// extension we missed, percent-encoding, query junk) is rejected.
fn is_plausible_handle(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 64
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
        // Reject things that are clearly filenames, not handles.
        && !h.ends_with(".html")
        && !h.ends_with(".php")
        && !h.ends_with(".aspx")
}

pub(crate) fn extract_api_keys_from_body(body: &str, domain: &str) {
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

pub(crate) fn detect_frameworks(body: &str, found: &mut HashSet<&'static str>) {
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

pub(crate) fn detect_page_types(body: &str, types: &mut HashSet<&'static str>) {
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

pub(crate) fn audit_security_headers(
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
