use super::helpers::*;
use super::{EngineSpec, MAX_RESULTS_PER_ENGINE, SearchResult};
use crate::modules::oathnet_pro::key_harvest::identify_api_key;

pub(super) async fn fetch_and_parse(
    url: &str,
    engine: &EngineSpec,
    query: &str,
    post_body: Option<&str>,
) -> Option<Vec<SearchResult>> {
    match try_fetch(url, engine.ua, post_body).await {
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
        && let FetchOutcome::Body(body) = try_fetch(url, engine.ua_alt, post_body).await
    {
        let results = parse_results(&body, engine.name, query);
        if !results.is_empty() {
            return Some(results);
        }
    }

    None
}

pub(super) async fn try_fetch(url: &str, ua: &str, post_body: Option<&str>) -> FetchOutcome {
    let body = if let Some(data) = post_body {
        crate::util::curl::fetch_post_with_ua(url, data, 8_000, ua).await
    } else {
        crate::util::curl::fetch_with_ua(url, 8_000, ua).await
    };

    // If direct fetch failed, try through the HUNTSMAN_SEARCH_PROXY env
    // or fall back to the proxy pool (populated by util::proxy::harvest)
    let body = match body {
        Some(b) if b.len() >= 500 => Some(b),
        _ => {
            if let Ok(proxy) = std::env::var("HUNTSMAN_SEARCH_PROXY")
                && !proxy.is_empty()
            {
                return match crate::util::curl::fetch_via_proxy(url, 8_000, ua, &proxy).await {
                    Some(b) if b.len() >= 500 && !is_captcha_page(&b) => FetchOutcome::Body(b),
                    Some(_) => FetchOutcome::Blocked,
                    None => FetchOutcome::Unreachable,
                };
            }
            body
        }
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

/// High-confidence anti-bot / CAPTCHA *vendor* fingerprints. Each string is
/// specific enough that it essentially only appears when the actual challenge
/// widget or script is embedded, so a single match is decisive. Compared
/// case-insensitively, so every entry MUST be lowercase.
///
/// Kept data-driven (rather than a chain of `||`) so a new interstitial
/// vendor is a one-line addition with a matching test, and so the matcher
/// stays a strict superset of the engines' real-world block pages.
pub(super) const BLOCK_VENDOR_SIGNATURES: &[&str] = &[
    // Cloudflare managed challenge / Turnstile / "Just a moment" interstitial
    "challenges.cloudflare.com",
    "/cdn-cgi/challenge-platform",
    "cf-chl-", // cf-chl-opt / cf-chl-bypass challenge tokens
    // Google reCAPTCHA + the classic "/sorry/" rate-limit interstitial
    "/recaptcha/api",
    "g-recaptcha",
    "grecaptcha",
    "/sorry/index",
    // hCaptcha
    "hcaptcha.com",
    "h-captcha",
    // DataDome
    "captcha-delivery.com",
    "datadome",
    // PerimeterX / HUMAN
    "perimeterx",
    "px-captcha",
    "_pxhd",
    // FunCaptcha / Arkose Labs
    "funcaptcha",
    "arkoselabs",
    // Yandex SmartCaptcha
    "smartcaptcha",
    "showcaptcha",
    // DuckDuckGo anomaly interstitial / generic retry wall
    "anomaly-modal",
    "httpservice/retry",
];

/// Lower-confidence challenge *phrases*. Each entry is an AND-set: every
/// token must be present for the page to count as a block. Requiring two
/// independent tokens keeps a real results page that merely *mentions* one
/// phrase (e.g. a SERP whose snippets discuss Cloudflare, or an article on
/// "unusual traffic" in analytics) from being misread as a block — the
/// previous single-substring detector flagged exactly those false positives.
/// Multi-word phrases specific enough on their own are single-element sets.
/// All tokens MUST be lowercase.
pub(super) const BLOCK_PHRASE_SETS: &[&[&str]] = &[
    &["just a moment", "cloudflare"],
    &["attention required", "cloudflare"],
    &["checking your browser", "cloudflare"],
    &["unusual traffic", "network"], // Google: "...unusual traffic from your computer network"
    &["before you continue", "consent"],
    &["request unsuccessful", "incapsula"], // Imperva / Incapsula
    &["are not a robot"],
    &["verify you are human"],
    &["enable javascript and cookies to continue"],
    &["access to this page has been denied"], // PerimeterX classic block page
];

/// Detect CAPTCHA / anti-bot interstitial pages that carry no real results.
///
/// Two-tier match: a single high-confidence [`BLOCK_VENDOR_SIGNATURES`]
/// fingerprint is decisive; otherwise an entire AND-set in
/// [`BLOCK_PHRASE_SETS`] must match. This is a strict superset of the old
/// detector's coverage while cutting its false-positive surface.
pub(super) fn is_captcha_page(body: &str) -> bool {
    let lower = body.to_lowercase();
    if BLOCK_VENDOR_SIGNATURES
        .iter()
        .any(|sig| lower.contains(sig))
    {
        return true;
    }
    BLOCK_PHRASE_SETS
        .iter()
        .any(|set| set.iter().all(|tok| lower.contains(tok)))
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

// ---------------------------------------------------------------------------
// Tests — the SERP HTML extraction iterators were previously uncovered. These
// lock in their observed behaviour as a regression guard: engines change their
// result markup over time, and a silent break here drops results.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cite_iter_extracts_bing_display_urls() {
        // Bing puts the display URL in <cite>, often with " ›" breadcrumbs and
        // attributes on the opening tag.
        let html = r#"<cite>https://example.com › about › team</cite>
            <cite class="b_attribution">www.foo.org</cite>"#;
        let got: Vec<&str> = CiteIter::new(html).collect();
        assert_eq!(got, vec!["https://example.com", "www.foo.org"]);
    }

    #[test]
    fn cite_iter_skips_non_domains_and_malformed() {
        assert!(CiteIter::new("<cite>ab</cite>").next().is_none()); // no dot, too short
        assert!(CiteIter::new("<cite>no dot here</cite>").next().is_none()); // no '.'
        assert!(CiteIter::new("<cite>x<b>.com</cite>").next().is_none()); // nested tag
        assert!(CiteIter::new("<cite>https://unclosed.com").next().is_none()); // no </cite>
        assert!(CiteIter::new("no cites at all").next().is_none());
    }

    #[test]
    fn google_url_iter_extracts_redirect_targets() {
        let html = r#"<a href="/url?q=https://example.com/page&amp;sa=U">x</a>
            <a href="/url?q=https://news.example.org&sa=U">y</a>"#;
        let got: Vec<&str> = GoogleUrlIter::new(html).collect();
        assert_eq!(
            got,
            vec!["https://example.com/page", "https://news.example.org"]
        );
    }

    #[test]
    fn google_url_iter_filters_self_and_relative() {
        // Google's own links and relative targets are dropped.
        assert!(
            GoogleUrlIter::new("/url?q=https://google.com/search&sa=U")
                .next()
                .is_none()
        );
        assert!(GoogleUrlIter::new("/url?q=/settings&sa=U").next().is_none());
        // A quote terminator (no trailing '&') still yields the URL.
        let got: Vec<&str> =
            GoogleUrlIter::new(r#"<a href="/url?q=https://q.example.com">"#).collect();
        assert_eq!(got, vec!["https://q.example.com"]);
        // No redirect markers at all.
        assert!(GoogleUrlIter::new("plain html").next().is_none());
    }
}
