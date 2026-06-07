pub(super) use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    scan::{Target, TargetKind},
    tags,
};
pub(super) use std::collections::HashSet;

pub(super) const SRC: &str = "search_engines";

pub(crate) struct SearchResult {
    pub(super) url: String,
    pub(super) title: String,
    pub(super) snippet: String,
    pub(super) engine: &'static str,
    pub(super) query: String,
}
pub(super) fn extract_path_username(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let segments: Vec<&str> = parsed.path_segments()?.filter(|s| !s.is_empty()).collect();
    let candidate = segments.first()?;
    if candidate.len() >= 3
        && candidate.len() <= 40
        && candidate
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        Some(candidate.to_string())
    } else {
        None
    }
}

// ─── Fetch + parse ──────────────────────────────────────────────────────────

/// Outcome of a single fetch attempt. Distinguishes "engine responded
/// but was blocked" (worth retrying with alt UA) from "engine is
/// unreachable" (retrying wastes the timeout budget).
pub(super) enum FetchOutcome {
    Body(String),
    Blocked,
    Unreachable,
}

/// Decode the handful of HTML entities that show up in engine result markup
/// and percent-encoded redirect hrefs. Mirrors `util::html`'s decoder (which
/// already handled `&apos;`) so a title/snippet/URL decoded here matches one
/// decoded there. Not a full entity decoder by design — just the entities
/// observed in real SERP output.
pub(super) fn decode_html_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&apos;", "'")
}

/// Resolve an href into a clean URL, decoding engine-specific redirects.
pub(super) fn resolve_href(href: &str) -> Option<String> {
    let href = &decode_html_entities(href);

    // DuckDuckGo wraps URLs: //duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com&rut=...
    if href.contains("uddg=") {
        return extract_url_param(href, "uddg=");
    }

    // Yandex wraps URLs: //yandex.com/clck/jsredir?...&url=https%3A%2F%2Fexample.com&...
    if href.contains("yandex.com/clck") && href.contains("url=") {
        return extract_url_param(href, "url=");
    }

    // Yahoo wraps URLs: /RU=https%3a%2f%2fexample.com/RK=.../RS=...
    if href.contains("/RU=") {
        return href
            .split("/RU=")
            .nth(1)
            .and_then(|rest| rest.split("/R").next())
            .and_then(|encoded| {
                let decoded: String = url::form_urlencoded::parse(encoded.as_bytes())
                    .next()
                    .map_or_else(|| encoded.to_string(), |(k, _)| k.into_owned());
                if decoded.starts_with("http") {
                    Some(decoded)
                } else {
                    None
                }
            });
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

pub(super) fn extract_url_param(href: &str, param: &str) -> Option<String> {
    href.split(param)
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .map(|encoded| {
            url::form_urlencoded::parse(encoded.as_bytes())
                .next()
                .map_or_else(|| encoded.to_string(), |(k, _)| k.into_owned())
        })
}

// ─── HTML iteration ─────────────────────────────────────────────────────────

pub(super) struct HrefIter<'a> {
    remaining: &'a str,
}

impl<'a> HrefIter<'a> {
    pub(super) fn new(html: &'a str) -> Self {
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

pub(super) fn extract_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_lowercase))
        .unwrap_or_default()
}

pub(super) const ENGINE_DOMAINS: &[&str] = &[
    "duckduckgo.com",
    "startpage.com",
    "mojeek.com",
    "brave.com",
    "yahoo.com",
    "bing.com",
    "google.com",
    "yandex.com",
    "yandex.ru",
    "yandex.net",
    "yimg.com",
    "search.yahoo.com",
    "r.search.yahoo.com",
    "cc.bingj.com",
    "aol.com",
    "search.aol.com",
    "oath.com",
    "gstatic.com",
    "googleapis.com",
    "googleusercontent.com",
    "schema.org",
    "w3.org",
    "imgs.search.brave.com",
    "ecosia.org",
    "qwant.com",
    "api.qwant.com",
    "dogpile.com",
    "swisscows.com",
    "system1.com",
    "flocdn.com",
    "cookielaw.org",
    "onetrust.com",
    "syndicatedsearch.goog",
    "microsoftonline.com",
    "msn.com",
    // Engine-adjacent infrastructure that appears in their chrome
    "teleguard.com",
    "shdw.me",
    "unpkg.com",
    "torproject.org",
    "mastodon.social",
    "discord.com",
    "apple.com",
    "play.google.com",
    "apps.apple.com",
    "itunes.apple.com",
    "microsoft.com",
    "support.microsoft.com",
];

pub(super) fn is_engine_domain(host: &str) -> bool {
    ENGINE_DOMAINS
        .iter()
        .any(|d| crate::util::domains::is_or_subdomain_of(host, d))
}

/// Domains that are generic infrastructure / unrelated to any target.
/// These appear in search result pages from engine chrome, ads, or
/// generic navigation links, never as OSINT-relevant findings.
pub(super) fn is_generic_domain(domain: &str) -> bool {
    const GENERIC: &[&str] = &[
        "amazonaws.com",
        "androidpolice.com",
        "britannica.com",
        "builtin.com",
        "christiantoday.com",
        "cloudflare.com",
        "co.za",
        "contactout.com",
        "dol.gov",
        "dpd.com",
        "emailsherlock.com",
        "f6s.com",
        "fitfit.fitness",
        "forbes.com",
        "gardenweb.com",
        "hexomatic.com",
        "hunter.io",
        "littlecaesars.com",
        "mapquest.com",
        "martindale.com",
        "nolo.com",
        "office.com",
        "outlook.com",
        "reversecontact.com",
        "stvincentipa.com",
        "tomba.io",
        "usps.com",
        "wikihow.com",
        "windowsreport.com",
        "zoominfo.com",
    ];
    GENERIC.contains(&domain)
}

/// People-search / username-aggregator / lookup-tooling domains. These are the
/// search's OWN instruments — the username dork ladder explicitly queries
/// `site:peekyou.com`, `site:spokeo.com`, … — so a *bare* aggregator domain in
/// the results is noise, never the target's own asset, and must not become a
/// `Domain` finding. A *specific* profile page on one of them
/// (`peekyou.com/<handle>`) is still emitted as a `Url` entity by the
/// path-match gate; this only drops the bare-domain noise. Surfaced by a
/// statistical pass over a live `kylo4kylo` run, where ~15 of 84 domains were
/// such aggregators.
pub(super) fn is_search_tooling_domain(domain: &str) -> bool {
    const TOOLING: &[&str] = &[
        // people-search aggregators
        "411.com",
        "anywho.com",
        "beenverified.com",
        "fastpeoplesearch.com",
        "idcrawl.com",
        "intelius.com",
        "locatefamily.com",
        "melissa.com",
        "familytreenow.com",
        "neighborwho.com",
        "nuwber.com",
        "peekyou.com",
        "peoplefinder.com",
        "peoplefinders.com",
        "peoplesearch.com",
        "pipl.com",
        "propertychecker.com",
        "propertyshark.com",
        "quickpeoplelookup.com",
        "radaris.com",
        "rocketreach.co",
        "searchpeoplefree.com",
        "spokeo.com",
        "thatsthem.com",
        "truepeoplesearch.com",
        "usphonebook.com",
        "whitepages.com",
        "whitepages.com.au",
        // genealogy aggregators — same shape as people-search
        "ancestry.com",
        "familysearch.org",
        "geni.com",
        "wikitree.com",
        // obituary / funeral-notice aggregators — a name + locality search
        // (e.g. a common name in a small town) floods these with hits for a
        // DIFFERENT, often deceased, person; never the subject's asset.
        "cdclarkfuneralhome.com",
        "dignitymemorial.com",
        "echovita.com",
        "everloved.com",
        "findagrave.com",
        "legacy.com",
        "tributearchive.com",
        // breach / leak lookup aggregators — these are the search's OWN breach
        // instruments (the email dork ladder queries them); a bare result host
        // here is noise, never the subject's asset. The specific breach hit is
        // already surfaced by the breach modules with real evidence.
        "breachdirectory.org",
        "ghostbin.co",
        "leakcheck.io",
        "paste.ee",
        "scamsurvivors.com",
        "scatteredsecrets.com",
        "snusbase.com",
        // privacy search engines that appear as result hosts of meta-queries
        "brave.app",
        "ecosia.co",
        "ecosia.org",
        "metager.org",
        // anti-spam / generic reference databases — a bare host here is noise,
        // never the subject's own asset
        "cleantalk.org",
        "wikipedia.org",
        // username-availability / cross-platform lookup tools
        "check-username.com",
        "checkusernames.com",
        "instantusername.com",
        "knowem.com",
        "namecheckr.com",
        "namechk.com",
        "usernamegenerator.com",
        "whatsmyname.app",
    ];
    let d = domain.trim().to_lowercase();
    let d = d.strip_prefix("www.").unwrap_or(&d);
    TOOLING.contains(&d)
}

pub(super) fn is_tracking_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.contains("r.search.yahoo.com")
        || lower.contains("duckduckgo.com/y.js")
        || lower.contains("clickserve")
        || lower.contains("ad.doubleclick")
        || lower.contains("googleads")
        || lower.contains("r.bing.com")
        || lower.contains("th.bing.com")
        || lower.contains("cc.bingj.com")
        || lower.contains("yandex.com/clck")
        || lower.contains("ecosia.org/newtab")
        || lower.contains("dogpile.com/click")
        || lower.contains("swisscows.com/api")
        || lower.contains("/privacy-policy")
        || lower.contains("/terms-of-use")
        || lower.contains("/terms-of-service")
        || lower.contains("guce.yahoo.com")
        || lower.contains("guce.aol.com")
        || lower.contains("advertising.yahoo.com")
        || lower.contains("feedback.yahoo.com")
}

pub(super) fn is_non_name_word(s: &str) -> bool {
    const BLOCKED: &[&str] = &[
        "about",
        "amp",
        "ancientfaces",
        "and",
        "blog",
        "com",
        "find",
        "for",
        "from",
        "github",
        "has",
        "his",
        "home",
        "how",
        "img",
        "info",
        "into",
        "its",
        "linkedin",
        "locatefamily",
        "may",
        "net",
        "new",
        "not",
        "now",
        "old",
        "one",
        "org",
        "our",
        "out",
        "own",
        "page",
        "per",
        "photos",
        "profile",
        "public",
        "results",
        "search",
        "shop",
        "site",
        "surname",
        "the",
        "their",
        "this",
        "was",
        "web",
        "who",
        "with",
        "www",
        "you",
        "your",
    ];
    BLOCKED.contains(&s)
}

pub(super) fn is_navigation_path(s: &str) -> bool {
    const EXACT: &[&str] = &[
        "about",
        "api",
        "browse",
        "business",
        "careers",
        "company",
        "contact",
        "create",
        "creator",
        "creators",
        "download",
        "events",
        "explore",
        "features",
        "feed",
        "followers",
        "following",
        "foryou",
        "groups",
        "help",
        "home",
        "jobs",
        "legal",
        "live",
        "log-in",
        "marketplace",
        "media",
        "messenger",
        "music",
        "myspace",
        "news",
        "notifications",
        "people",
        "photos",
        "popular",
        "posts",
        "privacy",
        "reel",
        "reels",
        "settings",
        "shorts",
        "status",
        "stories",
        "support",
        "tag",
        "tags",
        "terms",
        "topics",
        "tpm",
        "trends",
        "user",
        "users",
        "video",
        "videos",
        "watch",
        "web",
        "wiki",
    ];
    const CONTAINS: &[&str] = &[
        "login",
        "signup",
        "signin",
        "signout",
        "logout",
        "register",
        "getstarted",
        "official",
        "dogpile",
        "swisscows",
        "qwant",
        "instagram",
        "facebook",
        "twitter",
        "youtube",
        "tiktok",
        "ecosia",
        ".php",
        ".html",
        ".asp",
    ];
    EXACT.contains(&s)
        || s.starts_with("search")
        || s.starts_with("public")
        || s.starts_with("upload")
        || s.starts_with("discover")
        || CONTAINS.iter().any(|n| s.contains(n))
}

/// Structural URL/web tokens that are never a meaningful target identifier.
/// Dropping them keeps a `Url` target (whose value is split into path tokens)
/// from turning `https`/`www`/`ssl`/a TLD into a "term" that then matches every
/// unrelated page carrying that token — e.g. a target of `…/why-use-https` made
/// `https` a term that matched every HTTPS-explainer page in the relevance gate.
fn is_web_stopword(w: &str) -> bool {
    matches!(
        w,
        "http"
            | "https"
            | "www"
            | "com"
            | "org"
            | "net"
            | "edu"
            | "gov"
            | "html"
            | "htm"
            | "php"
            | "aspx"
            | "asp"
            | "jsp"
            | "ssl"
            | "tls"
    )
}

/// Extract the meaningful search terms from a target value.
/// For email: uses the local part (before @). For names: each word.
/// Filters to ≥3 chars (dropping structural web stopwords) and lowercases.
/// Used by every relevance gate.
pub(super) fn target_terms(target: &Target) -> Vec<String> {
    let seed = match target.kind {
        TargetKind::Email => target.value.split('@').next().unwrap_or(""),
        _ => &target.value,
    };
    seed.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3 && !is_web_stopword(w))
        .map(String::from)
        .collect()
}

/// Check whether a URL's path contains any target term (≥4 chars).
pub(super) fn url_matches_target(url: &str, terms: &[String]) -> bool {
    let path = url::Url::parse(url)
        .ok()
        .map(|u| u.path().to_lowercase())
        .unwrap_or_default();
    if path.len() < 4 {
        return false;
    }
    terms
        .iter()
        .filter(|w| w.len() >= 4)
        .any(|w| path.contains(w.as_str()))
}

/// Score how strongly a discovered username is connected to the target.
/// Uses multiple independent signals — a username that shares no terms
/// with the seed can still be validated through co-occurrence, people-
/// search provenance, or search-engine contextual linking.
///
/// Returns (score, confidence):
///   score ≥ 3 → strong: 0.55 confidence (PROBABLE tier)
///   score 1-2 → weak:   0.30 confidence (CANDIDATE tier)
///   score 0   → drop:   not emitted
pub(super) fn score_username(
    username: &str,
    host: &str,
    terms: &[String],
    result: &SearchResult,
) -> (u8, f64) {
    let mut score: u8 = 0;

    // Signal 1: direct term overlap (strongest)
    let parts: Vec<String> = username
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3)
        .map(String::from)
        .collect();
    if terms.iter().any(|t| {
        parts
            .iter()
            .any(|p| p == t || p.contains(t.as_str()) || t.contains(p.as_str()))
    }) {
        score += 3;
    }

    // Signal 2: people-search provenance — the site specialises in
    // linking identities, so any username it connects to the target
    // has high implicit credibility
    let people_search = [
        "peekyou.com",
        "spokeo.com",
        "nuwber.com",
        "whitepages.com",
        "thatsthem.com",
        "whitepages.com.au",
        "locatefamily.com",
        "peoplefinder.com.au",
        "ancestry.com.au",
    ];
    // Match the host itself or a subdomain of it — `host.ends_with(ps)` alone
    // would also fire on `myspokeo.com` / `notwhitepages.com`. Same dot-boundary
    // predicate used for the aggregator check above.
    if people_search
        .iter()
        .any(|ps| crate::util::domains::is_or_subdomain_of(host, ps))
    {
        score += 3;
    }

    // Signal 3: co-occurrence — a target term (≥4 chars) appears
    // in the same snippet/title as this username, meaning the search
    // engine's result page explicitly associates both
    let text = format!("{} {}", result.title, result.snippet).to_lowercase();
    if terms
        .iter()
        .filter(|t| t.len() >= 4)
        .any(|t| text.contains(t.as_str()))
    {
        score += 2;
    }

    // Signal 4: platform-targeted query — the query used site:
    // for this exact platform, meaning the engine specifically
    // matched the target to this profile on this platform
    let ql = result.query.to_lowercase();
    let host_base = host
        .trim_start_matches("www.")
        .trim_start_matches("m.")
        .trim_start_matches("mobile.");
    if ql.contains(&format!("site:{host_base}")) {
        score += 1;
    }

    // Signal 5: handle similarity — the candidate is structurally a VARIANT of
    // the seed handle, which separates a likely alias of the SAME person from an
    // unrelated username that merely co-occurred on the result page. Two matches:
    //  - shared alphabetic STEM: seed "kylo4kylo" → stem "kylo" → "kylocool630".
    //    Bigram overlap alone misses this (~0.2 < 0.25 because the digits/suffix
    //    dilute it), so also test substring-containment of any ≥4-char alpha run
    //    of the seed; and
    //  - bigram overlap ("jaydes" ↔ "jdespal") for transposed/abbreviated aliases.
    // Unlike the old `score == 0` fallback this BOOSTS, so a seed-resembling
    // handle that ALSO co-occurs reaches PROBABLE (0.55) while pure co-occurrence
    // stays CANDIDATE (0.30) — the precision lift that keeps alias variants ahead
    // of co-occurrence noise.
    let cand = username.to_lowercase();
    let stem_match = terms
        .iter()
        .flat_map(|t| t.split(|c: char| c.is_ascii_digit()))
        .any(|s| s.len() >= 4 && cand.contains(s));
    let seed = terms.first().map(String::as_str).unwrap_or("");
    if stem_match || bigram_similarity(&cand, seed) >= 0.25 {
        score += 2;
    }

    let confidence = if score >= 3 { 0.55 } else { 0.30 };
    (score, confidence)
}

pub(super) fn dedup_results(mut results: Vec<SearchResult>) -> Vec<SearchResult> {
    let mut seen = HashSet::new();
    results.retain(|r| {
        let key = canonicalize_url(&r.url);
        seen.insert(key)
    });
    results
}

/// Dedup / cross-engine-corroboration KEY for a result URL (the stored URL is
/// never altered). Drops the fragment, a trailing slash, and known
/// tracking/analytics query params — but KEEPS content-bearing params, so
/// distinct pages such as `…/watch?v=A` vs `…/watch?v=B` or `…?id=1` vs `…?id=2`
/// are not collapsed into one (collapsing them would silently *omit* real
/// results). Kept params are sorted so param order can't defeat dedup.
pub(super) fn canonicalize_url(url: &str) -> String {
    let url = url.split('#').next().unwrap_or(url); // drop fragment first
    let (base, query) = url.split_once('?').map_or((url, ""), |(b, q)| (b, q));
    let base = base.trim_end_matches('/');
    let mut kept: Vec<&str> = query
        .split('&')
        .filter(|kv| !kv.is_empty() && !is_tracking_param(kv.split('=').next().unwrap_or(kv)))
        .collect();
    if kept.is_empty() {
        return base.to_string();
    }
    kept.sort_unstable();
    format!("{base}?{}", kept.join("&"))
}

/// Known click-tracking / analytics query params that have no bearing on which
/// page a URL addresses — stripped from [`canonicalize_url`]'s key so the same
/// page tagged with different campaign params dedups, while content params
/// (`v`, `id`, `q`, `page`, …) are preserved.
fn is_tracking_param(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k.starts_with("utm_")
        || matches!(
            k.as_str(),
            "fbclid"
                | "gclid"
                | "gclsrc"
                | "dclid"
                | "msclkid"
                | "yclid"
                | "mc_cid"
                | "mc_eid"
                | "igshid"
                | "_ga"
                | "_gl"
        )
}

/// Normalize an address for fuzzy dedup: lowercased, state abbreviations
/// expanded, common punctuation and whitespace collapsed. This catches
/// "Gatton, QLD" ≡ "Gatton, Queensland" ≡ "gatton queensland".
pub(super) fn normalise_address_key(addr: &str) -> String {
    let mut s = addr.to_lowercase();
    let expansions = [
        ("qld", "queensland"),
        ("nsw", "new south wales"),
        ("vic", "victoria"),
        ("tas", "tasmania"),
        ("act", "australian capital territory"),
        ("sa", "south australia"),
        ("wa", "western australia"),
        ("nt", "northern territory"),
    ];
    for (abbr, full) in &expansions {
        if s.contains(abbr) && !s.contains(full) {
            s = s.replace(abbr, full);
        }
    }
    s.retain(|c| c.is_alphanumeric() || c == ' ');
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

pub(super) fn ceil_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

pub(super) fn extract_anchor_text(html: &str, href: &str, max_len: usize) -> String {
    let search_dq = format!("href=\"{href}\"");
    let search_sq = format!("href='{href}'");
    let pos = match html.find(&search_dq).or_else(|| html.find(&search_sq)) {
        Some(p) => p,
        None => return String::new(),
    };
    let after_href = &html[pos..];
    let gt = match after_href.find('>') {
        Some(g) => pos + g + 1,
        None => return String::new(),
    };
    let rest = &html[gt..];
    let end_tag = rest.find("</a>").or_else(|| rest.find("</A>"));
    let end = match end_tag {
        Some(e) => gt + e,
        None => return String::new(),
    };
    strip_tags(&html[gt..end], max_len)
}

pub(super) fn extract_surrounding_text(html: &str, anchor: &str, max_len: usize) -> String {
    let pos = match html.find(anchor) {
        Some(p) => p,
        None => return String::new(),
    };
    let start = floor_char_boundary(html, pos.saturating_sub(300));
    let end = ceil_char_boundary(html, (pos + anchor.len() + 300).min(html.len()));
    strip_tags(&html[start..end], max_len)
}

pub(super) fn extract_snippet_near(html: &str, anchor: &str, max_len: usize) -> String {
    let raw = match html.find(anchor) {
        Some(p) => p + anchor.len(),
        None => return String::new(),
    };
    let pos = ceil_char_boundary(html, raw);
    let end = ceil_char_boundary(html, (pos + 1600).min(html.len()));
    let raw_text = strip_tags(&html[pos..end], max_len);
    clean_snippet(&raw_text)
}

pub(super) fn clean_snippet(s: &str) -> String {
    let mut out = s
        .replace("\\\"", "")
        .replace("\\n", " ")
        .replace("\\t", " ");
    while out.contains("  ") {
        out = out.replace("  ", " ");
    }
    // Remove Bing-style SERP ID artifacts: h="ID=SERP,1234.5"
    if let Some(start) = out.find("h=\"ID=SERP")
        && let Some(end) = out[start..].find('"').and_then(|first_q| {
            out[start + first_q + 1..]
                .find('"')
                .map(|second_q| start + first_q + 1 + second_q + 1)
        })
    {
        out = format!("{}{}", &out[..start], &out[end..]);
    }
    out.trim().to_string()
}

pub(super) fn strip_tags(html: &str, max_len: usize) -> String {
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

pub(super) fn known_city_coords(addr: &str) -> Option<(f64, f64)> {
    let lower = addr.to_lowercase();
    const CITIES: &[(&str, f64, f64)] = &[
        // Australian capitals + major cities
        ("brisbane", -27.4698, 153.0251),
        ("sydney", -33.8688, 151.2093),
        ("melbourne", -37.8136, 144.9631),
        ("perth", -31.9505, 115.8605),
        ("adelaide", -34.9285, 138.6007),
        ("canberra", -35.2809, 149.1300),
        ("hobart", -42.8821, 147.3272),
        ("darwin", -12.4634, 130.8456),
        ("gold coast", -28.0167, 153.4000),
        ("sunshine coast", -26.6500, 153.0667),
        ("cairns", -16.9186, 145.7781),
        ("townsville", -19.2590, 146.8169),
        ("toowoomba", -27.5598, 151.9507),
        ("rockhampton", -23.3791, 150.5100),
        // QLD suburbs + regional
        ("gatton", -27.5567, 152.2767),
        ("laidley", -27.6333, 152.3833),
        ("lockyer valley", -27.5567, 152.2767),
        ("helidon", -27.5500, 152.1167),
        ("plainland", -27.5667, 152.4167),
        ("forest hill", -27.5833, 152.3500),
        ("nundah", -27.4017, 153.0600),
        ("redcliffe", -27.2289, 153.1050),
        ("caboolture", -27.0847, 152.9511),
        ("chermside", -27.3861, 153.0331),
        ("aspley", -27.3650, 153.0167),
        ("strathpine", -27.3050, 152.9900),
        ("north lakes", -27.2281, 153.0019),
        ("ipswich", -27.6167, 152.7667),
        ("logan", -27.6389, 153.1092),
        ("springfield", -27.6667, 152.9167),
        ("surfers paradise", -28.0029, 153.4300),
        ("nerang", -27.9897, 153.3372),
        ("bundaberg", -24.8661, 152.3489),
        ("hervey bay", -25.2881, 152.8411),
        ("gladstone", -23.8488, 151.2673),
        ("mount isa", -20.7264, 139.4928),
        ("mackay", -21.1411, 149.1861),
        ("maryborough", -25.5411, 152.7028),
        ("warwick", -28.2167, 152.0333),
        ("dalby", -27.1833, 151.2667),
        ("kingaroy", -26.5400, 151.8400),
        ("stanthorpe", -28.6567, 151.9333),
        // NSW regional
        ("newcastle", -32.9283, 151.7817),
        ("wollongong", -34.4278, 150.8931),
        ("central coast", -33.3000, 151.3500),
        ("tamworth", -31.0833, 150.9167),
        ("wagga wagga", -35.1083, 147.3598),
        ("albury", -36.0737, 146.9135),
        ("orange", -33.2833, 149.1000),
        ("bathurst", -33.4167, 149.5833),
        ("dubbo", -32.2569, 148.6011),
        // VIC regional
        ("geelong", -38.1499, 144.3617),
        ("ballarat", -37.5622, 143.8503),
        ("bendigo", -36.7570, 144.2794),
        ("shepparton", -36.3833, 145.3833),
        // US cities (expanded)
        ("new york", 40.7128, -74.0060),
        ("los angeles", 33.9425, -118.2551),
        ("chicago", 41.8781, -87.6298),
        ("houston", 29.7604, -95.3698),
        ("phoenix", 33.4484, -111.9490),
        ("san francisco", 37.7749, -122.4194),
        ("seattle", 47.6062, -122.3321),
        ("denver", 39.7392, -104.9903),
        ("colorado springs", 38.8339, -104.8214),
        ("colo springs", 38.8339, -104.8214),
        ("philadelphia", 39.9526, -75.1652),
        ("san antonio", 29.4241, -98.4936),
        ("dallas", 32.7767, -96.7970),
        ("san jose", 37.3382, -121.8863),
        ("austin", 30.2672, -97.7431),
        ("jacksonville", 30.3322, -81.6557),
        ("columbus", 39.9612, -82.9988),
        ("miami", 25.7617, -80.1918),
        ("boston", 42.3601, -71.0589),
        ("atlanta", 33.7490, -84.3880),
        ("portland", 45.5152, -122.6784),
        ("las vegas", 36.1699, -115.1398),
        ("nashville", 36.1627, -86.7816),
        ("minneapolis", 44.9778, -93.2650),
        // UK cities (expanded)
        ("london", 51.5074, -0.1278),
        ("manchester", 53.4808, -2.2426),
        ("birmingham", 52.4862, -1.8904),
        ("leeds", 53.8008, -1.5491),
        ("glasgow", 55.8642, -4.2518),
        ("liverpool", 53.4084, -2.9916),
        ("edinburgh", 55.9533, -3.1883),
        ("bristol", 51.4545, -2.5879),
        // NZ cities
        ("auckland", -36.8485, 174.7633),
        ("wellington", -41.2865, 174.7762),
        ("christchurch", -43.5321, 172.6362),
    ];
    for &(city, lat, lon) in CITIES {
        if lower.contains(city) {
            return Some((lat, lon));
        }
    }
    None
}

pub(super) fn extract_registrable(host: &str) -> String {
    crate::util::domains::registrable_domain(host).unwrap_or_else(|| host.to_string())
}

/// Build a clean, structured evidence entry from a search result.
/// Every evidence entry includes the full navigable URL so the user
/// can click through to verify the finding.
pub(super) fn build_search_evidence(r: &SearchResult) -> Evidence {
    let title_clean: String = r.title.chars().take(200).collect();
    let snippet_clean: String = r.snippet.chars().take(800).collect();

    let summary = if !title_clean.is_empty() {
        format!("[{}] {} — {}", r.engine, title_clean.trim(), r.url)
    } else {
        format!("[{}] {}", r.engine, r.url)
    };

    let mut ev = Evidence::new(SRC, summary)
        .with_attr("url", &r.url)
        .with_attr("engine", r.engine)
        .with_attr("query", &r.query);
    if !title_clean.is_empty() {
        ev = ev.with_attr("page_title", title_clean.trim());
    }
    if !snippet_clean.is_empty() {
        ev = ev.with_attr("snippet", snippet_clean.trim());
    }

    let kp = extract_key_phrase(&snippet_clean, &r.query);
    if !kp.is_empty() {
        ev = ev.with_attr("key_phrase", &kp);
    }
    ev
}

/// Extract the most relevant sentence fragment from a snippet by
/// finding the clause that overlaps most with the query terms.
pub(super) fn extract_key_phrase(snippet: &str, query: &str) -> String {
    if snippet.len() < 10 {
        return String::new();
    }
    let query_words: HashSet<String> = query
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3)
        .map(String::from)
        .collect();
    if query_words.is_empty() {
        return String::new();
    }

    let mut best = "";
    let mut best_score = 0usize;
    for clause in snippet.split(['.', '!', '?', '|']) {
        let clause = clause.trim();
        if clause.len() < 8 || clause.len() > 200 {
            continue;
        }
        let score = clause
            .to_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| query_words.contains(*w))
            .count();
        if score > best_score {
            best_score = score;
            best = clause;
        }
    }
    if best_score >= 1 {
        best.to_string()
    } else {
        String::new()
    }
}

/// Extract "City, State" patterns from text for geolocation.
/// Only matches when a comma-separated city name precedes a known
/// state/territory name, and the city portion starts with an uppercase
/// letter (filters out random sentence fragments).
pub(super) fn extract_addresses_from_text(text: &str) -> Vec<String> {
    const STATES: &[&str] = &[
        "Queensland",
        "New South Wales",
        "Victoria",
        "Tasmania",
        "South Australia",
        "Western Australia",
        "Northern Territory",
        "NSW",
        "QLD",
        "VIC",
        "TAS",
        "ACT",
        "Alabama",
        "Alaska",
        "Arizona",
        "Arkansas",
        "California",
        "Colorado",
        "Connecticut",
        "Delaware",
        "Florida",
        "Georgia",
        "Hawaii",
        "Idaho",
        "Illinois",
        "Indiana",
        "Iowa",
        "Kansas",
        "Kentucky",
        "Louisiana",
        "Maine",
        "Maryland",
        "Massachusetts",
        "Michigan",
        "Minnesota",
        "Mississippi",
        "Missouri",
        "Montana",
        "Nebraska",
        "Nevada",
        "New Hampshire",
        "New Jersey",
        "New Mexico",
        "New York",
        "North Carolina",
        "North Dakota",
        "Ohio",
        "Oklahoma",
        "Oregon",
        "Pennsylvania",
        "Rhode Island",
        "South Carolina",
        "South Dakota",
        "Tennessee",
        "Texas",
        "Utah",
        "Vermont",
        "Virginia",
        "Washington",
        "West Virginia",
        "Wisconsin",
        "Wyoming",
    ];

    let mut addrs = Vec::new();
    for state in STATES {
        let mut search_from = 0;
        while let Some(pos) = text[search_from..].find(state) {
            let abs = search_from + pos;
            search_from = abs + state.len();

            // Need ", State" — check for comma before the state name
            let before = text[..abs].trim_end();
            if !before.ends_with(',') {
                continue;
            }
            // Extract the city name between the nearest prior comma
            // (or start of text) and the comma before the state name.
            // "Jerome Despal, Nundah, Queensland" → "Nundah"
            // "lives in Houston, Texas" → "Houston"
            let pre_comma = before.trim_end_matches(',').trim();
            let last_segment = match pre_comma.rfind(',') {
                Some(i) => pre_comma[i + 1..].trim(),
                None => {
                    let words: Vec<&str> = pre_comma.split_whitespace().collect();
                    let mut n = 0;
                    for w in words.iter().rev() {
                        if w.starts_with(|c: char| c.is_ascii_uppercase()) {
                            n += 1;
                        } else {
                            break;
                        }
                    }
                    if n == 0 {
                        continue;
                    }
                    let start_idx = words.len() - n;
                    &pre_comma[pre_comma.find(words[start_idx]).unwrap_or(0)..]
                }
            };
            let city = last_segment.trim();
            if city.len() < 2
                || city.len() > 40
                || !city.starts_with(|c: char| c.is_ascii_uppercase())
            {
                continue;
            }
            if !city
                .chars()
                .all(|c| c.is_alphanumeric() || c == ' ' || c == '-')
            {
                continue;
            }
            let addr = format!("{city}, {state}");
            addrs.push(addr);
        }
    }

    // Second pass: AU city + state context detection
    const AU_PLACES: &[&str] = &[
        // Capital cities
        "Brisbane",
        "Sydney",
        "Melbourne",
        "Perth",
        "Adelaide",
        "Canberra",
        "Hobart",
        "Darwin",
        // Major regional
        "Gold Coast",
        "Newcastle",
        "Wollongong",
        "Geelong",
        "Sunshine Coast",
        "Central Coast",
        // Queensland suburbs/cities
        "Cairns",
        "Townsville",
        "Toowoomba",
        "Rockhampton",
        "Mackay",
        "Bundaberg",
        "Hervey Bay",
        "Gladstone",
        "Mount Isa",
        "Nundah",
        "Redcliffe",
        "Caboolture",
        "Chermside",
        "Aspley",
        "Sandgate",
        "Shorncliffe",
        "Deagon",
        "Bracken Ridge",
        "Strathpine",
        "Petrie",
        "Kallangur",
        "Narangba",
        "Morayfield",
        "Burpengary",
        "North Lakes",
        "Fortitude Valley",
        "New Farm",
        "Teneriffe",
        "Woolloongabba",
        "South Brisbane",
        "West End",
        "Kangaroo Point",
        "Spring Hill",
        "Paddington",
        "Milton",
        "Toowong",
        "Indooroopilly",
        "St Lucia",
        "Taringa",
        "Logan",
        "Ipswich",
        "Springfield",
        // Lockyer Valley region
        "Gatton",
        "Laidley",
        "Helidon",
        "Plainland",
        "Forest Hill",
        "Lockyer Valley",
        "Withcott",
        // Western Downs / Darling Downs
        "Dalby",
        "Warwick",
        "Kingaroy",
        "Stanthorpe",
        "Goondiwindi",
        "Chinchilla",
        // Moreton Bay
        "Maryborough",
        "Beenleigh",
        "Capalaba",
        "Cleveland",
        "Wynnum",
        "Manly",
        "Surfers Paradise",
        "Broadbeach",
        "Robina",
        "Nerang",
        "Coolangatta",
        "Tweed Heads",
        // NSW
        "Parramatta",
        "Blacktown",
        "Penrith",
        "Liverpool",
        "Bondi",
        "Manly",
        "Cronulla",
        "Bankstown",
        // VIC
        "St Kilda",
        "Richmond",
        "Fitzroy",
        "Collingwood",
        "South Yarra",
        "Prahran",
        "Carlton",
        "Brunswick",
    ];

    for place in AU_PLACES {
        let lower = text.to_lowercase();
        let place_lower = place.to_lowercase();
        if let Some(pos) = lower.find(&place_lower) {
            let after = &lower[pos + place_lower.len()..];
            let context: String = after.chars().take(60).collect();
            // Walk back to a char boundary; UTF-8 multi-byte chars
            // (e.g. '>' substitutes spanning 3 bytes) must not be split.
            let mut before_start = pos.saturating_sub(60);
            while before_start > 0 && !lower.is_char_boundary(before_start) {
                before_start -= 1;
            }
            let before: String = lower[before_start..pos].chars().collect();
            let combined = format!("{before} {context}");
            if combined.contains("australia")
                || combined.contains("qld")
                || combined.contains("nsw")
                || combined.contains("vic")
                || combined.contains("queensland")
                || combined.contains("new south wales")
                || combined.contains("victoria")
            {
                let state_tag = if combined.contains("qld") || combined.contains("queensland") {
                    "QLD"
                } else if combined.contains("nsw") || combined.contains("new south wales") {
                    "NSW"
                } else if combined.contains("vic") || combined.contains("victoria") {
                    "VIC"
                } else {
                    "Australia"
                };
                let addr = format!("{place}, {state_tag}");
                let addr_lower = addr.to_lowercase();
                if !addrs.iter().any(|a| a.to_lowercase() == addr_lower) {
                    addrs.push(addr);
                }
            }
        }
    }

    // Third pass: Australian postcodes (4 digits after a place name)
    let postcode_re_like = |s: &str| -> Option<String> {
        let bytes = s.as_bytes();
        let len = bytes.len();
        let mut i = 0;
        while i + 3 < len {
            if bytes[i].is_ascii_digit()
                && bytes[i + 1].is_ascii_digit()
                && bytes[i + 2].is_ascii_digit()
                && bytes[i + 3].is_ascii_digit()
                && (i + 4 >= len || !bytes[i + 4].is_ascii_digit())
                && (i == 0 || !bytes[i - 1].is_ascii_digit())
            {
                let pc = &s[i..i + 4];
                let first = pc.as_bytes()[0];
                // AU postcodes: 2xxx (NSW/ACT), 3xxx (VIC), 4xxx (QLD),
                // 5xxx (SA), 6xxx (WA), 7xxx (TAS), 08xx (NT)
                if (b'2'..=b'7').contains(&first) {
                    return Some(pc.to_string());
                }
            }
            i += 1;
        }
        None
    };

    for r in &addrs.clone() {
        let after_idx = text.find(r.as_str()).unwrap_or(0) + r.len();
        if after_idx < text.len() {
            // Walk the end forward to a char boundary so multi-byte
            // UTF-8 chars cannot be split mid-codepoint.
            let mut end = text.len().min(after_idx + 20);
            while end < text.len() && !text.is_char_boundary(end) {
                end += 1;
            }
            let snippet = &text[after_idx..end];
            if let Some(pc) = postcode_re_like(snippet) {
                let with_pc = format!("{r} {pc}");
                if !addrs.contains(&with_pc) {
                    addrs.push(with_pc);
                }
            }
        }
    }

    addrs
}

/// Extract Australian Business Numbers (11 digits) and Australian
/// Company Numbers (9 digits) from text. ABNs are formatted as
/// "XX XXX XXX XXX" or "XXXXXXXXXXX"; ACNs as "XXX XXX XXX".
/// Returns (value, kind_label) pairs.
pub(super) fn extract_abn_acn_from_text(text: &str) -> Vec<(String, &'static str)> {
    let mut results = Vec::new();
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        let mut digits = Vec::new();
        while i < len && (bytes[i].is_ascii_digit() || bytes[i] == b' ') {
            if bytes[i].is_ascii_digit() {
                digits.push(bytes[i]);
            }
            i += 1;
        }
        if digits.len() == 11 {
            let num: String = digits.iter().map(|&b| b as char).collect();
            if is_valid_abn(&num) {
                let before = text[..start].to_lowercase();
                let trimmed = before.trim_end();
                if trimmed.ends_with("abn")
                    || trimmed.ends_with("abn:")
                    || trimmed.ends_with("a.b.n.")
                    || trimmed.ends_with("business number")
                    || trimmed.ends_with("business number:")
                {
                    results.push((num, "ABN"));
                    if results.len() >= 10 {
                        break;
                    }
                }
            }
        } else if digits.len() == 9 {
            let num: String = digits.iter().map(|&b| b as char).collect();
            let before = text[..start].to_lowercase();
            let trimmed = before.trim_end();
            let has_context = trimmed.ends_with("acn")
                || trimmed.ends_with("acn:")
                || trimmed.ends_with("a.c.n.")
                || trimmed.ends_with("company number")
                || trimmed.ends_with("company number:");
            // Require the ASIC check-digit too (symmetric with the ABN path) so a
            // random 9-digit number next to the word "acn" is rejected.
            if has_context && crate::util::abn::is_valid_acn(&num) {
                results.push((num, "ACN"));
                if results.len() >= 10 {
                    break;
                }
            }
        }
    }
    results
}

pub(super) fn is_valid_abn(s: &str) -> bool {
    // Shared, checksum-validated implementation (see `util::abn`).
    crate::util::abn::is_valid_abn(s)
}

/// Extract organisation names from text. Looks for patterns like
/// "Pty Ltd", "Inc", "LLC", "Corporation" near the target context.
pub(super) fn extract_organisations_from_text(text: &str, terms: &[String]) -> Vec<String> {
    let suffixes = [
        " Pty Ltd",
        " Pty. Ltd.",
        " Pty Limited",
        " Inc.",
        " Inc",
        " LLC",
        " Ltd",
        " Ltd.",
        " Limited",
        " Corporation",
        " Corp.",
        " Corp",
        " Co.",
    ];
    let mut orgs = Vec::new();
    let bytes = text.as_bytes();
    for suffix in &suffixes {
        // Case-insensitive search over the ORIGINAL `text`. We deliberately do
        // NOT index `text` with byte offsets taken from `text.to_lowercase()`:
        // to_lowercase() is not length-preserving (İ→i̇ 2→3 bytes, ẞ→ß), so such
        // offsets can overshoot the end of `text` or split a code point — a
        // `str` index panic, which under `panic="abort"` takes down the whole
        // `serve` process on a hostile SERP snippet. The suffix is ASCII and
        // begins with a space, so a match position `i` and its end are always
        // valid char boundaries in `text`.
        let sfx = suffix.as_bytes();
        let mut i = 0;
        while i + sfx.len() <= bytes.len() {
            if !bytes[i..i + sfx.len()].eq_ignore_ascii_case(sfx) {
                i += 1;
                continue;
            }
            let end = i + sfx.len();
            // Walk backwards to the start of the org name.
            let before = &text[..i];
            let mut name_start = before
                .rfind([',', '.', ';', '(', '\n'])
                .map_or(i.saturating_sub(60), |d| d + 1);
            // The `i-60` fallback may land mid-code-point; snap forward to a
            // boundary so the slice below is always valid.
            while name_start < i && !text.is_char_boundary(name_start) {
                name_start += 1;
            }
            let org = text[name_start..end].trim();
            if org.len() >= 5
                && org.starts_with(|c: char| c.is_ascii_uppercase())
                && terms
                    .iter()
                    .any(|t| org.to_lowercase().contains(t.as_str()))
            {
                orgs.push(org.to_string());
            }
            i = end;
        }
    }
    orgs
}

/// Semantic similarity between two strings using character bigram
/// overlap (Dice coefficient). Returns 0.0–1.0.
pub(super) fn bigram_similarity(a: &str, b: &str) -> f64 {
    fn bigrams(s: &str) -> Vec<(char, char)> {
        let chars: Vec<char> = s.to_lowercase().chars().collect();
        chars.windows(2).map(|w| (w[0], w[1])).collect()
    }
    let ba = bigrams(a);
    let bb = bigrams(b);
    if ba.is_empty() || bb.is_empty() {
        return 0.0;
    }
    let matches = ba.iter().filter(|bg| bb.contains(bg)).count();
    (2 * matches) as f64 / (ba.len() + bb.len()) as f64
}

pub(super) fn extract_emails_from_text(text: &str) -> Vec<String> {
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
        // A local-part that contains a web-script/page extension (`viewtopic.php`,
        // `index.html`) is not a mailbox — the `@` was glued to a forum/CMS URL
        // fragment during HTML stripping (a real scan produced the bogus
        // `viewtopic.phprose.cl@onet.eu`). Reject these outright.
        let local_lower = text[local_start..i].to_lowercase();
        const SCRIPT_EXT: &[&str] = &[
            ".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".cgi", ".cfm", ".phtml",
        ];
        if SCRIPT_EXT.iter().any(|ext| local_lower.contains(ext)) {
            i = domain_end;
            continue;
        }
        if domain.contains('.') && domain.len() > 3 && (domain_end - local_start) <= 254 {
            let email = text[local_start..domain_end].to_lowercase();
            if !email.ends_with(".png")
                && !email.ends_with(".jpg")
                && !email.ends_with(".gif")
                && !email.ends_with(".css")
                && !email.ends_with(".svg")
                && !email.ends_with(".webp")
                && !email.ends_with(".ico")
                && !email.ends_with(".woff")
                && !email.ends_with(".woff2")
                && !email.contains("@2x.")
                && !email.contains("@3x.")
            {
                emails.push(email);
                if emails.len() >= 50 {
                    break;
                }
            }
        }
        i = domain_end;
    }
    emails
}

pub(super) fn extract_phones_from_text(text: &str) -> Vec<String> {
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
                if phones.len() >= 30 {
                    break;
                }
            }
        } else {
            i += 1;
        }
    }
    phones
}

pub(super) fn is_email_local_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b == b'+'
}

pub(super) fn is_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_orgs_does_not_panic_on_non_ascii_lowercase_divergence() {
        // Regression: offsets were taken from text.to_lowercase() (not
        // length-preserving: İ U+0130 is 2 bytes, lowercases to 3) and used to
        // slice the original text → out-of-bounds / mid-codepoint str index
        // panic, fatal under panic="abort". A hostile SERP snippet must not
        // crash the scan; a normal org must still extract.
        let terms = vec!["acme".to_string(), "pty".to_string()];
        // Must not panic (İ before a company suffix is the original repro).
        let _ = extract_organisations_from_text("İ Pty Ltd", &terms);
        let _ = extract_organisations_from_text("ẞomething Inc and İ Pty Ltd", &terms);
        // Normal ASCII extraction still works.
        let got = extract_organisations_from_text("Contact ACME Pty Ltd today", &terms);
        assert!(
            got.iter().any(|o| o.contains("ACME Pty Ltd")),
            "expected ACME Pty Ltd, got {got:?}"
        );
    }

    #[test]
    fn abn_validator_does_not_panic_on_leading_zero() {
        // Regression: an 11-digit candidate starting with '0' lifted from a
        // live search result used to overflow (0u32.wrapping_sub(1) * 10) and
        // panic the search_engines module mid-scan. Must now return false.
        assert!(!is_valid_abn("01234567890"));
        assert!(!is_valid_abn("00000000000"));
    }

    #[test]
    fn abn_validator_accepts_known_valid() {
        // ATO worked-example ABN (also the README's `--kind abn` example).
        assert!(is_valid_abn("51824753556"));
    }

    #[test]
    fn abn_validator_rejects_wrong_length_and_checksum() {
        assert!(!is_valid_abn("123")); // too short
        assert!(!is_valid_abn("123456789012")); // too long
        assert!(!is_valid_abn("51824753557")); // valid length, bad checksum
        assert!(!is_valid_abn("abcdefghijk")); // non-digits → <11 digits
    }

    #[test]
    fn abn_validator_handles_all_leading_digits_without_panic() {
        // No 11-digit string should ever panic the validator, whatever the
        // leading digit — the whole point of the signed-wide accumulator.
        for first in '0'..='9' {
            let candidate = format!("{first}1824753556");
            let _ = is_valid_abn(&candidate); // must not panic
        }
    }
}
