//! Search-engine helpers — URL classification and normalisation.
//!
//! Reaches the other helper groups and shared imports through `use super::*`.

use super::*;

pub(in crate::modules::search_engines) fn extract_path_username(url: &str) -> Option<String> {
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

// ─── URL helpers ────────────────────────────────────────────────────────────

pub(in crate::modules::search_engines) fn extract_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_lowercase))
        .unwrap_or_default()
}

pub(in crate::modules::search_engines) const ENGINE_DOMAINS: &[&str] = &[
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

pub(in crate::modules::search_engines) fn is_engine_domain(host: &str) -> bool {
    ENGINE_DOMAINS
        .iter()
        .any(|d| crate::util::domains::is_or_subdomain_of(host, d))
}

/// Domains that are generic infrastructure / unrelated to any target.
/// These appear in search result pages from engine chrome, ads, or
/// generic navigation links, never as OSINT-relevant findings.
pub(in crate::modules::search_engines) fn is_generic_domain(domain: &str) -> bool {
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
pub(in crate::modules::search_engines) fn is_search_tooling_domain(domain: &str) -> bool {
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

pub(in crate::modules::search_engines) fn is_tracking_url(url: &str) -> bool {
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

pub(in crate::modules::search_engines) fn is_non_name_word(s: &str) -> bool {
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
        "named",
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

pub(in crate::modules::search_engines) fn is_navigation_path(s: &str) -> bool {
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
        "dir",
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
        // LinkedIn directory prefix: `linkedin.com/pub/dir/First/Last` is a
        // people-search URL, not a profile — its first path segment `pub`
        // (with `dir`) must never become a "username".
        "pub",
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
pub(in crate::modules::search_engines) fn target_terms(target: &Target) -> Vec<String> {
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

/// Code-repository hosts whose first path segment is the account *owner* (the
/// identity-bearing handle), and whose later segments name a repository, branch
/// or file — content that merely *belongs* to that owner.
const REPO_HOSTS: &[&str] = &["github.com", "gitlab.com", "bitbucket.org"];

/// True when a code-repo URL matched a target term only in a NON-owner segment
/// (a repository / file name), while the owner handle itself shares nothing with
/// the target — i.e. a project that happens to be named after the subject's term,
/// not the subject's own account.
///
/// A live "Haigen Bamford" scan surfaced `github.com/ExponentiAI/HAIGEN` (an AI
/// project under the org `ExponentiAI`): it matched on the repo name "HAIGEN"
/// but the owner is unrelated. `github.com/Haigen` (owner == term) and
/// `github.com/haigenbamford/repo` (owner contains a term) are the subject's own
/// accounts and are NOT off-target. Hosts outside [`REPO_HOSTS`] never match.
pub(in crate::modules::search_engines) fn is_offtarget_repo_url(
    url: &str,
    terms: &[String],
) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    let host = parsed.host_str().unwrap_or("").trim_start_matches("www.");
    if !REPO_HOSTS.contains(&host) {
        return false;
    }
    let segments: Vec<&str> = parsed.path().split('/').filter(|s| !s.is_empty()).collect();
    // Need an owner + at least one deeper segment to be a repo/file URL.
    if segments.len() < 2 {
        return false;
    }
    let owner = segments[0].to_lowercase();
    let term_in = |s: &str| {
        terms
            .iter()
            .filter(|t| t.len() >= 4)
            .any(|t| s.contains(t.as_str()))
    };
    let owner_matches = term_in(&owner);
    let deeper_matches = segments[1..].iter().any(|s| term_in(&s.to_lowercase()));
    // Off-target only when the owner is unrelated yet a deeper segment matched.
    !owner_matches && deeper_matches
}

/// Check whether a URL's path contains any target term (≥4 chars).
pub(in crate::modules::search_engines) fn url_matches_target(url: &str, terms: &[String]) -> bool {
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

pub(in crate::modules::search_engines) fn dedup_results(
    mut results: Vec<SearchResult>,
) -> Vec<SearchResult> {
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
pub(in crate::modules::search_engines) fn canonicalize_url(url: &str) -> String {
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

pub(in crate::modules::search_engines) fn extract_registrable(host: &str) -> String {
    crate::util::domains::registrable_domain(host).unwrap_or_else(|| host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_path_username_first_segment_only_when_handle_shaped() {
        assert_eq!(
            extract_path_username("https://github.com/torvalds").as_deref(),
            Some("torvalds")
        );
        // Deeper path: only the first segment is the handle candidate.
        assert_eq!(
            extract_path_username("https://x.com/jane.doe/status/1").as_deref(),
            Some("jane.doe")
        );
        // Too short, root, and unparseable all yield None (never panic).
        assert_eq!(extract_path_username("https://github.com/ab"), None);
        assert_eq!(extract_path_username("https://github.com/"), None);
        assert_eq!(extract_path_username("not a url"), None);
    }

    #[test]
    fn extract_host_lowercases_and_tolerates_garbage() {
        assert_eq!(extract_host("https://Example.COM/path"), "example.com");
        assert_eq!(extract_host("garbage"), String::new());
    }

    #[test]
    fn canonicalize_url_strips_tracking_keeps_content_params() {
        // Fragment + trailing slash dropped; campaign params stripped.
        assert_eq!(
            canonicalize_url("https://x.com/page/?utm_source=nl&fbclid=abc#frag"),
            "https://x.com/page"
        );
        // CONTRACT: distinct content params must NOT collapse — else real results
        // would be silently dropped by dedup.
        assert_ne!(
            canonicalize_url("https://yt.com/watch?v=A"),
            canonicalize_url("https://yt.com/watch?v=B")
        );
        // Content params are preserved and order-normalised so the key is stable.
        assert_eq!(
            canonicalize_url("https://x.com/p?b=2&a=1"),
            "https://x.com/p?a=1&b=2"
        );
        // A URL that is only tracking params reduces to the bare base.
        assert_eq!(
            canonicalize_url("https://x.com/p?gclid=1&utm_medium=x"),
            "https://x.com/p"
        );
    }

    #[test]
    fn is_tracking_url_flags_known_redirectors_only() {
        assert!(is_tracking_url("https://r.search.yahoo.com/RV=2/RU=abc"));
        assert!(is_tracking_url("https://site.test/privacy-policy"));
        assert!(!is_tracking_url("https://example.com/about"));
    }

    #[test]
    fn url_matches_target_needs_a_long_term_in_the_path() {
        let terms = vec!["jordan".to_string(), "ab".to_string()];
        assert!(url_matches_target("https://x.com/jordan-avery", &terms));
        // Short terms (<4) are ignored; a path without any long term fails.
        assert!(!url_matches_target("https://x.com/profile", &terms));
        assert!(!url_matches_target("https://x.com/ab", &["ab".to_string()]));
    }
}
