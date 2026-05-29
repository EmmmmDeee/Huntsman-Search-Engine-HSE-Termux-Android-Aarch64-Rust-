//! Regional search localisation.
//!
//! Search engines return *different results by region* — Google `gl`/`hl`,
//! Bing `cc`/`setlang`, DuckDuckGo `kl`, etc. Setting `HUNTSMAN_REGION` (an ISO
//! country code like `AU`, or `au-en`) localises every engine that exposes a
//! safe locale parameter, so an AU-focused investigation gets AU-weighted
//! results. Engines without a well-known param are left untouched (no harm).
//!
//! This pairs with the proxy retriever: with a region set, `HUNTSMAN_PROXY=auto`
//! also prefers a same-country proxy (see `util::http`), so the request egresses
//! from the right locale too — the "high-yield range for that region".
//!
//! All functions are pure given an explicit `Option<Region>` (tested without
//! env); the `*_localized` wrappers read `HUNTSMAN_REGION` once.

/// A parsed locale: lowercase 2-letter country + language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Region {
    pub cc: String,
    pub lang: String,
}

/// Parse `HUNTSMAN_REGION` syntax: `"AU"`, `"au"`, or `"au-en"`. Returns `None`
/// for empty/malformed input (not a 2-letter country).
pub(super) fn parse_region(raw: &str) -> Option<Region> {
    let raw = raw.trim().to_lowercase();
    if raw.is_empty() {
        return None;
    }
    let (cc, lang) = match raw.split_once('-') {
        Some((c, l)) if !l.is_empty() => (c.to_string(), l.to_string()),
        _ => {
            let cc = raw.clone();
            (cc.clone(), cc_to_lang(&cc).to_string())
        }
    };
    if cc.len() != 2 || !cc.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(Region { cc, lang })
}

/// Default UI language for a country (best-effort; defaults to English).
fn cc_to_lang(cc: &str) -> &'static str {
    match cc {
        "fr" => "fr",
        "de" | "at" => "de",
        "es" | "mx" | "ar" => "es",
        "it" => "it",
        "br" | "pt" => "pt",
        "ru" => "ru",
        "jp" => "ja",
        "cn" | "tw" | "hk" => "zh",
        "nl" => "nl",
        "se" => "sv",
        "no" => "no",
        "pl" => "pl",
        _ => "en",
    }
}

/// Read the configured region from `HUNTSMAN_REGION`, if any.
pub(super) fn region() -> Option<Region> {
    parse_region(&std::env::var("HUNTSMAN_REGION").ok()?)
}

/// Append locale GET params for engines with a known-safe parameter. Pure.
pub(super) fn localize_url_with(engine: &str, url: &str, region: Option<&Region>) -> String {
    let Some(r) = region else {
        return url.to_string();
    };
    let sep = if url.contains('?') { '&' } else { '?' };
    match engine {
        "google" => format!("{url}{sep}gl={}&hl={}", r.cc, r.lang),
        "bing" => format!("{url}{sep}cc={}&setlang={}", r.cc, r.lang),
        "brave" => format!("{url}{sep}country={}", r.cc),
        "ecosia" => format!("{url}{sep}gl={}", r.cc),
        "qwant" => format!("{url}{sep}locale={}_{}", r.lang, r.cc.to_uppercase()),
        // Yahoo/AOL/Mojeek/Startpage/Dogpile/Yandex/Swisscows: no stable public
        // locale param — leave the URL unchanged.
        _ => url.to_string(),
    }
}

/// Localize a POST body (DuckDuckGo's `kl=<cc>-<lang>` region key). Pure.
pub(super) fn localize_post_with(engine: &str, body: &str, region: Option<&Region>) -> String {
    let Some(r) = region else {
        return body.to_string();
    };
    match engine {
        "duckduckgo" => body.replace("kl=us-en", &format!("kl={}-{}", r.cc, r.lang)),
        _ => body.to_string(),
    }
}

/// `localize_url_with` using the env-configured region.
pub(super) fn localize_url(engine: &str, url: &str) -> String {
    localize_url_with(engine, url, region().as_ref())
}

/// `localize_post_with` using the env-configured region.
pub(super) fn localize_post(engine: &str, body: &str) -> String {
    localize_post_with(engine, body, region().as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_region_forms() {
        assert_eq!(
            parse_region("AU"),
            Some(Region {
                cc: "au".into(),
                lang: "en".into()
            })
        );
        assert_eq!(
            parse_region("fr"),
            Some(Region {
                cc: "fr".into(),
                lang: "fr".into()
            })
        );
        assert_eq!(
            parse_region("au-en"),
            Some(Region {
                cc: "au".into(),
                lang: "en".into()
            })
        );
        assert_eq!(parse_region(""), None);
        assert_eq!(parse_region("australia"), None); // not 2-letter
        assert_eq!(parse_region("1!"), None);
    }

    #[test]
    fn localize_appends_per_engine_params() {
        let au = parse_region("AU");
        let r = au.as_ref();
        assert_eq!(
            localize_url_with("google", "https://www.google.com/search?q=x&num=20", r),
            "https://www.google.com/search?q=x&num=20&gl=au&hl=en"
        );
        assert_eq!(
            localize_url_with("bing", "https://www.bing.com/search?q=x&count=30", r),
            "https://www.bing.com/search?q=x&count=30&cc=au&setlang=en"
        );
        assert_eq!(
            localize_url_with("brave", "https://search.brave.com/search?q=x", r),
            "https://search.brave.com/search?q=x&country=au"
        );
        // Engine without a known param → unchanged.
        assert_eq!(
            localize_url_with("mojeek", "https://www.mojeek.com/search?q=x", r),
            "https://www.mojeek.com/search?q=x"
        );
    }

    #[test]
    fn localize_is_noop_without_region() {
        assert_eq!(
            localize_url_with("google", "https://www.google.com/search?q=x", None),
            "https://www.google.com/search?q=x"
        );
        assert_eq!(
            localize_post_with("duckduckgo", "q=x&b=&kl=us-en&df=", None),
            "q=x&b=&kl=us-en&df="
        );
    }

    #[test]
    fn localize_post_swaps_ddg_region() {
        let au = parse_region("au");
        assert_eq!(
            localize_post_with("duckduckgo", "q=x&b=&kl=us-en&df=", au.as_ref()),
            "q=x&b=&kl=au-en&df="
        );
    }
}
