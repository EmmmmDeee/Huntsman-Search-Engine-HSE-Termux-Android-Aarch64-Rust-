pub(super) struct EngineSpec {
    pub(super) name: &'static str,
    pub(super) build_url: fn(&str) -> String,
    pub(super) build_post: Option<fn(&str) -> String>,
    pub(super) paginate: Option<fn(&str, usize) -> String>,
    pub(super) ua: &'static str,
    pub(super) ua_alt: &'static str,
}

// All 17 engines are always tried. Blocked engines are detected and
// skipped in <1s via the interstitial detector in fetch_and_parse.
// Yahoo/Bing are most reliable from datacenter IPs. DDG/Google/Brave
// work best from residential IPs (Termux). AOL is Yahoo-powered (same
// /RU= format). Mojeek has an independent index.
//
// New engines (2026): Startpage (POST, Google-sourced), Yandex
// (independent Russian index), Ecosia (Bing-powered), Qwant (European
// privacy engine), Dogpile (System1 meta-aggregator), Swisscows
// (Swiss Bing-powered). These may be CAPTCHA-blocked from datacenter
// IPs but work from Termux residential connections.
pub(super) const ENGINES: &[EngineSpec] = &[
    // ── Original 7 engines ──────────────────────────────────────────
    EngineSpec {
        name: "yahoo",
        build_url: |q| {
            format!(
                "https://search.yahoo.com/search?p={}&n=20",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        paginate: Some(|q, page| {
            format!(
                "https://search.yahoo.com/search?p={}&n=20&b={}",
                crate::util::http::urlencode(q),
                1 + page * 20
            )
        }),
        ua: crate::util::curl::UA_MOBILE,
        ua_alt: crate::util::curl::UA_DESKTOP,
    },
    EngineSpec {
        name: "bing",
        build_url: |q| {
            format!(
                "https://www.bing.com/search?q={}&count=30",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        paginate: Some(|q, page| {
            format!(
                "https://www.bing.com/search?q={}&count=30&first={}",
                crate::util::http::urlencode(q),
                1 + page * 30
            )
        }),
        ua: crate::util::curl::UA_MOBILE,
        ua_alt: crate::util::curl::UA_DESKTOP,
    },
    EngineSpec {
        name: "aol",
        build_url: |q| {
            format!(
                "https://search.aol.com/aol/search?q={}",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        paginate: Some(|q, page| {
            format!(
                "https://search.aol.com/aol/search?q={}&b={}",
                crate::util::http::urlencode(q),
                1 + page * 10
            )
        }),
        ua: crate::util::curl::UA_MOBILE,
        ua_alt: crate::util::curl::UA_DESKTOP,
    },
    EngineSpec {
        name: "duckduckgo",
        build_url: |_q| "https://html.duckduckgo.com/html/".to_string(),
        // `kl=wt-wt` is DDG's "No region" (worldwide) — geolocation-neutral by
        // default so results aren't biased to a single country. Regional bias is
        // opt-in (see the regional-search toggle), not baked in here.
        build_post: Some(|q| format!("q={}&b=&kl=wt-wt&df=", crate::util::http::urlencode(q))),
        paginate: None,
        ua: crate::util::curl::UA_FIREFOX,
        ua_alt: crate::util::curl::UA_DESKTOP,
    },
    EngineSpec {
        name: "google",
        build_url: |q| {
            format!(
                "https://www.google.com/search?q={}&num=20",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        paginate: Some(|q, page| {
            format!(
                "https://www.google.com/search?q={}&num=20&start={}",
                crate::util::http::urlencode(q),
                page * 20
            )
        }),
        ua: crate::util::curl::UA_MOBILE,
        ua_alt: crate::util::curl::UA_DESKTOP,
    },
    EngineSpec {
        name: "brave",
        build_url: |q| {
            format!(
                "https://search.brave.com/search?q={}",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        paginate: Some(|q, page| {
            format!(
                "https://search.brave.com/search?q={}&offset={}",
                crate::util::http::urlencode(q),
                page + 1
            )
        }),
        ua: crate::util::curl::UA_DESKTOP,
        ua_alt: crate::util::curl::UA_SAFARI,
    },
    EngineSpec {
        name: "mojeek",
        build_url: |q| {
            format!(
                "https://www.mojeek.com/search?q={}",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        paginate: Some(|q, page| {
            format!(
                "https://www.mojeek.com/search?q={}&s={}",
                crate::util::http::urlencode(q),
                page * 10
            )
        }),
        ua: crate::util::curl::UA_DESKTOP,
        ua_alt: crate::util::curl::UA_MOBILE,
    },
    // ── New engines (2026) ──────────────────────────────────────────
    EngineSpec {
        name: "startpage",
        build_url: |_q| "https://www.startpage.com/sp/search".to_string(),
        build_post: Some(|q| {
            format!(
                "query={}&cat=web&abp=1&abd=1&abe=1",
                crate::util::http::urlencode(q)
            )
        }),
        paginate: None,
        ua: crate::util::curl::UA_FIREFOX,
        ua_alt: crate::util::curl::UA_DESKTOP,
    },
    EngineSpec {
        name: "yandex",
        build_url: |q| {
            // No `lr=` region id — geolocation-neutral (global results), not
            // pinned to a single country.
            format!(
                "https://yandex.com/search/?text={}",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        paginate: None,
        ua: crate::util::curl::UA_DESKTOP,
        ua_alt: crate::util::curl::UA_MOBILE,
    },
    EngineSpec {
        name: "ecosia",
        build_url: |q| {
            format!(
                "https://www.ecosia.org/search?method=index&q={}",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        paginate: None,
        ua: crate::util::curl::UA_FIREFOX,
        ua_alt: crate::util::curl::UA_SAFARI,
    },
    EngineSpec {
        name: "qwant",
        build_url: |q| {
            format!(
                "https://lite.qwant.com/?q={}&t=web",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        paginate: None,
        ua: crate::util::curl::UA_FIREFOX,
        ua_alt: crate::util::curl::UA_DESKTOP,
    },
    EngineSpec {
        name: "dogpile",
        build_url: |q| {
            format!(
                "https://www.dogpile.com/serp?q={}",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        paginate: None,
        ua: crate::util::curl::UA_DESKTOP,
        ua_alt: crate::util::curl::UA_SAFARI,
    },
    EngineSpec {
        name: "swisscows",
        build_url: |q| {
            format!(
                "https://swisscows.com/en/web?query={}",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        paginate: None,
        ua: crate::util::curl::UA_DESKTOP,
        ua_alt: crate::util::curl::UA_FIREFOX,
    },
    // ── Extended engines (2026 batch 2) ─────────────────────────────
    // you.com is conversational but exposes a classic /search HTML view
    // with referrer-style result anchors. Useful when other engines are
    // CAPTCHA-blocked.
    EngineSpec {
        name: "you",
        build_url: |q| {
            format!(
                "https://you.com/search?q={}&tbm=youchat",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        paginate: None,
        ua: crate::util::curl::UA_DESKTOP,
        ua_alt: crate::util::curl::UA_FIREFOX,
    },
    // Presearch is a decentralised privacy engine that proxies to a
    // configurable backend. The HTML view is parsable like DDG/Brave.
    EngineSpec {
        name: "presearch",
        build_url: |q| {
            format!(
                "https://presearch.com/search?q={}",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        paginate: None,
        ua: crate::util::curl::UA_DESKTOP,
        ua_alt: crate::util::curl::UA_FIREFOX,
    },
    // MetaGer (German non-profit) federates 50+ underlying engines and
    // returns clean HTML; rarely CAPTCHA-blocked.
    EngineSpec {
        name: "metager",
        build_url: |q| {
            format!(
                "https://metager.org/meta/meta.ger3?eingabe={}",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        paginate: None,
        ua: crate::util::curl::UA_FIREFOX,
        ua_alt: crate::util::curl::UA_DESKTOP,
    },
    // SearXNG public instances aggregate dozens of engines. We point
    // at the well-known etsi.org instance; if blocked, the engine
    // falls back via the standard interstitial detector path.
    EngineSpec {
        name: "searx",
        build_url: |q| {
            format!(
                "https://searx.be/search?q={}&format=html&categories=general",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        paginate: None,
        ua: crate::util::curl::UA_DESKTOP,
        ua_alt: crate::util::curl::UA_FIREFOX,
    },
];

/// Engines used for the secondary pivot + entity-recycler passes — the most
/// reliable from Termux residential IPs (Yahoo/Bing are stable; Brave works
/// well off-CAPTCHA). Resolved by NAME via [`reliable_engines`] rather than by
/// array index, so reordering or inserting into [`ENGINES`] can never silently
/// repoint those passes at the wrong engines (the prior `ENGINES[0/1/5]`
/// indexing was a latent drift bug). Order here is the order they're tried.
pub(super) const RELIABLE_ENGINE_NAMES: [&str; 3] = ["yahoo", "bing", "brave"];

/// Resolve [`RELIABLE_ENGINE_NAMES`] to their [`EngineSpec`]s, preserving that
/// order. A name absent from [`ENGINES`] is skipped; the
/// `reliable_engines_resolve_by_name` test asserts all three resolve, so a
/// rename/removal in [`ENGINES`] fails CI instead of silently shrinking the
/// reliable set at runtime.
pub(super) fn reliable_engines() -> Vec<&'static EngineSpec> {
    RELIABLE_ENGINE_NAMES
        .iter()
        .filter_map(|name| ENGINES.iter().find(|e| e.name == *name))
        .collect()
}

#[cfg(test)]
mod geo_tests {
    use super::*;

    #[test]
    fn engine_queries_are_geolocation_neutral_by_default() {
        // No engine may hard-pin a country/region in its default query — results
        // stay global unless regional searching is explicitly toggled on.
        const REGION_LOCKS: &[&str] = &["kl=us", "&lr=", "?lr=", "&gl=", "&cc=", "country="];
        for e in ENGINES {
            let url = (e.build_url)("probe");
            let post = e.build_post.map(|f| f("probe")).unwrap_or_default();
            for lock in REGION_LOCKS {
                assert!(
                    !url.contains(lock),
                    "engine {} has region lock '{lock}' in its URL: {url}",
                    e.name
                );
                assert!(
                    !post.contains(lock),
                    "engine {} has region lock '{lock}' in its POST body: {post}",
                    e.name
                );
            }
        }
        // DuckDuckGo is explicitly worldwide (kl=wt-wt), not US-pinned.
        let ddg = ENGINES.iter().find(|e| e.name == "duckduckgo").unwrap();
        let post = (ddg.build_post.unwrap())("probe");
        assert!(post.contains("kl=wt-wt"), "ddg must be worldwide: {post}");
    }
}
