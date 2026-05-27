pub(super) struct EngineSpec {
    pub(super) name: &'static str,
    pub(super) build_url: fn(&str) -> String,
    pub(super) build_post: Option<fn(&str) -> String>,
    pub(super) paginate: Option<fn(&str, usize) -> String>,
    pub(super) ua: &'static str,
    pub(super) ua_alt: &'static str,
}

// All 13 engines are always tried. Blocked engines are detected and
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
        build_post: Some(|q| format!("q={}&b=&kl=us-en&df=", crate::util::http::urlencode(q))),
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
            format!(
                "https://yandex.com/search/?text={}&lr=84",
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
];
