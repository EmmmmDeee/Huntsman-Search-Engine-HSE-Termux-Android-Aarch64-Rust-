pub(super) struct EngineSpec {
    pub(super) name: &'static str,
    pub(super) build_url: fn(&str) -> String,
    pub(super) build_post: Option<fn(&str) -> String>,
    pub(super) paginate: Option<fn(&str, usize) -> String>,
    pub(super) ua: &'static str,
    pub(super) ua_alt: &'static str,
    /// Per-engine fetch ceiling (ms). Overrides the global `MAX_FETCH_MS` when
    /// set. Use for engines whose real-world latency distribution makes the
    /// global 8 s cap wasteful (e.g. DDG: 6.6 s avg / 56% unreachable from
    /// datacenter IPs — a 4 s cap fails fast without sacrificing recall from
    /// the 1/41 ok case).
    pub(super) max_fetch_ms: Option<u64>,
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
                "https://search.yahoo.com/search?p={}&n=30",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        paginate: Some(|q, page| {
            // `b=` is a 1-based result offset; it MUST track the `n=30` page size
            // so consecutive pages don't overlap.
            format!(
                "https://search.yahoo.com/search?p={}&n=30&b={}",
                crate::util::http::urlencode(q),
                1 + page * 30
            )
        }),
        ua: crate::util::curl::UA_MOBILE,
        ua_alt: crate::util::curl::UA_DESKTOP,
        max_fetch_ms: None,
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
        max_fetch_ms: None,
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
        // Live scan: 0/203 ok, 591 ms avg — fails at network layer consistently.
        // 800 ms cap cuts p95 outliers without sacrificing the near-zero hit rate.
        max_fetch_ms: Some(800),
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
        // Live scans: 6.6 s avg / 56% unreachable from datacenter IPs.
        // 4 s cap fails fast without sacrificing the occasional ok result.
        max_fetch_ms: Some(4_000),
    },
    EngineSpec {
        name: "google",
        build_url: |q| {
            format!(
                "https://www.google.com/search?q={}&num=30",
                crate::util::http::urlencode(q)
            )
        },
        build_post: None,
        paginate: Some(|q, page| {
            // `start=` is a 0-based result offset; it MUST track the `num=30` page
            // size so consecutive pages don't overlap.
            format!(
                "https://www.google.com/search?q={}&num=30&start={}",
                crate::util::http::urlencode(q),
                page * 30
            )
        }),
        ua: crate::util::curl::UA_MOBILE,
        ua_alt: crate::util::curl::UA_DESKTOP,
        max_fetch_ms: None,
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
            // Brave's web `offset` is a 0-based PAGE index (offset=1 → page 2),
            // not a result count. The caller fetches page 0 via `build_url` and
            // then calls this with `page` starting at 1, so the first paginated
            // request must ask for offset=1 (page 2). Using `page + 1` here asked
            // for offset=2 and silently skipped Brave's second page of results.
            format!(
                "https://search.brave.com/search?q={}&offset={}",
                crate::util::http::urlencode(q),
                page
            )
        }),
        ua: crate::util::curl::UA_DESKTOP,
        ua_alt: crate::util::curl::UA_SAFARI,
        max_fetch_ms: None,
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
        // Live scan: 0/203 ok, 576 ms avg — consistently unreachable from DC IPs.
        max_fetch_ms: Some(800),
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
        max_fetch_ms: None,
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
        // Live scan: 0/203 ok, 938 ms avg — Russian CDN blocks DC IPs at TLS layer.
        // 1 s cap saves ~(938-1000 clamped → 938) ms per dispatch on average;
        // cuts p95 outliers meaningfully.
        max_fetch_ms: Some(1_000),
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
        max_fetch_ms: None,
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
        // Live scan: 0/203 ok, 1780 ms avg, 3585 ms p95 — consistently blocked.
        // 1.5 s cap cuts the long tail (p95 at 3.6 s) and saves ~460 ms per
        // dispatch on average vs the global 8 s ceiling.
        max_fetch_ms: Some(1_500),
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
        max_fetch_ms: None,
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
        max_fetch_ms: None,
    },
    // ── Extended engines (2026 batch 2) ─────────────────────────────
    // you.com's `?tbm=youchat` view is NOT a classic HTML SERP (corrected
    // 2026-07-14, T2.7 golden-fixture corpus, seventh slice): a real live
    // capture is a Cloudflare-gated Next.js SPA with zero server-rendered
    // `<a href>` result anchors anywhere in the body — every result is
    // hydrated client-side by JS this engine never executes. The Cloudflare
    // challenge script (`/cdn-cgi/challenge-platform/…`) is present in the
    // raw HTML, so `is_captcha_page` already classifies every real fetch
    // as `Blocked` (never a fabricated "empty" success) — kept in `ENGINES`
    // for the rare instance that skips the challenge, detected/skipped in
    // <1s otherwise via the interstitial detector in `fetch_and_parse`.
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
        max_fetch_ms: None,
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
        // Live scan: 0/203 ok, 794 ms avg — anti-bot blocks DC IPs consistently.
        max_fetch_ms: Some(1_000),
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
        max_fetch_ms: None,
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
        max_fetch_ms: None,
    },
];

/// Engines used for the secondary pivot + entity-recycler passes — the most
/// reliable from both Termux residential and DC IPs. Resolved by NAME via
/// [`reliable_engines`] rather than by array index, so reordering or inserting
/// into [`ENGINES`] can never silently repoint those passes at the wrong
/// engines (the prior `ENGINES[0/1/5]` indexing was a latent drift bug).
/// Order here is the order they're tried.
///
/// Live scan evidence (depth-2 "Onur Ada", 6,688 engine dispatches each):
///   swisscows: 100% hit, 0% blocked,  4 results/call (DC + residential)
///   dogpile:    97% hit, 0% blocked,  1 result/call  (DC + residential)
///   yahoo/bing/brave: killed by SESSION_DEAD after <400 dispatches from DC IPs
///
/// `metager` was demoted from this set (T2.7 golden-fixture corpus, fourth
/// slice, 2026-07-13): a real live capture proved its legacy `/meta/meta.ger3`
/// endpoint now unconditionally redirects to MetaGer's own marketing homepage
/// regardless of query, cookies, or HTTP method — confirmed with two
/// independent real queries plus MetaGer's own `robots.txt Disallow: /meta/`
/// — so the "100% hit, 0% blocked, 20 results/call" figure this comment used
/// to quote for it is disproven, not merely stale. `metager` stays registered
/// in [`ENGINES`] (still dispatched normally in the primary pass, now
/// correctly yielding zero rather than 30 fake chrome-leak "results" — see
/// `helpers::urls::ENGINE_DOMAINS`) in case a future cycle finds a working
/// replacement endpoint; it is no longer trusted as part of the GUARANTEED
/// floor `pivot_engine_set` always falls back to, since it currently
/// contributes zero genuine results to that floor.
pub(super) const RELIABLE_ENGINE_NAMES: [&str; 2] = ["swisscows", "dogpile"];

/// Resolve [`RELIABLE_ENGINE_NAMES`] to their [`EngineSpec`]s, preserving that
/// order. A name absent from [`ENGINES`] is skipped; the
/// `reliable_engines_resolve_by_name` test asserts both resolve, so a
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
