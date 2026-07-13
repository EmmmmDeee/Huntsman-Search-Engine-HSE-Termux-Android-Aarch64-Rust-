use super::*;

    /// The fetch-timeout clamp is what stops an in-flight request from overrunning
    /// the module deadline: a request is NEVER issued past the deadline, and one
    /// issued under it is capped to the remaining budget (never the full fixed
    /// ceiling), so it always finishes before the engine's hard kill.
    #[test]
    fn fetch_timeout_clamps_to_remaining_budget() {
        use std::time::{Duration, Instant};
        // Past / too-soon deadlines yield no request at all.
        assert_eq!(fetch_timeout_ms(Instant::now() - Duration::from_secs(1)), None);
        assert_eq!(
            fetch_timeout_ms(Instant::now() + Duration::from_millis(500)),
            None,
            "under the MIN_FETCH floor → don't bother starting"
        );
        // Plenty of budget → capped at the per-request ceiling.
        assert_eq!(
            fetch_timeout_ms(Instant::now() + Duration::from_secs(60)),
            Some(MAX_FETCH_MS)
        );
        // A few seconds left → clamped to (about) that, never the full ceiling.
        let t = fetch_timeout_ms(Instant::now() + Duration::from_millis(3_000))
            .expect("3 s is above the floor");
        assert!(
            (MIN_FETCH_MS..=3_000).contains(&t),
            "clamped to the ~3 s that remain, not the 8 s ceiling: got {t}"
        );
    }

    /// SERP HTML comes from arbitrary, untrusted search engines — it can be
    /// truncated, malformed, or have a multibyte codepoint butted against any
    /// structural marker (`href=`, a quote, `<cite>`, the ` ›` breadcrumb, `>`,
    /// `/url?q=`, `&`). The result parser and its iterators must NEVER panic
    /// (a mid-codepoint byte slice would), so a hostile page can't crash a scan.
    /// This drives the whole pipeline over a battery of adversarial inputs; the
    /// assertion is simply that none of them unwind.
    #[test]
    fn result_parsers_never_panic_on_adversarial_html() {
        let m = "é"; // 2-byte codepoint to land next to markers
        let bell = "›"; // 3-byte U+203A, the Bing breadcrumb glyph
        let cases: Vec<String> = vec![
            String::new(),
            "<".into(),
            "href=".into(),        // truncated, no quote
            format!("href={m}"),   // multibyte right after marker
            "href=\"".into(),      // open quote, no close
            format!("href=\"{m}"), // unterminated multibyte value
            format!("<a href=\"http://{}.com/{m}\">{m}</a>", "x".repeat(50)),
            "<cite".into(),                // truncated cite, no '>'
            format!("<cite>{m}{bell}{m}"), // cite, no close, multibyte+breadcrumb
            format!("<cite>http://a.com {bell} {m}</cite>"),
            "</cite>".into(),
            format!("<cite>{}</cite>", bell.repeat(100)),
            "/url?q=".into(),             // truncated google redirect
            format!("/url?q=http://{m}"), // multibyte, no terminator
            format!("/url?q=https%3A%2F%2F{m}&sa=U"),
            format!("a href='//{m}.com' {m}> <cite>{m}{bell}</cite> /url?q={m}\""),
            format!("<a href=\"{m}>"),             // marker then bare '>'
            "&amp;&lt;&#x;&#;&#999999999;".into(), // entity edge cases via add_result
            format!("<a href=\"javascript:{m}\">x</a>"), // filtered scheme + multibyte
            "\u{0}\u{1}<a href=\"\u{7}\">\u{0}</a>".into(), // control chars
            format!("<a href=\"http://b.com\">{}</a>", m.repeat(5000)), // bulk anchor text
        ];
        for (i, html) in cases.iter().enumerate() {
            // Each of these would unwind on a bad byte slice; reaching the next
            // line is the assertion.
            let _ = parse_results(html, "fuzz", "the query");
            let _ = HrefIter::new(html).count();
            let _ = CiteIter::new(html).count();
            let _ = GoogleUrlIter::new(html).count();
            let _ = external_link_count(html, "fuzz");
            // Sanity: any URL produced is non-empty and the title/snippet are
            // valid UTF-8 (guaranteed by `&str`, but assert the result shape).
            for r in parse_results(html, "fuzz", "the query") {
                assert!(!r.url.is_empty(), "case {i}: empty URL emitted");
            }
        }
    }

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
    fn add_result_preserves_complete_query_string_url() {
        // Regression: a clean result URL with a query string must be stored in
        // FULL. The old blanket `form_urlencoded` decode split on '&'/'=' and
        // truncated e.g. `…/watch?v=abc&t=5s` down to `…/watch?v`.
        let html = r#"<a href="https://www.youtube.com/watch?v=abc123&t=5s">video</a>"#;
        let urls: Vec<String> = parse_results(html, "test", "q")
            .into_iter()
            .map(|r| r.url)
            .collect();
        assert!(
            urls.contains(&"https://www.youtube.com/watch?v=abc123&t=5s".to_string()),
            "complete query-string URL must be preserved, got {urls:?}"
        );
    }

    #[test]
    fn add_result_decodes_percent_encoded_redirect_target() {
        // The Google /url?q= path yields a percent-encoded target; it must still
        // decode to a COMPLETE URL with its query string intact.
        let html =
            r#"<a href="/url?q=https%3A%2F%2Fexample.org%2Fa%3Fid%3D42%26page%3D2&sa=U">x</a>"#;
        let urls: Vec<String> = parse_results(html, "test", "q")
            .into_iter()
            .map(|r| r.url)
            .collect();
        assert!(
            urls.contains(&"https://example.org/a?id=42&page=2".to_string()),
            "percent-encoded redirect target must decode to a complete URL, got {urls:?}"
        );
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

    /// Regression (real-execution derived): the EXACT 332-byte body Mojeek
    /// returned with HTTP 403 in a live 8/8-run sweep. It is < 500 bytes, so the
    /// old ordering returned `Unreachable` ("down") before `is_captcha_page` ran
    /// — mislabelling an anti-bot *block* as a network failure. `is_captcha_page`
    /// must now recognise it so `try_fetch` returns `Blocked`.
    #[test]
    fn mojeek_403_automated_queries_detected_as_block() {
        let body = "<!DOCTYPE html><html><head><title>403 - Forbidden</title></head>\
            <body><h1>403 - Forbidden</h1><h2>Sorry your network appears to be \
            sending automated queries so we can't process your search at this \
            time.</h2><h3>If you are seeing this in error please \
            <a href=\"/about/contact?refr=403&q=example.com\">contact us</a>.</h3>\
            </body></html>";
        assert!(body.len() < 500, "fixture must exercise the short-body path");
        assert!(
            is_captcha_page(body),
            "Mojeek 403 'sending automated queries' page must be detected as a block"
        );
    }

    /// The other side of the reorder: a genuinely tiny/empty response that
    /// matches no block signature must NOT be misread as a block (it stays
    /// `Unreachable` in `try_fetch`).
    #[test]
    fn short_non_block_body_is_not_flagged() {
        assert!(!is_captcha_page("<html><body>ok</body></html>"));
        assert!(!is_captcha_page(""));
    }

    // ── Golden fixture (T2.7 "scraper resilience" — the corpus leg) ─────────
    //
    // `testdata/brave_kylo4kylo.html` is a REAL Brave SERP response, fetched
    // live (2026-07-12) for the project's own canonical test seed `Kylo4kylo`
    // and checked in verbatim — not a hand-written fragment. Real SERP HTML is
    // where this parser actually breaks: engines ship SvelteKit/React shells,
    // footer chrome, and result markup that drifts without notice, and the
    // existing inline-literal tests above (small, hand-crafted `href=`/`<cite>`
    // fragments) can't catch that because they're never wrong in the way a real
    // page is. This is the first slice of the corpus this node calls for — one
    // real engine, proving the pattern — not all 17 at once.
    const GOLDEN_BRAVE_KYLO4KYLO: &str = include_str!("testdata/brave_kylo4kylo.html");

    /// If Brave's markup drifts enough to break `href=` extraction, this fails
    /// deterministically instead of the silent-empty-results failure mode T2.7
    /// exists to catch (a scan that just quietly returns nothing from Brave).
    #[test]
    fn parse_results_extracts_from_a_real_brave_serp_capture() {
        let results = parse_results(GOLDEN_BRAVE_KYLO4KYLO, "brave", "Kylo4kylo");
        assert!(
            !results.is_empty(),
            "a layout change silently broke extraction from this real, \
             previously-working Brave capture"
        );

        let urls: Vec<&str> = results.iter().map(|r| r.url.as_str()).collect();
        // Pin specific, known-present organic hits from this exact capture — a
        // drift narrow enough to keep SOME results (so the emptiness check above
        // stays green) but that silently drops a class of card (e.g. the
        // Instagram-embed layout, or `<cite>`-based hosts) still fails here.
        assert!(
            urls.iter().any(|u| u.contains("instagram.com/kylo4k")),
            "expected the Instagram profile hit, got: {urls:?}"
        );
        assert!(
            urls.iter().any(|u| u.contains("wikipedia.org/wiki/Kylo_Ren")),
            "expected the Wikipedia hit, got: {urls:?}"
        );
        assert!(
            urls.iter().any(|u| u.contains("youtube.com")),
            "expected a YouTube hit, got: {urls:?}"
        );
        // Every extracted URL is a genuine organic result, never the engine's
        // own account/CDN/branding chrome — `is_engine_domain` must still be
        // doing its job against this real page's footer links.
        for u in &urls {
            assert!(
                !u.contains("brave.com") && !u.contains("cdn.search.brave"),
                "engine chrome link leaked into results: {u}"
            );
        }
        // Deterministic count: pins the exact yield so a change that silently
        // drops (or duplicates) even one real result is caught, not just a
        // change that empties the page entirely.
        assert_eq!(
            results.len(),
            26,
            "expected exactly 26 organic results from this fixture, got {}: {urls:?}",
            results.len()
        );
    }

    // `testdata/bing_kylo4kylo.html` is a REAL Bing SERP response, fetched live
    // (2026-07-13) for the project's own canonical test seed `Kylo4kylo` and
    // checked in verbatim. Bing is the second slice of the golden-fixture
    // corpus (Brave was the first, T2.75-1) and specifically the highest-risk
    // engine for a `<cite>`-format drift: `parse_results`' secondary extraction
    // path reads Bing's `<cite>` tags for the display URL, a markup shape none
    // of the other 16 engines use. This real capture happens to return zero
    // results actually about `Kylo4kylo` — Bing's own answer for this exact
    // query, on this exact page, was five unrelated ESPN links — which is
    // itself a genuine, honestly-observed result: this test is not about
    // recall or relevance (that's the correlator/audit's job), only that the
    // parser extracts every real result block a live page contains without
    // silently dropping some or leaking engine chrome, exactly the failure
    // mode T2.7 exists to catch.
    const GOLDEN_BING_KYLO4KYLO: &str = include_str!("testdata/bing_kylo4kylo.html");

    /// If Bing's `<cite>`-based markup drifts enough to break extraction, this
    /// fails deterministically instead of the silent-empty-results failure mode
    /// T2.7 exists to catch.
    #[test]
    fn parse_results_extracts_from_a_real_bing_serp_capture() {
        let results = parse_results(GOLDEN_BING_KYLO4KYLO, "bing", "Kylo4kylo");
        assert!(
            !results.is_empty(),
            "a layout change silently broke extraction from this real, \
             previously-working Bing capture"
        );

        let urls: Vec<&str> = results.iter().map(|r| r.url.as_str()).collect();
        // Pin the specific real hosts present in this exact capture.
        assert!(
            urls.iter().any(|u| u.contains("espn.com")),
            "expected the espn.com hit, got: {urls:?}"
        );
        assert!(
            urls.iter().any(|u| u.contains("facebook.com/ESPN")),
            "expected the Facebook hit, got: {urls:?}"
        );
        assert!(
            urls.iter().any(|u| u.contains("espn.co.uk")),
            "expected the espn.co.uk hit, got: {urls:?}"
        );
        // Every extracted URL is a genuine organic result, never the engine's
        // own account/CDN/branding chrome — `is_engine_domain` must still be
        // doing its job against this real page's `bing.com`-hosted assets
        // (this capture's own `<link>`/`<script>` CDN paths).
        for u in &urls {
            assert!(
                !u.contains("bing.com"),
                "engine chrome link leaked into results: {u}"
            );
        }
        // Deterministic count: pins the exact yield so a change that silently
        // drops (or duplicates) even one real result is caught, not just a
        // change that empties the page entirely.
        assert_eq!(
            results.len(),
            5,
            "expected exactly 5 organic results from this fixture, got {}: {urls:?}",
            results.len()
        );
    }

    // `testdata/duckduckgo_kylo4kylo.html` is a REAL DuckDuckGo HTML-endpoint
    // (`html.duckduckgo.com/html/`) response, fetched live (2026-07-13) for the
    // project's own canonical test seed `Kylo4kylo` and checked in verbatim.
    // DuckDuckGo is the third slice of the golden-fixture corpus (Brave then
    // Bing) and specifically exercises the primary `href=` extraction path's
    // `resolve_href` redirect-unwrap step against DDG's own
    // `//duckduckgo.com/l/?uddg=...` wrapper links (already unit-tested with
    // hand-written fragments elsewhere in this module, but never against a
    // real, full DDG results page with its actual chrome/nav/footer links
    // alongside the wrapped organic hits). This real capture happens to
    // return four results unrelated to `Kylo4kylo` specifically — an
    // honestly-observed real result, not a fabricated one: this test is about
    // extraction completeness, never relevance (that's the correlator/audit's
    // job).
    const GOLDEN_DUCKDUCKGO_KYLO4KYLO: &str = include_str!("testdata/duckduckgo_kylo4kylo.html");

    /// If DDG's `uddg=`-wrapped href markup drifts enough to break the redirect
    /// unwrap, this fails deterministically instead of the silent-empty-results
    /// failure mode T2.7 exists to catch.
    #[test]
    fn parse_results_extracts_from_a_real_duckduckgo_serp_capture() {
        let results = parse_results(GOLDEN_DUCKDUCKGO_KYLO4KYLO, "duckduckgo", "Kylo4kylo");
        assert!(
            !results.is_empty(),
            "a layout change silently broke extraction from this real, \
             previously-working DuckDuckGo capture"
        );

        let urls: Vec<&str> = results.iter().map(|r| r.url.as_str()).collect();
        // Pin the specific real hosts present in this exact capture.
        assert!(
            urls.iter().any(|u| u.contains("teamk4l.com")),
            "expected the teamk4l.com hit, got: {urls:?}"
        );
        assert!(
            urls.iter().any(|u| u.contains("tiktok.com")),
            "expected the TikTok hit, got: {urls:?}"
        );
        assert!(
            urls.iter().any(|u| u.contains("youtube.com")),
            "expected the YouTube hit, got: {urls:?}"
        );
        assert!(
            urls.iter().any(|u| u.contains("watch.plex.tv")),
            "expected the plex.tv hit, got: {urls:?}"
        );
        // Every extracted URL is a genuine organic result, never DDG's own
        // account/CDN/branding chrome or an un-unwrapped redirect wrapper —
        // `is_engine_domain` + `resolve_href`'s `uddg=` unwrap must both still
        // be doing their job against this real page's nav/footer links.
        for u in &urls {
            assert!(
                !u.contains("duckduckgo.com"),
                "engine chrome or un-unwrapped redirect link leaked into results: {u}"
            );
        }
        // Deterministic count: pins the exact yield so a change that silently
        // drops (or duplicates) even one real result is caught, not just a
        // change that empties the page entirely.
        assert_eq!(
            results.len(),
            4,
            "expected exactly 4 organic results from this fixture, got {}: {urls:?}",
            results.len()
        );
    }

    /// Golden-fixture corpus, fourth slice: MetaGer, one of only THREE engines
    /// in [`super::super::engines::RELIABLE_ENGINE_NAMES`] — the guaranteed
    /// floor `pivot_engine_set` falls back to when nothing else has proven
    /// live yet, so a silent defect here degrades the core cross-platform
    /// pivot/recycle pass on every scan, not just one engine's coverage.
    ///
    /// A REAL live capture of this exact fixture (`eingabe=Kylo4kylo`,
    /// followed through its redirect) surfaced a genuine, previously-unknown
    /// defect rather than merely proving the happy path: MetaGer's own
    /// homepage/language-switcher/footer chrome (`metager.org`, the separate
    /// `maps.metager.de` subdomain, and `suma-ev.de` — MetaGer's own
    /// nonprofit operator, self-disclosed in this exact page's "MetaGer is
    /// developed and run by our nonprofit organization, SUMA-EV" text) was
    /// **not** in [`super::super::helpers::ENGINE_DOMAINS`], so all 30 of
    /// those self-referential links were extracted as fake organic
    /// "results" — false positives, the defect class this project's own
    /// evidentiary doctrine treats as worse than missing coverage. Fixed by
    /// adding the three domains to `ENGINE_DOMAINS`.
    const GOLDEN_METAGER_KYLO4KYLO: &str = include_str!("testdata/metager_kylo4kylo.html");

    /// Pins the fix: every one of this real capture's 30 raw hits is
    /// MetaGer's own chrome, so post-fix extraction is correctly EMPTY, not a
    /// specific non-empty count like the Brave/Bing/DuckDuckGo slices. A
    /// regression that drops any of the three `ENGINE_DOMAINS` entries this
    /// fix added would silently reopen the false-positive leak on every
    /// MetaGer query. Git-stash-proven: reverting the `ENGINE_DOMAINS`
    /// addition makes this fail (30 leaked results); restored, it passes.
    #[test]
    fn parse_results_excludes_metagers_own_chrome_from_a_real_serp_capture() {
        let results = parse_results(GOLDEN_METAGER_KYLO4KYLO, "metager", "Kylo4kylo");
        let urls: Vec<&str> = results.iter().map(|r| r.url.as_str()).collect();
        assert!(
            urls.is_empty(),
            "every hit in this real capture is MetaGer's own homepage/footer/nonprofit-\
             operator chrome, none of it a genuine organic result — a fix that leaves any \
             leaking through is a false-positive regression: {urls:?}"
        );
    }
