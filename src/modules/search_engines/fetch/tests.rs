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

    /// Golden fixture (T2.7): a real, saved Bing SERP response for a benign
    /// public query, not a hand-typed HTML snippet. A layout change on Bing's
    /// side that breaks extraction fails THIS test, whereas a synthetic
    /// fixture only proves the parser matches what we assumed the markup
    /// looks like. Captured live via curl with the module's exact request
    /// shape (`EngineSpec` for `bing`): `GET
    /// https://www.bing.com/search?q=<query>&count=30` with `UA_MOBILE`.
    ///
    /// Bing's real markup wraps query-term matches inside `<cite>` in nested
    /// `<strong>` tags (e.g. `<cite>https://<strong>rust</strong>-lang.org
    /// </cite>`), which [`CiteIter`]'s `!clean.contains('<')` guard rejects
    /// by design (`cite_iter_skips_non_domains_and_malformed`). Real results
    /// still come through because Bing's result anchors also carry the
    /// complete absolute URL directly in `href=`, so [`HrefIter`] (the
    /// primary pass) finds them; `<cite>` is a fallback for engines that
    /// don't.
    #[test]
    fn parse_results_extracts_real_bing_serp_fixture() {
        let html = include_str!("testdata/bing_rust_programming_language.html");
        assert!(
            !is_captcha_page(html),
            "fixture must be a genuine results page, not a bot-block/interstitial"
        );

        let results = parse_results(html, "bing", "rust programming language");
        let urls: Vec<&str> = results.iter().map(|r| r.url.as_str()).collect();

        assert!(
            urls.len() >= 4,
            "expected several real results from a live Bing SERP, got {urls:?}"
        );
        assert!(
            urls.contains(&"https://rust-lang.org/"),
            "the official rust-lang.org result must be extracted, got {urls:?}"
        );
        assert!(
            urls.contains(&"https://en.wikipedia.org/wiki/Rust_(programming_language)"),
            "the Wikipedia result must be extracted, got {urls:?}"
        );
        // No engine-chrome or tracking domain should ever surface as a result.
        assert!(
            !urls.iter().any(|u| u.contains("bing.com")),
            "Bing's own chrome links must be filtered, got {urls:?}"
        );
    }
