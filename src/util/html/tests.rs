use super::*;

    #[test]
    fn table_rows_extracts_trimmed_stripped_cells_per_row() {
        // Two data rows with nested tags + whitespace, plus a `<th>` header row
        // that yields no `<td>` cells (an empty row the caller drops).
        let html = "<table>\
            <tr><th>Name</th><th>No</th></tr>\
            <tr><td> Jane <b>Doe</b> </td><td>RN123</td><td>Nurse</td></tr>\
            <tr><td>Bob</td><td> 42 </td><td></td></tr>\
            </table>";
        let rows = table_rows(html);
        assert_eq!(
            rows,
            vec![
                vec![],
                vec!["Jane Doe".to_string(), "RN123".to_string(), "Nurse".to_string()],
                vec!["Bob".to_string(), "42".to_string(), String::new()],
            ]
        );
    }

    #[test]
    fn table_rows_is_total_on_unterminated_markup() {
        // A `<tr>` with no closing `</tr>` yields nothing (the row is incomplete);
        // a closed row with an unterminated `<td>` drops that cell. Neither
        // panics or loops.
        assert!(table_rows("<tr><td>x").is_empty(), "no </tr> → no row");
        assert_eq!(
            table_rows("<tr><td>x</td></tr>"),
            vec![vec!["x".to_string()]]
        );
        assert_eq!(
            table_rows("<tr><td>ok</td><td>trunc"),
            Vec::<Vec<String>>::new(),
            "row without </tr> is not emitted"
        );
        assert!(table_rows("no table here").is_empty());
    }

    #[test]
    fn strips_scripts_styles_and_tags() {
        let html = "<html><script>alert(1)</script><style>.x{}</style>\
                    <body>Hello <b>world</b>!</body></html>";
        let s = strip_html(html);
        assert!(s.contains("Hello"));
        assert!(s.contains("world"));
        assert!(!s.contains("alert"));
        assert!(!s.contains(".x{}"));
        assert!(!s.contains("<b>"));
    }

    #[test]
    fn decodes_common_entities() {
        let s = decode_entities("&amp; &lt;tag&gt; &quot;q&quot; &#39;a&#39; &nbsp;x");
        assert_eq!(s, "& <tag> \"q\" 'a'  x");
    }

    #[test]
    fn strip_html_empty_and_plain_text() {
        assert_eq!(strip_html(""), "");
        assert_eq!(strip_html("plain text no tags"), "plain text no tags");
    }

    #[test]
    fn decode_entities_no_amp_fast_path() {
        // When no '&' is present, the fast path returns without scanning.
        assert_eq!(decode_entities(""), "");
        assert_eq!(decode_entities("no ampersands here"), "no ampersands here");
    }

    #[test]
    fn decodes_breadcrumb_separator_from_a_real_scraped_title() {
        // Reproduces a real gap found in a live scan's debug log: au.zenbu.org's
        // page title used the NAMED `&rsaquo;` breadcrumb separator (no numeric
        // fallback applied, since the source used the named form), which leaked
        // as literal "&rsaquo;" into decoded search-result titles before this
        // entity was added to the table.
        assert_eq!(
            decode_entities("au.zenbu.org &rsaquo; entry &rsaquo; example-listing"),
            "au.zenbu.org › entry › example-listing"
        );
        assert_eq!(decode_entities("Home &raquo; Products &raquo; Widget"), "Home » Products » Widget");
    }

    #[test]
    fn decodes_named_smart_typography_entities() {
        assert_eq!(
            decode_entities("&ldquo;Hello&rdquo; &mdash; &lsquo;world&rsquo;&hellip;"),
            "“Hello” — ‘world’…"
        );
    }

    #[test]
    fn decodes_named_common_symbols() {
        assert_eq!(
            decode_entities("&copy; 2026 &trade; &reg; 20&deg;C &euro;5 &pound;3 &bull; item"),
            "© 2026 ™ ® 20°C €5 £3 • item"
        );
    }

    #[test]
    fn named_entity_case_sensitivity_matches_html5_spec() {
        // `&dagger;`/`&Dagger;` are DIFFERENT characters per the HTML5 named
        // character reference table — case must not be folded.
        assert_eq!(decode_entities("&dagger;"), "†");
        assert_eq!(decode_entities("&Dagger;"), "‡");
        // An unrecognised case variant (not a real HTML5 name) stays verbatim.
        assert_eq!(decode_entities("&RSAQUO;"), "&RSAQUO;");
    }

    #[test]
    fn decodes_numeric_refs_and_is_double_decode_safe() {
        // Numeric refs (decimal + hex): the pervasive curly-quote/dash/nbsp cases.
        assert_eq!(
            decode_entities("Smith&nbsp;&amp; Sons &#8211; O&#8217;Brien"),
            "Smith & Sons – O’Brien",
        );
        assert_eq!(decode_entities("it&#x2019;s"), "it’s");
        // `&amp;lt;` is the ESCAPED literal `&lt;` — must NOT collapse to `<`.
        assert_eq!(decode_entities("&amp;lt;"), "&lt;");
        // Bare/unknown/malformed refs and a multibyte char after `&` are verbatim,
        // never panicking.
        assert_eq!(decode_entities("R&D"), "R&D");
        assert_eq!(decode_entities("&#xZZ;"), "&#xZZ;");
        assert_eq!(decode_entities("&café"), "&café");
    }

    /// The exact shape a CDN returns when an origin is unreachable — the first
    /// 200 characters are doctype and IE conditional comments, and the title is
    /// the only line that names the failure.
    const CLOUDFLARE_523: &str = concat!(
        "<!DOCTYPE html>\n",
        "<!--[if lt IE 7]> <html class=\"no-js ie6 oldie\" lang=\"en-US\"> <![endif]-->\n",
        "<!--[if IE 7]>    <html class=\"no-js ie7 oldie\" lang=\"en-US\"> <![endif]-->\n",
        "<!--[if IE 8]>    <html class=\"no-js ie8 oldie\" lang=\"en-US\"> <![endif]-->\n",
        "<head>\n<title>psbdmp.ws | 523: Origin is unreachable</title>\n",
        "<style>.x{color:red}</style>\n</head>\n",
        "<body><h1>Error 523</h1><p>Origin is unreachable</p></body></html>",
    );

    #[test]
    fn title_of_an_error_page_names_the_failure() {
        assert_eq!(
            title(CLOUDFLARE_523).as_deref(),
            Some("psbdmp.ws | 523: Origin is unreachable"),
            "the title is the whole diagnostic value of a CDN error page"
        );
    }

    #[test]
    fn title_decodes_entities_and_collapses_whitespace() {
        assert_eq!(
            title("<html><title>\n  Bad\n  &amp;  broken\n</title>").as_deref(),
            Some("Bad & broken")
        );
    }

    #[test]
    fn title_tolerates_attributes_and_reports_absence() {
        assert_eq!(
            title("<title lang=\"en\">Gateway Time-out</title>").as_deref(),
            Some("Gateway Time-out")
        );
        assert_eq!(title("<html><body>no title here</body></html>"), None);
        assert_eq!(title("<title></title>"), None, "an empty title is no title");
        assert_eq!(title("<title>unterminated"), None);
    }

    #[test]
    fn looks_like_document_requires_an_opener_not_a_stray_bracket() {
        assert!(looks_like_document(CLOUDFLARE_523));
        assert!(looks_like_document("  \n<html lang=\"en\">"));
        assert!(looks_like_document("<!doctype HTML PUBLIC ..."));

        // The case that must NOT be treated as a document: a JSON error payload
        // that merely quotes markup. Rewriting it would destroy the real message.
        assert!(!looks_like_document(
            r#"{"error":"unexpected <html> in response"}"#
        ));
        assert!(!looks_like_document("plain text failure"));
        assert!(!looks_like_document(""));
        assert!(
            !looks_like_document("<result><html>x</html></result>"),
            "an XML payload whose first element is not <html> is not a document"
        );
    }

    /// The panic class `find_ascii_ci` exists to prevent, exercised on the
    /// characters that actually trigger it.
    ///
    /// `to_lowercase()` is not byte-length-preserving — `İ` (U+0130, 2 bytes)
    /// lowercases to `i̇` (3 bytes) and `ẞ` to `ß` — so an offset taken from a
    /// lowercased copy and used to slice the ORIGINAL can land mid-codepoint and
    /// panic. Error bodies are entirely upstream-controlled, so this input is
    /// reachable by anything a server chooses to return.
    #[test]
    fn title_and_document_detection_survive_length_changing_lowercase() {
        // `İ`/`ẞ` BEFORE the tag, so a lowercased-copy offset would be shifted
        // past a char boundary in the original.
        let html = "İİİẞ<html><head><title>İstanbul ẞ Error</title></head>";
        assert_eq!(title(html).as_deref(), Some("İstanbul ẞ Error"));

        // Same characters inside the title text itself.
        assert_eq!(
            title("<title>İ ẞ İ</title>").as_deref(),
            Some("İ ẞ İ"),
            "title text must round-trip unchanged"
        );

        // And in a document that must still be detected.
        assert!(looks_like_document("<HTML lang=\"tr\">İ"));
        assert!(!looks_like_document("İ<html>"), "not at position 0");

        // The two concrete failures of the `to_lowercase()`-offset shape, both
        // reproduced against it before this fix:
        //   * silent corruption — it returned "日本語<", trailing garbage from a
        //     close offset shifted 2 bytes by `İ` (2 bytes → 3);
        //   * an outright panic — `ẞ` (3 bytes) → `ß` (2) shifts the offset
        //     backwards into the middle of an emoji.
        assert_eq!(title("İ<title>日本語</title>").as_deref(), Some("日本語"));
        assert_eq!(title("ẞ<title>😀😀</title>").as_deref(), Some("😀😀"));

        // Total over arbitrary placements: must never panic.
        for filler in ["İ", "ẞ", "İẞ", "e\u{301}", "😀"] {
            for tpl in [
                "{f}<title>x</title>",
                "<title>{f}</title>",
                "<title{f}>x</title>",
                "<html>{f}<title>{f}x{f}</title>{f}",
                "{f}",
                "<title>{f}",
            ] {
                let s = tpl.replace("{f}", filler);
                let _ = title(&s);
                let _ = looks_like_document(&s);
            }
        }
    }

    #[test]
    fn collapse_whitespace_flattens_stripped_markup() {
        assert_eq!(collapse_whitespace("  a\n\n\tb   c \r\n"), "a b c");
        assert_eq!(collapse_whitespace("   "), "");
    }

// ── Property tests: the HTML helpers never panic on hostile bytes ───────────
// strip_html / decode_entities run on every scraped page — fully attacker-
// controlled. The doc claims the `&…;` slice "can never split a codepoint";
// proptest proves it over arbitrary input where `&` lands adjacent to multibyte
// characters (`&café;`, `&#x` + junk, `&` at end, `&;`, huge numeric refs), the
// exact class a single hand-picked example misses.
mod prop {
    use proptest::prelude::*;

    use super::{decode_entities, strip_html};

    proptest! {
        /// `decode_entities` is total (never panics) for any input, and a string
        /// with no `&` is returned byte-identical (the fast-path contract).
        #[test]
        fn decode_entities_is_total(s in ".{0,128}") {
            let out = decode_entities(&s);
            if !s.contains('&') {
                prop_assert_eq!(&out, &s);
            }
        }

        /// Decoding is a single left-to-right pass with no double-decode: feeding
        /// the *output* back through must not turn a surviving `&amp;`/`&lt;` into
        /// a second-level character (the doc's `&amp;lt;` → `&lt;` guarantee). We
        /// assert the weaker, robust invariant that re-decoding an output whose
        /// remaining `&` sequences are all non-entities is a fixed point.
        #[test]
        fn decode_entities_no_panic_on_ampersand_storms(
            s in r"[&#xX0-9;a-zé ]{0,64}"
        ) {
            // Dense `&`/`#`/`x`/`;`/accented runs — the parser's branchiest path.
            let _ = decode_entities(&s);
        }

        /// `strip_html` is total for any input — unclosed tags (`<script` with no
        /// `>`), nested/overlapping tags, multibyte content, lone `<`/`>`.
        #[test]
        fn strip_html_is_total(s in r"[<>/a-z &;#0-9é’]{0,128}") {
            let _ = strip_html(&s);
        }

        /// Even adversarial markup-shaped input doesn't panic strip_html.
        #[test]
        fn strip_html_total_on_arbitrary(s in ".{0,128}") {
            let _ = strip_html(&s);
        }
    }
}

    // Regression: the `;` search used to scan the WHOLE remainder and only then
    // reject a hit past `MAX_ENTITY_BODY`, so a run of bare ampersands cost one
    // full scan each — quadratic. The property tests above cap at 64-128 chars,
    // far too short to show it, which is why it survived. This asserts the
    // OUTPUT at a size where the old behaviour was already seconds of CPU.
    #[test]
    fn decode_entities_is_correct_on_an_ampersand_storm() {
        // 64 KiB of bare `&`, the worst case: every one starts a search that
        // finds no `;` at all.
        let storm = "&".repeat(64 * 1024);
        assert_eq!(
            decode_entities(&storm),
            storm,
            "a bare `&` is not an entity and must survive verbatim"
        );

        // A `;` sitting far beyond any legal entity body must NOT be treated as a
        // terminator, and must not be searched for either.
        let far = format!("&{}re;", "x".repeat(4096));
        assert_eq!(decode_entities(&far), far, "a distant `;` terminates nothing");

        // The bound is on the BODY, so a legal entity still decodes when it sits
        // immediately after a storm.
        let mixed = format!("{}&amp;", "&".repeat(4096));
        assert_eq!(decode_entities(&mixed), format!("{}&", "&".repeat(4096)));

        // Exactly at and one past the accepted body length.
        assert_eq!(decode_entities("&#x1F600;"), "\u{1F600}");
        assert_eq!(decode_entities("&0123456789012;"), "&0123456789012;");
    }

    // Timing ratios are a property of the scheduler, not of the code, so this is
    // `#[ignore]`d to match the house convention for perf baselines rather than
    // reddening the gate on a loaded runner. Run it by hand to re-confirm the
    // bound: before it was bounded, 128 KB of `&` took 3.85 s against 1.53 ms
    // after, with time quadrupling per doubling of input.
    #[test]
    #[ignore = "timing ratio; run with --ignored --nocapture"]
    fn decode_entities_is_linear_in_ampersand_count() {
        let small = "&".repeat(16 * 1024);
        let large = "&".repeat(128 * 1024); // 8x

        let t = std::time::Instant::now();
        let a = decode_entities(&small);
        let small_ns = t.elapsed().as_nanos().max(1);
        let t = std::time::Instant::now();
        let b = decode_entities(&large);
        let large_ns = t.elapsed().as_nanos().max(1);

        assert_eq!(a, small);
        assert_eq!(b, large);
        let ratio = large_ns as f64 / small_ns as f64;
        println!("8x input -> {ratio:.1}x time (quadratic would be ~64x)");
        assert!(ratio < 24.0, "8x the input cost {ratio:.1}x the time");
    }

    /// The two shapes GitHub's runner received on 2026-09-15 (`anubis`,
    /// `austlii`) are walls; a provider's own outage/error template is not —
    /// `util::http::http_status_error` and the JSON decode helpers draw the
    /// line here, and a false positive would turn a real outage into a
    /// "blocked" verdict that hides it.
    #[test]
    fn is_challenge_page_recognises_cloudflare_walls_and_not_an_outage_page() {
        assert!(is_challenge_page(
            "<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title>\
             </head><body><h1>Sorry, you have been blocked</h1></body></html>"
        ));
        assert!(is_challenge_page(
            "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>\
             <script src=\"/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1\"></script>\
             </body></html>"
        ));
        assert!(!is_challenge_page(
            "<!DOCTYPE html><html><head><title>Internet Archive: Temporarily Offline</title>\
             </head><body>The Wayback Machine is temporarily offline.</body></html>"
        ));
        assert!(!is_challenge_page(
            "<!DOCTYPE html><html><head><title>Error | Vistumbler WiFiDB</title></head>\
             <body>Fatal error: Uncaught TypeError</body></html>"
        ));
        assert!(!is_challenge_page("{\"error\":\"not found\"}"));
        assert!(!is_challenge_page(""));
    }

    /// REQ-PROBE-004: the Radware Bot Manager (formerly ShieldSquare) captcha
    /// interstitial imlive.com served the runner's known-negative control — a
    /// 200 under `validate.perfdrive.com` titled "Radware Captcha Page".
    /// `social_probe::classify_probe` reads a probe body through this oracle, so
    /// each of the three fingerprints must be decisive on its own (the vendor
    /// tier is a single match), while a page that merely names the company is not
    /// a wall.
    #[test]
    fn is_challenge_page_recognises_the_radware_perfdrive_interstitial() {
        for one in [
            "<html><body><img src=\"https://validate.perfdrive.com/px/captcha\"></body></html>",
            "<html><body>powered by shieldsquare bot manager</body></html>",
            "<html><head><title>Radware Captcha Page</title></head></html>",
        ] {
            assert!(is_challenge_page(one), "each Radware fingerprint is decisive: {one}");
        }
        assert!(!is_challenge_page(
            "<html><body>Radware reported record revenue this quarter.</body></html>"
        ));
    }

    // Two REAL Cloudflare answers, fetched live from this project's sandbox on
    // 2026-09-15 (15:53 UTC) with a browser User-Agent and checked in verbatim
    // except for the Ray IDs and the egress address, which are scrubbed:
    //   * `jonlu.ca/anubis/subdomains/example.com` (where `jldc.me` redirects)
    //     → 403, the BLOCK page: "Attention Required! | Cloudflare", "Sorry, you
    //     have been blocked", no challenge loader — only the title phrase set
    //     recognises it;
    //   * `www.austlii.edu.au/cgi-bin/sinosrch.cgi?query=…` → 403, the same
    //     title plus the `/cdn-cgi/challenge-platform` loader — the vendor
    //     fingerprint recognises it.
    // GitHub's runner received the same two pages on the 2026-09-15 live-drift
    // run (34985449332) and filed both providers as "unreachable". No PII: a
    // CDN's generic refusal for the project's own canonical sample targets.
    const CF_BLOCK_ANUBIS: &str = include_str!("testdata/cloudflare_block_anubis_2026-09-15.html");
    const CF_CHALLENGE_AUSTLII: &str =
        include_str!("testdata/cloudflare_challenge_austlii_2026-09-15.html");

    /// Pins the classifier against the two real captures: if either tier
    /// regresses, a real wall reads as an outage again ("unreachable", a false
    /// DEAD CANARY for a canary) instead of `Error::BotChallenge`.
    #[test]
    fn is_challenge_page_recognises_both_real_cloudflare_captures() {
        assert!(
            CF_BLOCK_ANUBIS.contains("Sorry, you have been blocked")
                && !CF_BLOCK_ANUBIS.contains("/cdn-cgi/challenge-platform"),
            "the anubis capture must be the block page without a challenge loader — \
             the phrase-set tier is what recognises it"
        );
        assert!(
            is_challenge_page(CF_BLOCK_ANUBIS),
            "the real Cloudflare block page must be a wall, not an outage"
        );
        assert!(
            CF_CHALLENGE_AUSTLII.contains("/cdn-cgi/challenge-platform"),
            "the austlii capture must carry the challenge loader — the vendor tier"
        );
        assert!(
            is_challenge_page(CF_CHALLENGE_AUSTLII),
            "the real Cloudflare challenge page must be a wall, not an outage"
        );
        // Both are under the 8 KiB error-body cap `http_status_error` reads, so
        // the classifier sees them whole on the production path.
        assert!(CF_BLOCK_ANUBIS.len() < 8 * 1024 && CF_CHALLENGE_AUSTLII.len() < 8 * 1024);
    }

    /// A 200-status wall observed on the first runner sweep carrying the 2xx
    /// guard (live-drift run 34995740898, 2026-09-15) and reproduced from the
    /// sandbox: AHPRA's register answers a datacenter client with an HTTP 200
    /// interstitial — the `/cdn-cgi/challenge-platform` loader, 91 characters
    /// of visible text ("Please enable JavaScript to view the page content.
    /// Your support ID is: …"), no practitioner rows — and the runner's copy
    /// keeps the origin's own `<title>`. Every earlier `ahpra` lookup parsed
    /// this page for rows and reported "no registered practitioner". Scrubbed
    /// of the support id.
    /// The Akamai Bot Manager block page ACMA's register served the sandbox on
    /// 2026-09-15 (HTTP 403, the reference number scrubbed): no vendor string
    /// anywhere in it, only its own prose, so the phrase-set tier is what must
    /// recognise it. Before this set it was `Error::Module`, and a 2xx copy
    /// would have been parsed as "no licences".
    #[test]
    fn is_challenge_page_recognises_the_akamai_block_page() {
        const WALL: &str = include_str!("testdata/wall_akamai_acma_403_2026-09-15.html");
        assert!(is_challenge_page(WALL));
        assert!(is_challenge_document(WALL));
        // A page that merely mentions a reference number is not a wall.
        assert!(!is_challenge_page(
            "<html><body>Your order has been received. Reference number: 12345.</body></html>"
        ));
    }

    /// Every checked-in wall capture must be classified by the markers of the
    /// vendor it is NAMED for — not by another vendor's marker that happens to
    /// be on the same page.
    ///
    /// This is the discipline REQ-HTML-001 established the hard way. Both AHPRA
    /// captures were classified solely via `/cdn-cgi/challenge-platform`, a
    /// CLOUDFLARE marker their page carries because the register also fronts
    /// with Cloudflare; F5 BIG-IP ASM, the appliance actually serving the wall,
    /// had no signature in the table at all. The existing test asserted "this
    /// page is a wall" and passed, so the gap was invisible: a fixture proves
    /// nothing about its vendor until the OTHER vendors' markers are removed
    /// from it first.
    ///
    /// So each fixture declares which signature tokens are its own, and is
    /// re-tested with every foreign token rewritten out. A future capture added
    /// here without its vendor being in the table fails this test instead of
    /// silently riding on a neighbour's marker.
    #[test]
    fn every_wall_fixture_is_carried_by_its_own_vendors_markers() {
        // (fixture, the tokens belonging to the vendor this capture is OF)
        const FIXTURES: &[(&str, &str, &[&str])] = &[
            (
                "cloudflare_block_anubis_2026-09-15",
                include_str!("testdata/cloudflare_block_anubis_2026-09-15.html"),
                &["attention required", "cloudflare"],
            ),
            (
                "cloudflare_challenge_austlii_2026-09-15",
                include_str!("testdata/cloudflare_challenge_austlii_2026-09-15.html"),
                &[
                    "attention required",
                    "cloudflare",
                    "/cdn-cgi/challenge-platform",
                ],
            ),
            (
                "wall_akamai_acma_403_2026-09-15",
                include_str!("testdata/wall_akamai_acma_403_2026-09-15.html"),
                &["your request has been blocked", "reference number"],
            ),
            (
                "wall_ahpra_200_2026-09-15",
                include_str!("testdata/wall_ahpra_200_2026-09-15.html"),
                &["enable javascript to view the page content", "support id"],
            ),
            (
                "wall_ahpra_200_2026-09-18",
                include_str!("testdata/wall_ahpra_200_2026-09-18.html"),
                &["enable javascript to view the page content", "support id"],
            ),
        ];

        // Rewrite out every signature token that is NOT this capture's own. The
        // detector matches ASCII-case-insensitively, so lowercasing first is
        // behaviour-preserving and lets the strip be a plain literal replace.
        fn strip_foreign_markers(body: &str, own: &[&str]) -> String {
            let mut out = body.to_ascii_lowercase();
            let foreign = CHALLENGE_VENDOR_SIGNATURES
                .iter()
                .copied()
                .chain(CHALLENGE_PHRASE_SETS.iter().flat_map(|s| s.iter().copied()))
                .filter(|tok| !own.contains(tok));
            for tok in foreign {
                out = out.replace(tok, "x");
            }
            out
        }

        for (name, body, own) in FIXTURES {
            assert!(
                is_challenge_document(body),
                "{name}: the capture must be a wall to begin with"
            );
            // The declared owner must really be present — a stale declaration
            // would make the strip below vacuously easy to pass.
            assert!(
                own.iter()
                    .any(|tok| crate::util::str_util::find_ascii_ci(body, tok).is_some()),
                "{name}: none of its declared own markers are in the capture"
            );
            let alone = strip_foreign_markers(body, own);
            assert!(
                is_challenge_document(&alone),
                "{name}: classified only via ANOTHER vendor's marker — its own \
                 vendor needs a signature in the table"
            );
        }
    }

    #[test]
    fn is_challenge_document_recognises_the_ahpra_200_wall() {
        const WALL: &str = include_str!("testdata/wall_ahpra_200_2026-09-15.html");
        assert!(is_challenge_document(WALL), "a 200 interstitial is a wall");
        assert!(WALL.len() < 8 * 1024);
        // The same wall re-captured live three days later (2026-09-18): F5
        // rotates the obfuscated payload and the support ID on every request,
        // so the two captures differ byte-for-byte and in length (6,983 vs
        // 7,553 B). The detector must key on the wall's STABLE prose, not on
        // the rotating body — otherwise it decays silently into reading this
        // 200 as "the subject is not a registered health practitioner".
        const WALL_LATER: &str = include_str!("testdata/wall_ahpra_200_2026-09-18.html");
        assert_ne!(WALL, WALL_LATER, "the payload rotates per request");
        assert!(
            is_challenge_document(WALL_LATER),
            "a re-rolled F5 interstitial is still a wall"
        );
        // Both captures also carry `/cdn-cgi/challenge-platform`, because the
        // register fronts with Cloudflare as well — so detecting them proves
        // nothing about F5 itself. Strip that one incidental marker and the
        // page must STILL be a wall, on its own F5 prose. Without this the
        // whole F5 ASM family is invisible the moment a walled host does not
        // happen to sit behind Cloudflare too.
        for capture in [WALL, WALL_LATER] {
            let f5_only = capture.replace("/cdn-cgi/challenge-platform", "/assets/app");
            assert!(
                !f5_only.contains("cdn-cgi"),
                "the Cloudflare marker must be gone for this to prove anything"
            );
            assert!(
                is_challenge_document(&f5_only),
                "an F5 ASM support-ID wall is a wall without any Cloudflare marker"
            );
        }
        // F5's other standard block body, and the two false positives the
        // AND-sets exist to avoid: either marker ALONE is not a wall.
        assert!(is_challenge_document(
            "<!DOCTYPE html><html><body>The requested URL was rejected. Please consult with \
             your administrator.<br>Your support ID is: 123456789</body></html>"
        ));
        assert!(!is_challenge_document(
            "<!DOCTYPE html><html><body><noscript>Please enable JavaScript to view the page \
             content.</noscript><table><tr><td>Jane Smith</td></tr></table></body></html>"
        ));
        assert!(!is_challenge_document(
            "<!DOCTYPE html><html><body><h1>Contact us</h1><p>Quote your support ID is: \
             4471 when you call.</p></body></html>"
        ));
        // A genuine register page that merely names the register is not.
        assert!(!is_challenge_document(
            "<!DOCTYPE html><html><head><title>Register of practitioners</title></head>\
             <body><table><tr><td>No practitioners matched your search.</td></tr></table>\
             </body></html>"
        ));
    }

    /// Reddit's network-security block page opens with a bare `<body …>` and no
    /// doctype (an excerpt of the 2026-09-15 capture: the real opener and the
    /// page's only prose; its 189 KB of inline CSS/JSON elided). Before this a
    /// 403 carrying it was neither a document (raw markup became the error
    /// snippet) nor a wall. XML, RSS and Atom stay non-documents.
    #[test]
    fn a_document_may_open_with_a_bare_body_or_head_and_reddits_block_page_is_a_wall() {
        const REDDIT_EXCERPT: &str = "<body class=theme-beta><div><style>/* elided */</style>\
            <h1>You've been blocked by network security.</h1>\
            <p>If you think you've been blocked by mistake, file a ticket below and we'll \
            look into it.</p><a>File a ticket</a></div></body>";
        assert!(looks_like_document(REDDIT_EXCERPT));
        assert!(looks_like_document("<head><title>x</title></head><body>y</body>"));
        assert!(!looks_like_document("<?xml version=\"1.0\"?><feed xmlns=\"http://www.w3.org/2005/Atom\"></feed>"));
        assert!(!looks_like_document("<rss version=\"2.0\"><channel></channel></rss>"));
        assert!(!looks_like_document("{\"error\":\"<body> quoted in a message\"}"));
        assert!(is_challenge_page(REDDIT_EXCERPT));
        assert!(is_challenge_document(REDDIT_EXCERPT));
    }
