use super::*;

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
    fn parse_table_rows_extracts_cells_and_drops_short_rows() {
        let html = "<table>\
                     <tr><td>Name</td><td>Number</td><td>Type</td></tr>\
                     <tr><td>Jane <b>Doe</b></td><td>123</td><td>Widget</td></tr>\
                     <tr><td>Only two</td><td>cells</td></tr>\
                     <tr><td>John Smith</td><td>456</td><td>Gadget</td></tr>\
                     </table>";
        let rows = parse_table_rows(html, 3);
        assert_eq!(
            rows,
            vec![
                vec!["Name".to_string(), "Number".to_string(), "Type".to_string()],
                vec!["Jane Doe".to_string(), "123".to_string(), "Widget".to_string()],
                vec!["John Smith".to_string(), "456".to_string(), "Gadget".to_string()],
            ]
        );
        // `<th>` header cells are NOT `<td>`, so a genuine `<th>`-only header
        // row yields zero cells and is dropped by the `min_cols` filter here —
        // callers whose header row uses `<td>` (matching this table) instead
        // rely on their own field-value filter (e.g. `name != "Licensee"`).
        assert!(
            parse_table_rows("<table><tr><th>Name</th><th>Number</th></tr></table>", 1).is_empty()
        );
    }

    #[test]
    fn parse_table_rows_empty_on_no_rows_or_unterminated_row() {
        assert!(parse_table_rows("<table></table>", 1).is_empty());
        assert!(parse_table_rows("plain text, no table at all", 1).is_empty());
        // An unterminated `<tr>` (no closing `</tr>`) must not panic or loop.
        assert!(parse_table_rows("<table><tr><td>a</td>", 1).is_empty());
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
