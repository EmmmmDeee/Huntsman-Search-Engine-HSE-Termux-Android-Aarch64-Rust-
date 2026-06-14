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
    fn decodes_common_entities() {
        let s = decode_entities("&amp; &lt;tag&gt; &quot;q&quot; &#39;a&#39; &nbsp;x");
        assert_eq!(s, "& <tag> \"q\" 'a'  x");
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
