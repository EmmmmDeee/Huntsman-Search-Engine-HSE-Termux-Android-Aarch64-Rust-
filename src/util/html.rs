//! Minimal HTML→text helpers shared across modules.
//!
//! Not a full parser; just enough to feed plain text to regex-based
//! extractors (addresses, phones, emails, profile URLs) when the page
//! body is fetched as raw HTML.

use std::sync::OnceLock;

use regex::Regex;

/// Strip `<script>`/`<style>` blocks, remove remaining tags, and decode
/// the most common HTML entities. Returns plain text suitable for
/// regex extraction.
pub fn strip_html(html: &str) -> String {
    static SCRIPT: OnceLock<Regex> = OnceLock::new();
    static STYLE: OnceLock<Regex> = OnceLock::new();
    static TAG: OnceLock<Regex> = OnceLock::new();
    let script = SCRIPT.get_or_init(|| Regex::new(r"(?is)<script[^>]*>.*?</script>").unwrap());
    let style = STYLE.get_or_init(|| Regex::new(r"(?is)<style[^>]*>.*?</style>").unwrap());
    let tag = TAG.get_or_init(|| Regex::new(r"(?s)<[^>]+>").unwrap());
    let no_script = script.replace_all(html, " ");
    let no_style = style.replace_all(&no_script, " ");
    let no_tags = tag.replace_all(&no_style, " ");
    decode_entities(&no_tags)
}

/// Decode HTML entities in a single left-to-right pass: the named entities real
/// markup uses (`&amp; &lt; &gt; &quot; &apos; &nbsp;`) and ANY numeric character
/// reference — decimal `&#8217;` or hex `&#x2019;` (curly quotes, en/em dashes,
/// nbsp). Each `&…;` is consumed exactly once, so the escaped text `&amp;lt;`
/// round-trips to the literal `&lt;` (never double-decodes to `<`), and a
/// bare/unknown/malformed `&…;` is emitted verbatim. The single, shared decoder
/// for the whole codebase — `search_engines` delegates here so a title decoded in
/// a module matches one decoded in core/util.
pub fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let inner = &rest[amp + 1..]; // text after the '&'
        // Entity bodies are short and ASCII; `find(';')` lands on an ASCII byte
        // (a char boundary), so the slice below can never split a codepoint.
        if let Some(semi) = inner.find(';')
            && semi <= 10
            && let Some(ch) = decode_one_entity(&inner[..semi])
        {
            out.push(ch);
            rest = &inner[semi + 1..];
            continue;
        }
        out.push('&');
        rest = inner;
    }
    out.push_str(rest);
    out
}

/// Decode a single entity body (text between `&` and `;`) to its character, or
/// `None` if unrecognised/malformed. Named set covers real markup; numeric
/// references (`#8217`, `#x2019`) are decoded generically.
fn decode_one_entity(body: &str) -> Option<char> {
    match body {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        // Normalise NBSP to a regular space so decoded text stays word-splittable.
        "nbsp" => Some(' '),
        _ => {
            let num = body.strip_prefix('#')?;
            let cp = match num.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => num.parse::<u32>().ok()?,
            };
            char::from_u32(cp)
        }
    }
}

#[cfg(test)]
mod tests {
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
}
