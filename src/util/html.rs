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

/// Decode the handful of HTML entities most commonly seen in
/// scraped contact pages.
pub fn decode_entities(s: &str) -> String {
    s.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
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
}
