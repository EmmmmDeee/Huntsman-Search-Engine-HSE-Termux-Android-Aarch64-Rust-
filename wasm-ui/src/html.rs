//! HTML-escaping shared by every view port under [`crate::scan_info`] (and
//! future top-level views) — one implementation instead of each port
//! re-deriving `src/web/js/helpers.js`'s `esc()` by hand.

/// Escapes `&`, `<`, `>`, `"`, and `'` for safe interpolation into an HTML
/// string. Mirrors `helpers.js`'s `esc()` exactly (same five characters, same
/// replacements, in the same order) so a ported view's output is
/// byte-for-byte identical to what the JS it replaces produced.
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_all_five_characters() {
        assert_eq!(
            escape_html(r#"<a href="x">'&'</a>"#),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn leaves_plain_text_untouched() {
        assert_eq!(escape_html("Elina Moreau"), "Elina Moreau");
    }

    #[test]
    fn empty_string_stays_empty() {
        assert_eq!(escape_html(""), "");
    }
}
