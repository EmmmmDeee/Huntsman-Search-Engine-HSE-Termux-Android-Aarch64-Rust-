//! Shared XML text and attribute escaper rebuilt from `core/xml`.

#[must_use]
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\u{FFFE}' | '\u{FFFF}' => {}
            c if (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r') => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_escape_matches_contract() {
        assert_eq!(escape(r#"a&b<c>d"e'f"#), "a&amp;b&lt;c&gt;d&quot;e&apos;f");
        assert_eq!(escape("&lt;"), "&amp;lt;");
        assert_eq!(escape("a\u{FFFE}b\u{FFFF}c"), "abc");
        assert_eq!(escape("a\tb\nc\rd"), "a\tb\nc\rd");
        let hostile = "\u{0}<script>alert('x')</script>\u{8} & \"quoted\"";
        let out = escape(hostile);
        assert!(!out.contains('<') && !out.contains('>'));
        assert!(!out.contains('"') && !out.contains('\''));
    }
}
