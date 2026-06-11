//! Minimal HTML→text helpers shared across modules.
//!
//! Not a full parser; just enough to feed plain text to regex-based
//! extractors (addresses, phones, emails, profile URLs) when the page
//! body is fetched as raw HTML.
//!
//! Termux/aarch64 note: [`strip_html`] is a single allocation-light pass —
//! one output buffer, no regex engine, no backtracking — rather than the
//! former three chained `Regex::replace_all` calls (which allocated a fresh
//! full-document `String` per stage and backtracked over `.*?`). On a
//! memory-constrained phone scraping many result pages this is the difference
//! between O(3n) transient allocation per page and O(n) into one buffer.

/// Strip `<script>`/`<style>` blocks, remove remaining tags, and decode
/// the most common HTML entities. Returns plain text suitable for
/// regex extraction.
///
/// Each removed tag or raw block collapses to a single space (matching the
/// prior regex pipeline's `replace_all(_, " ")` semantics exactly), inter-tag
/// text is preserved verbatim, then entities are decoded in one final pass.
/// Faithful to the old behaviour on the awkward cases too: tag matching is
/// ASCII-case-insensitive (`<SCRIPT>`), an *unclosed* `<script>`/`<style>`
/// degrades to generic-tag handling (so its body leaks as text, as the
/// non-matching regex left it), an empty `<>` is literal, and a trailing
/// unterminated `<` is literal.
pub fn strip_html(html: &str) -> String {
    let bytes = html.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(n);
    let mut i = 0;
    let mut text_start = 0;

    while i < n {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        // Flush the plain-text run that ended at this `<` (ASCII byte → safe
        // char boundary).
        out.push_str(&html[text_start..i]);

        // `<script …>…</script>` / `<style …>…</style>` removed wholesale →
        // one space (the regex pipeline stripped these before generic tags, so
        // their inner markup never reaches the generic stage here either).
        if let Some(end) = strip_raw_block(bytes, i, b"script", b"</script>")
            .or_else(|| strip_raw_block(bytes, i, b"style", b"</style>"))
        {
            out.push(' ');
            i = end;
            text_start = i;
            continue;
        }

        // Generic tag `<[^>]+>` → one space. Requires at least one char between
        // the angle brackets and a closing `>`; otherwise the `<` is literal
        // text (so `<>` and a trailing `<` round-trip unchanged, as the regex,
        // which never matched them, left them).
        match find_byte(bytes, i + 1, b'>') {
            Some(gt) if gt > i + 1 => {
                out.push(' ');
                i = gt + 1;
            }
            _ => {
                out.push('<');
                i += 1;
            }
        }
        text_start = i;
    }
    out.push_str(&html[text_start..]);
    decode_entities(&out)
}

/// If `bytes[lt]` opens a `<name …>…</name>` raw block (ASCII-case-insensitive,
/// `name` lowercase), return the index just past its closing tag — mirroring the
/// regex `(?is)<name[^>]*>.*?</name>`. `None` when it isn't that block or the
/// block is unclosed (the regex would then not match, leaving generic-tag
/// handling to the caller). **Pure**, byte-indexed, zero allocation.
fn strip_raw_block(bytes: &[u8], lt: usize, open_name: &[u8], close_seq: &[u8]) -> Option<usize> {
    if !ci_starts_with(bytes.get(lt + 1..)?, open_name) {
        return None;
    }
    // First `>` after the name closes the opening tag (`[^>]*` forbids `>`).
    let open_gt = find_byte(bytes, lt + 1 + open_name.len(), b'>')?;
    // First case-insensitive `</name>` after it (non-greedy `.*?` = nearest).
    let close = ci_find_seq(bytes, open_gt + 1, close_seq)?;
    Some(close + close_seq.len())
}

/// Index of the first `target` byte at or after `from`, if any.
fn find_byte(bytes: &[u8], from: usize, target: u8) -> Option<usize> {
    bytes
        .get(from..)?
        .iter()
        .position(|&b| b == target)
        .map(|p| from + p)
}

/// `hay` begins with `needle_lower` under ASCII-case-insensitive comparison
/// (`needle_lower` must already be lowercase).
fn ci_starts_with(hay: &[u8], needle_lower: &[u8]) -> bool {
    hay.len() >= needle_lower.len()
        && hay
            .iter()
            .zip(needle_lower)
            .all(|(&h, &n)| h.to_ascii_lowercase() == n)
}

/// Index of the first ASCII-case-insensitive occurrence of `needle_lower` at or
/// after `from`, if any.
fn ci_find_seq(bytes: &[u8], from: usize, needle_lower: &[u8]) -> Option<usize> {
    if needle_lower.is_empty() {
        return None;
    }
    let last_start = bytes.len().checked_sub(needle_lower.len())?;
    (from..=last_start).find(|&i| ci_starts_with(&bytes[i..], needle_lower))
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
    fn script_and_style_matching_is_case_insensitive_and_attribute_tolerant() {
        // Uppercase tag names and an attributed opening tag are still stripped
        // wholesale (the old regex used the `(?i)` flag and `[^>]*`).
        let s = strip_html("a<SCRIPT type='x'>evil()</SCRIPT>b<Style>.q{}</STYLE>c");
        assert!(!s.contains("evil"));
        assert!(!s.contains(".q{}"));
        assert!(s.contains('a') && s.contains('b') && s.contains('c'));
    }

    #[test]
    fn unclosed_raw_block_degrades_to_generic_tag() {
        // No `</script>` anywhere: the raw-block match fails (as the regex's
        // would), so `<script>` is treated as a generic tag and its body leaks
        // as text — identical to the prior pipeline, not a silent behaviour
        // change.
        assert_eq!(strip_html("x<script>body"), "x body");
        // A near-miss element name is NOT a script/style block.
        assert_eq!(strip_html("<scrip>hi</scrip>"), " hi ");
    }

    #[test]
    fn empty_and_unterminated_angle_brackets_are_literal() {
        // `<>` has nothing between the brackets → `<[^>]+>` never matched it → literal.
        assert_eq!(strip_html("a<>b"), "a<>b");
        // A trailing unterminated `<` is literal text, not a dropped tag.
        assert_eq!(strip_html("done <"), "done <");
    }

    #[test]
    fn entities_decoded_after_tag_strip() {
        // The final decode pass still runs on the stripped text.
        assert_eq!(
            strip_html("<p>Tom &amp; Jerry &#8217;90</p>"),
            " Tom & Jerry ’90 "
        );
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

    #[test]
    fn helpers_handle_boundaries_without_panic() {
        assert_eq!(find_byte(b"abc", 1, b'c'), Some(2));
        assert_eq!(find_byte(b"abc", 9, b'a'), None);
        assert!(ci_starts_with(b"SCRIPT>", b"script"));
        assert!(!ci_starts_with(b"scrip", b"script")); // shorter than needle
        assert_eq!(ci_find_seq(b"aa</SCRIPT>bb", 0, b"</script>"), Some(2));
        assert_eq!(ci_find_seq(b"none", 0, b"</script>"), None);
    }
}
