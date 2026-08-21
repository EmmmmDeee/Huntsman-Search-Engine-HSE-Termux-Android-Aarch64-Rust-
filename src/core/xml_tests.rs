use super::*;

#[test]
fn escapes_all_five_metacharacters() {
    assert_eq!(
        escape(r#"a&b<c>d"e'f"#),
        "a&amp;b&lt;c&gt;d&quot;e&apos;f"
    );
}

#[test]
fn escapes_the_ampersand_exactly_once() {
    // The regression a `.replace()` chain invites: substituting `<` before `&` turns `<` into
    // `&lt;` and then its `&` into `&amp;lt;`. Matching per character makes that unrepresentable,
    // so an already-escaped-looking input must survive with exactly one level of escaping.
    assert_eq!(escape("&lt;"), "&amp;lt;");
    assert_eq!(escape("&amp;"), "&amp;amp;");
}

#[test]
fn drops_xml_illegal_control_characters() {
    // XML 1.0 §2.2: the C0 controls other than tab/LF/CR are illegal in a document even as a
    // numeric reference, so they must be removed rather than escaped. This is the defect that
    // made a single poisoned entity value break an entire SVG.
    for c in ['\u{0}', '\u{1}', '\u{8}', '\u{B}', '\u{C}', '\u{E}', '\u{1F}'] {
        let out = escape(&format!("a{c}b"));
        assert_eq!(out, "ab", "{c:?} (U+{:04X}) must be dropped", c as u32);
    }
    assert_eq!(escape("a\u{FFFE}b\u{FFFF}c"), "abc");
}

#[test]
fn keeps_the_legal_whitespace_controls_and_c1() {
    // Tab, LF and CR are explicitly legal in XML 1.0, and the C1 range is legal too — dropping
    // either would silently corrupt legitimate values (a multi-line address, accented text).
    assert_eq!(escape("a\tb\nc\rd"), "a\tb\nc\rd");
    assert_eq!(escape("a\u{80}b\u{9F}c"), "a\u{80}b\u{9F}c");
    assert_eq!(escape("Ana Cañas — 東京"), "Ana Cañas — 東京");
}

#[test]
fn output_is_well_formed_when_embedded_in_an_element() {
    // The property that actually matters: whatever the input, the result can be dropped into an
    // element or a quoted attribute without producing a document a parser would reject. Asserted
    // structurally — no `<`, `>` or illegal control character survives, and quotes are escaped so
    // neither attribute flavour can be terminated early.
    let hostile = "\u{0}<script>alert('x')</script>\u{8} & \"quoted\" \u{1b}[31m";
    let out = escape(hostile);
    assert!(!out.contains('<') && !out.contains('>'));
    assert!(!out.contains('"') && !out.contains('\''));
    assert!(
        !out.chars().any(|c| (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r')),
        "no XML-illegal control character may survive: {out:?}"
    );
}

#[test]
fn empty_and_clean_values_are_unchanged() {
    assert_eq!(escape(""), "");
    assert_eq!(escape("plain-value.example"), "plain-value.example");
}
