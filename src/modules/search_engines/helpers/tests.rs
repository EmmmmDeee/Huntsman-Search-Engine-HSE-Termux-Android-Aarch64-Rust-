//! Unit tests for the search-engine helpers.
//!
//! Split out of the module file; reaches the helpers through `use super::*`.

use super::*;

#[test]
fn strip_tags_decodes_entities_in_titles_and_snippets() {
    // The exact garbled-result bug: a SERP title with entities must reach the
    // user as readable text, not raw `&amp;`/`&#39;`/`&quot;`.
    assert_eq!(
        strip_tags("<a>Smith &amp; Sons — O&#39;Brien &quot;Law&quot;</a>", 200),
        "Smith & Sons — O'Brien \"Law\"",
    );
    // Encoded `&lt;`/`&gt;` in page text become literal angle brackets, not
    // mistaken for markup and dropped.
    assert_eq!(strip_tags("uses &lt;b&gt; tags", 200), "uses <b> tags");
    // Tags are still stripped; whitespace still collapses.
    assert_eq!(strip_tags("<p>a   <b>b</b>\n c</p>", 200), "a b c");
}

#[test]
fn decode_html_entities_does_not_double_decode_escaped_entities() {
    // `&amp;lt;` is the ESCAPED form of the literal text `&lt;` — it must
    // round-trip to `&lt;`, never collapse all the way to `<`.
    assert_eq!(decode_html_entities("&amp;lt;"), "&lt;");
    assert_eq!(decode_html_entities("a&#39;b&amp;c"), "a'b&c");
    assert_eq!(decode_html_entities("plain text"), "plain text");
}

#[test]
fn decode_html_entities_handles_nbsp_and_numeric_references() {
    // The pervasive real-SERP cases: nbsp, curly quotes, dashes — decimal
    // and hex numeric references must all resolve to real characters.
    assert_eq!(
        decode_html_entities("Smith&nbsp;&amp; Sons &#8211; O&#8217;Brien"),
        "Smith & Sons – O’Brien",
    );
    assert_eq!(
        decode_html_entities("&#8220;Law&#8221;"),
        "\u{201c}Law\u{201d}"
    );
    assert_eq!(decode_html_entities("it&#x2019;s"), "it’s"); // hex
    // Malformed / unknown references are emitted verbatim, never panicking.
    assert_eq!(decode_html_entities("a & b"), "a & b"); // bare ampersand
    assert_eq!(decode_html_entities("R&D"), "R&D");
    assert_eq!(decode_html_entities("&#xZZ;"), "&#xZZ;"); // bad hex
    assert_eq!(decode_html_entities("&unknownentity;"), "&unknownentity;");
    // A multibyte char immediately after a bare '&' must not panic.
    assert_eq!(decode_html_entities("&café"), "&café");
}

#[test]
fn search_evidence_flags_truncated_snippet_and_preserves_full_length() {
    // A snippet longer than the preview cap must keep a generous preview
    // AND record that it was truncated plus the true length — so a finding
    // is verifiable and the UI never implies the snippet was complete.
    let long = "x".repeat(5000);
    let r = SearchResult {
        url: "https://example.com/page".into(),
        title: "Title".into(),
        snippet: long,
        engine: "test",
        query: "q".into(),
    };
    let ev = build_search_evidence(&r);
    assert_eq!(
        ev.attributes.get("snippet_truncated").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ev.attributes.get("snippet_full_len").map(String::as_str),
        Some("5000")
    );
    // The stored preview is capped but non-empty and the URL is preserved.
    assert!(
        ev.attributes
            .get("snippet")
            .is_some_and(|s| s.len() <= 4000)
    );
    assert_eq!(
        ev.attributes.get("url").map(String::as_str),
        Some("https://example.com/page")
    );
}

#[test]
fn search_evidence_does_not_flag_short_snippet() {
    let r = SearchResult {
        url: "https://example.com/".into(),
        title: "T".into(),
        snippet: "a short snippet".into(),
        engine: "test",
        query: "q".into(),
    };
    let ev = build_search_evidence(&r);
    assert!(!ev.attributes.contains_key("snippet_truncated"));
}

#[test]
fn extract_orgs_does_not_panic_on_non_ascii_lowercase_divergence() {
    // Regression: offsets were taken from text.to_lowercase() (not
    // length-preserving: İ U+0130 is 2 bytes, lowercases to 3) and used to
    // slice the original text → out-of-bounds / mid-codepoint str index
    // panic, fatal under panic="abort". A hostile SERP snippet must not
    // crash the scan; a normal org must still extract.
    let terms = vec!["acme".to_string(), "pty".to_string()];
    // Must not panic (İ before a company suffix is the original repro).
    let _ = extract_organisations_from_text("İ Pty Ltd", &terms);
    let _ = extract_organisations_from_text("ẞomething Inc and İ Pty Ltd", &terms);
    // Normal ASCII extraction still works.
    let got = extract_organisations_from_text("Contact ACME Pty Ltd today", &terms);
    assert!(
        got.iter().any(|o| o.contains("ACME Pty Ltd")),
        "expected ACME Pty Ltd, got {got:?}"
    );
}

#[test]
fn abn_validator_does_not_panic_on_leading_zero() {
    // Regression: an 11-digit candidate starting with '0' lifted from a
    // live search result used to overflow (0u32.wrapping_sub(1) * 10) and
    // panic the search_engines module mid-scan. Must now return false.
    assert!(!is_valid_abn("01234567890"));
    assert!(!is_valid_abn("00000000000"));
}

#[test]
fn abn_validator_accepts_known_valid() {
    // ATO worked-example ABN (also the README's `--kind abn` example).
    assert!(is_valid_abn("51824753556"));
}

#[test]
fn abn_validator_rejects_wrong_length_and_checksum() {
    assert!(!is_valid_abn("123")); // too short
    assert!(!is_valid_abn("123456789012")); // too long
    assert!(!is_valid_abn("51824753557")); // valid length, bad checksum
    assert!(!is_valid_abn("abcdefghijk")); // non-digits → <11 digits
}

#[test]
fn abn_validator_handles_all_leading_digits_without_panic() {
    // No 11-digit string should ever panic the validator, whatever the
    // leading digit — the whole point of the signed-wide accumulator.
    for first in '0'..='9' {
        let candidate = format!("{first}1824753556");
        let _ = is_valid_abn(&candidate); // must not panic
    }
}
