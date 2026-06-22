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

// ── resolve_href ─────────────────────────────────────────────────────────────

#[test]
fn resolve_href_returns_absolute_https_as_is() {
    assert_eq!(
        resolve_href("https://example.com/page"),
        Some("https://example.com/page".into()),
    );
}

#[test]
fn resolve_href_returns_http_as_is() {
    assert_eq!(
        resolve_href("http://example.com/"),
        Some("http://example.com/".into()),
    );
}

#[test]
fn resolve_href_upgrades_protocol_relative() {
    assert_eq!(
        resolve_href("//example.com/path"),
        Some("https://example.com/path".into()),
    );
}

#[test]
fn resolve_href_decodes_duckduckgo_redirect() {
    let href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage&rut=abc";
    assert_eq!(resolve_href(href), Some("https://example.com/page".into()),);
}

#[test]
fn resolve_href_decodes_yahoo_redirect() {
    // Yahoo path: /RU=<encoded>/RK=.../RS=...
    let href = "/RU=https%3A%2F%2Fexample.com%2F/RK=2/RS=xyz";
    assert_eq!(resolve_href(href), Some("https://example.com/".into()));
}

#[test]
fn resolve_href_returns_none_for_relative_path() {
    assert!(resolve_href("/relative/path").is_none());
    assert!(resolve_href("relative/path").is_none());
}

// ── extract_url_param ────────────────────────────────────────────────────────

#[test]
fn extract_url_param_decodes_percent_encoding() {
    let href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpath&rut=xyz";
    assert_eq!(
        extract_url_param(href, "uddg="),
        Some("https://example.com/path".into()),
    );
}

#[test]
fn extract_url_param_returns_none_when_param_absent() {
    assert!(extract_url_param("https://example.com/", "uddg=").is_none());
}

// ── HrefIter ─────────────────────────────────────────────────────────────────

#[test]
fn href_iter_yields_double_quoted_hrefs() {
    let html = r#"<a href="https://example.com">link</a>"#;
    let hrefs: Vec<&str> = HrefIter::new(html).collect();
    assert_eq!(hrefs, vec!["https://example.com"]);
}

#[test]
fn href_iter_handles_single_quoted_hrefs() {
    let html = "<a href='https://example.com/sq'>link</a>";
    let hrefs: Vec<&str> = HrefIter::new(html).collect();
    assert_eq!(hrefs, vec!["https://example.com/sq"]);
}

#[test]
fn href_iter_skips_fragment_and_special_schemes() {
    let html = "<a href=\"#\">frag</a>\
                <a href=\"javascript:void(0)\">js</a>\
                <a href=\"mailto:x@y.com\">mail</a>\
                <a href=\"tel:+1234\">tel</a>\
                <a href=\"data:text/plain,hi\">data</a>\
                <a href=\"https://example.com\">ok</a>";
    let hrefs: Vec<&str> = HrefIter::new(html).collect();
    assert_eq!(hrefs, vec!["https://example.com"]);
}

#[test]
fn href_iter_skips_empty_href() {
    let html = r#"<a href="">empty</a><a href="https://example.com">ok</a>"#;
    let hrefs: Vec<&str> = HrefIter::new(html).collect();
    assert_eq!(hrefs, vec!["https://example.com"]);
}

// ── extract_path_username ────────────────────────────────────────────────────

#[test]
fn extract_path_username_returns_first_segment() {
    assert_eq!(
        extract_path_username("https://github.com/alice"),
        Some("alice".into()),
    );
    assert_eq!(
        extract_path_username("https://github.com/alice/repo/tree/main"),
        Some("alice".into()),
    );
}

#[test]
fn extract_path_username_rejects_too_short() {
    assert!(extract_path_username("https://example.com/ab").is_none());
}

#[test]
fn extract_path_username_rejects_too_long() {
    let long = "a".repeat(41);
    assert!(extract_path_username(&format!("https://example.com/{long}")).is_none());
}

#[test]
fn extract_path_username_rejects_invalid_chars() {
    // '@' is not in the allowed set (alphanumeric, '_', '-', '.')
    assert!(extract_path_username("https://example.com/bad@char").is_none());
}

// ── extract_host ─────────────────────────────────────────────────────────────

#[test]
fn extract_host_lowercases_host() {
    assert_eq!(extract_host("https://GitHub.COM/alice"), "github.com");
    assert_eq!(extract_host("http://example.com/path?q=1"), "example.com");
}

#[test]
fn extract_host_returns_empty_for_invalid_url() {
    assert_eq!(extract_host("not-a-url"), "");
    assert_eq!(extract_host(""), "");
}

// ── is_engine_domain ─────────────────────────────────────────────────────────

#[test]
fn is_engine_domain_recognises_known_engines() {
    assert!(is_engine_domain("duckduckgo.com"));
    assert!(is_engine_domain("google.com"));
    assert!(is_engine_domain("bing.com"));
    assert!(is_engine_domain("yandex.com"));
}

#[test]
fn is_engine_domain_recognises_subdomains() {
    assert!(is_engine_domain("search.yahoo.com"));
    assert!(is_engine_domain("imgs.search.brave.com"));
}

#[test]
fn is_engine_domain_rejects_unrelated() {
    assert!(!is_engine_domain("example.com"));
    assert!(!is_engine_domain("github.com"));
}

// ── is_generic_domain ────────────────────────────────────────────────────────

#[test]
fn is_generic_domain_recognises_listed_domains() {
    assert!(is_generic_domain("zoominfo.com"));
    assert!(is_generic_domain("amazonaws.com"));
    assert!(is_generic_domain("forbes.com"));
}

#[test]
fn is_generic_domain_rejects_unlisted() {
    assert!(!is_generic_domain("example.com"));
    assert!(!is_generic_domain("github.com"));
}

// ── is_search_tooling_domain ─────────────────────────────────────────────────

#[test]
fn is_search_tooling_domain_recognises_people_search_sites() {
    assert!(is_search_tooling_domain("peekyou.com"));
    assert!(is_search_tooling_domain("spokeo.com"));
    assert!(is_search_tooling_domain("whitepages.com"));
}

#[test]
fn is_search_tooling_domain_strips_www_prefix() {
    assert!(is_search_tooling_domain("www.peekyou.com"));
}

#[test]
fn is_search_tooling_domain_rejects_unrelated() {
    assert!(!is_search_tooling_domain("example.com"));
    assert!(!is_search_tooling_domain("github.com"));
}

// ── is_tracking_url ──────────────────────────────────────────────────────────

#[test]
fn is_tracking_url_matches_known_trackers() {
    assert!(is_tracking_url("https://r.search.yahoo.com/click"));
    assert!(is_tracking_url("https://ad.doubleclick.net/click"));
    assert!(is_tracking_url("https://r.bing.com/click"));
    assert!(is_tracking_url("https://yandex.com/clck/redir"));
}

#[test]
fn is_tracking_url_rejects_normal_urls() {
    assert!(!is_tracking_url("https://example.com/page"));
    assert!(!is_tracking_url("https://github.com/alice/repo"));
}

// ── is_non_name_word ─────────────────────────────────────────────────────────

#[test]
fn is_non_name_word_blocks_common_stopwords() {
    assert!(is_non_name_word("about"));
    assert!(is_non_name_word("the"));
    assert!(is_non_name_word("search"));
    assert!(is_non_name_word("www"));
}

#[test]
fn is_non_name_word_allows_real_name_tokens() {
    assert!(!is_non_name_word("alice"));
    assert!(!is_non_name_word("bamford"));
    assert!(!is_non_name_word("corp"));
}

// ── is_navigation_path ───────────────────────────────────────────────────────

#[test]
fn is_navigation_path_matches_nav_segments() {
    assert!(is_navigation_path("about"));
    assert!(is_navigation_path("settings"));
    assert!(is_navigation_path("search-results")); // starts_with "search"
    assert!(is_navigation_path("login-page")); // contains "login"
    assert!(is_navigation_path("page.php")); // contains ".php"
}

#[test]
fn is_navigation_path_allows_username_segments() {
    assert!(!is_navigation_path("alice"));
    assert!(!is_navigation_path("haigenbamford"));
}

// ── target_terms ─────────────────────────────────────────────────────────────

#[test]
fn target_terms_uses_email_local_part() {
    let t = Target::new(TargetKind::Email, "alice.smith@example.com");
    let terms = target_terms(&t);
    assert!(terms.contains(&"alice".to_string()));
    assert!(terms.contains(&"smith".to_string()));
    assert!(
        !terms.iter().any(|s| s == "example"),
        "domain part excluded"
    );
}

#[test]
fn target_terms_filters_web_stopwords() {
    let t = Target::new(TargetKind::Username, "https");
    assert!(target_terms(&t).is_empty());
}

#[test]
fn target_terms_filters_tokens_under_3_chars() {
    let t = Target::new(TargetKind::Username, "ab-cde");
    let terms = target_terms(&t);
    assert!(!terms.iter().any(|s| s.len() < 3));
    assert!(terms.contains(&"cde".to_string()));
}

// ── is_offtarget_repo_url ────────────────────────────────────────────────────

#[test]
fn is_offtarget_repo_url_flags_unrelated_owner() {
    let terms = vec!["haigen".to_string()];
    assert!(is_offtarget_repo_url(
        "https://github.com/ExponentiAI/HAIGEN",
        &terms
    ));
}

#[test]
fn is_offtarget_repo_url_passes_when_owner_matches() {
    let terms = vec!["alice".to_string()];
    assert!(!is_offtarget_repo_url(
        "https://github.com/alice/repo",
        &terms
    ));
}

#[test]
fn is_offtarget_repo_url_returns_false_for_non_repo_host() {
    let terms = vec!["alice".to_string()];
    assert!(!is_offtarget_repo_url(
        "https://example.com/alice/page",
        &terms
    ));
}

// ── url_matches_target ───────────────────────────────────────────────────────

#[test]
fn url_matches_target_finds_term_in_path() {
    let terms = vec!["alice".to_string()];
    assert!(url_matches_target(
        "https://example.com/alice/profile",
        &terms
    ));
}

#[test]
fn url_matches_target_returns_false_for_absent_term() {
    let terms = vec!["alice".to_string()];
    assert!(!url_matches_target(
        "https://example.com/other/page",
        &terms
    ));
}

#[test]
fn url_matches_target_ignores_terms_under_4_chars() {
    let terms = vec!["abc".to_string()];
    assert!(!url_matches_target("https://example.com/abc/page", &terms));
}

// ── canonicalize_url ─────────────────────────────────────────────────────────

#[test]
fn canonicalize_url_drops_tracking_params_and_fragment() {
    let url = "https://example.com/page?utm_source=google&id=42#section";
    assert_eq!(canonicalize_url(url), "https://example.com/page?id=42");
}

#[test]
fn canonicalize_url_drops_trailing_slash() {
    assert_eq!(
        canonicalize_url("https://example.com/path/"),
        "https://example.com/path",
    );
}

#[test]
fn canonicalize_url_sorts_kept_params() {
    let url = "https://example.com/?page=2&id=42";
    assert_eq!(canonicalize_url(url), "https://example.com?id=42&page=2");
}

// ── clean_snippet ────────────────────────────────────────────────────────────

#[test]
fn clean_snippet_collapses_escape_sequences_and_spaces() {
    assert_eq!(clean_snippet("hello\\nworld"), "hello world");
    assert_eq!(clean_snippet("tab\\there"), "tab here");
    assert_eq!(clean_snippet("a  b   c"), "a b c");
}

#[test]
fn clean_snippet_removes_bing_serp_artifact() {
    let s = r#"text h="ID=SERP,1234.5" more"#;
    let result = clean_snippet(s);
    assert!(
        !result.contains("ID=SERP"),
        "artifact not removed: {result}"
    );
    assert!(
        result.contains("text"),
        "surrounding text must be preserved: {result}"
    );
}

// ── bigram_similarity ────────────────────────────────────────────────────────

#[test]
fn bigram_similarity_identical_strings_score_one() {
    assert!((bigram_similarity("alice", "alice") - 1.0).abs() < 1e-9);
}

#[test]
fn bigram_similarity_disjoint_strings_score_zero() {
    assert_eq!(bigram_similarity("abc", "xyz"), 0.0);
}

#[test]
fn bigram_similarity_is_case_insensitive() {
    assert!((bigram_similarity("Alice", "alice") - 1.0).abs() < 1e-9);
}

#[test]
fn bigram_similarity_is_symmetric() {
    let ab = bigram_similarity("hello", "world");
    let ba = bigram_similarity("world", "hello");
    assert!((ab - ba).abs() < 1e-9);
}

#[test]
fn bigram_similarity_repetitive_strings_stay_in_bounds() {
    let score = bigram_similarity("aaaa", "aaa");
    assert!((0.0..=1.0).contains(&score), "score out of [0,1]: {score}");
}

#[test]
fn bigram_similarity_empty_input_gives_zero() {
    assert_eq!(bigram_similarity("", "abc"), 0.0);
    assert_eq!(bigram_similarity("abc", ""), 0.0);
}

// `is_email_local_char` / `is_domain_char` were removed when email mining moved
// to `util::extract::page_emails`; the byte predicates (`is_email_local_byte` /
// `is_domain_byte`) now live there and are exercised via its `page_emails` tests.

// ── extract_key_phrase ───────────────────────────────────────────────────────

#[test]
fn extract_key_phrase_returns_best_matching_clause() {
    let snippet = "This is unrelated. Alice Smith works at Acme Corp.";
    let result = extract_key_phrase(snippet, "alice smith");
    assert!(
        result.contains("Alice Smith"),
        "expected matching clause, got: {result}"
    );
}

#[test]
fn extract_key_phrase_returns_empty_for_short_snippet() {
    assert_eq!(extract_key_phrase("short", "query"), "");
}

#[test]
fn extract_key_phrase_returns_empty_when_no_terms_match() {
    let snippet = "The quick brown fox jumps over the lazy dog. Another sentence here too.";
    let result = extract_key_phrase(snippet, "alice smith");
    assert!(result.is_empty(), "expected no match, got: {result}");
}

// ── dedup_results ────────────────────────────────────────────────────────────

#[test]
fn dedup_results_collapses_urls_that_canonicalize_equal() {
    // Build three results: the first two canonicalize to the SAME key
    // (tracking param stripped / fragment dropped) and the third is distinct.
    let mk = |url: &str| SearchResult {
        url: url.into(),
        title: "T".into(),
        snippet: "s".into(),
        engine: "test",
        query: "q".into(),
    };
    let results = vec![
        mk("https://example.com/page?utm_source=google"), // → example.com/page
        mk("https://example.com/page#section"),           // → example.com/page (dup)
        mk("https://other.com/profile"),                  // distinct
    ];
    let deduped = dedup_results(results);
    // Two survive; the first occurrence of the duplicate key is kept, order preserved.
    assert_eq!(deduped.len(), 2);
    assert_eq!(deduped[0].url, "https://example.com/page?utm_source=google");
    assert_eq!(deduped[1].url, "https://other.com/profile");
}

#[test]
fn dedup_results_keeps_distinct_content_params() {
    // Content params (`v`, `id`) are KEPT by canonicalize_url, so these
    // distinct pages must not collapse.
    let mk = |url: &str| SearchResult {
        url: url.into(),
        title: "T".into(),
        snippet: "s".into(),
        engine: "test",
        query: "q".into(),
    };
    let results = vec![
        mk("https://youtube.com/watch?v=A"),
        mk("https://youtube.com/watch?v=B"),
    ];
    assert_eq!(dedup_results(results).len(), 2);
}

// ── extract_surrounding_text ─────────────────────────────────────────────────

#[test]
fn extract_surrounding_text_returns_window_around_anchor() {
    // Anchor present: tags stripped, whitespace collapsed, full window kept.
    assert_eq!(
        extract_surrounding_text("<p>hello ANCHOR world</p>", "ANCHOR", 200),
        "hello ANCHOR world",
    );
}

#[test]
fn extract_surrounding_text_bounds_by_max_len() {
    // max_len caps the returned text (ASCII → one byte per kept char).
    let out = extract_surrounding_text("<p>hello ANCHOR world</p>", "ANCHOR", 5);
    assert!(out.len() <= 5, "expected ≤5 chars, got {out:?}");
    assert_eq!(out, "hello");
}

#[test]
fn extract_surrounding_text_returns_empty_when_anchor_absent() {
    assert_eq!(
        extract_surrounding_text("<p>no marker here</p>", "ANCHOR", 200),
        "",
    );
}

// ── extract_snippet_near ─────────────────────────────────────────────────────

#[test]
fn extract_snippet_near_returns_text_after_anchor() {
    // Returns the cleaned text FOLLOWING the anchor (not the preceding text).
    assert_eq!(
        extract_snippet_near("<p>before ANCHOR tail content</p>", "ANCHOR", 200),
        "tail content",
    );
}

#[test]
fn extract_snippet_near_bounds_by_max_len() {
    let out = extract_snippet_near("<p>before ANCHOR tail content</p>", "ANCHOR", 4);
    assert!(out.len() <= 4, "expected ≤4 chars, got {out:?}");
    assert_eq!(out, "tail");
}

#[test]
fn extract_snippet_near_returns_empty_when_anchor_absent() {
    assert_eq!(
        extract_snippet_near("<p>no marker here</p>", "ANCHOR", 200),
        "",
    );
}
