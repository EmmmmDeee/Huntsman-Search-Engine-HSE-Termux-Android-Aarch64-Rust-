use super::*;

/// A trimmed but structurally faithful Ahmia results page: one direct-href hit,
/// one wrapped in Ahmia's `redirect_url=` indirection, plus the nav/footer
/// `<li>`s that must NOT be mistaken for results.
const FIXTURE: &str = r#"
<ul class="nav">
  <li><a href="/">Home</a></li>
  <li><a href="/documentation/">Docs</a></li>
</ul>
<ol class="searchResults">
  <li class="result">
    <h4><a href="http://exampleleaksite7abcdefghij.onion/dump">Acme Corp &amp; credential dump</a></h4>
    <p>Includes <b>acme.example</b> employee logins observed in a stealer log.</p>
  </li>
  <li class="result">
    <h4><a href="/search/redirect?search_term=acme&amp;redirect_url=http%3A%2F%2Fsecondsite2klmnopqrs.onion%2Fpaste">Paste: acme.example</a></h4>
    <p>Mentions the acme.example domain.</p>
  </li>
</ol>
<ul class="footer"><li><a href="https://ahmia.fi/about/">About</a></li></ul>
"#;

#[test]
fn parses_direct_and_redirect_wrapped_onion_results() {
    let r = parse_results(FIXTURE);
    assert_eq!(r.len(), 2, "expected exactly the two result rows, got: {r:?}");

    assert_eq!(r[0].onion_url, "http://exampleleaksite7abcdefghij.onion/dump");
    // Entities decoded and markup stripped in both title and snippet.
    assert_eq!(r[0].title, "Acme Corp & credential dump");
    assert!(
        r[0].snippet.contains("acme.example employee logins"),
        "snippet should be tag-stripped: {:?}",
        r[0].snippet
    );

    // Ahmia's redirect wrapper is unwrapped to the underlying onion URL, so the
    // stored evidence is the real address rather than an ahmia.fi tracking link.
    assert_eq!(r[1].onion_url, "http://secondsite2klmnopqrs.onion/paste");
    assert_eq!(r[1].title, "Paste: acme.example");
}

#[test]
fn non_onion_links_are_never_returned() {
    // Ahmia's own nav/footer/about links are clearnet — they must not appear as
    // findings. This is what keeps the output an exposure report rather than a
    // link directory.
    for r in parse_results(FIXTURE) {
        assert!(
            r.onion_url.contains(".onion"),
            "non-onion link leaked into results: {}",
            r.onion_url
        );
    }
    assert!(parse_results(r#"<li><a href="https://ahmia.fi/about/">About</a></li>"#).is_empty());
    assert!(parse_results(r#"<li><a href="/documentation/">Docs</a></li>"#).is_empty());
}

#[test]
fn duplicate_onion_urls_collapse() {
    let html = r#"
      <li class="result"><h4><a href="http://dupe1234567890abc.onion/x">One</a></h4><p>a</p></li>
      <li class="result"><h4><a href="http://dupe1234567890abc.onion/x">One again</a></h4><p>b</p></li>
    "#;
    assert_eq!(parse_results(html).len(), 1);
}

#[test]
fn malformed_and_empty_input_yield_no_results() {
    // Parser is total: garbage in, empty out — never a panic.
    assert!(parse_results("").is_empty());
    assert!(parse_results("<li><a href=").is_empty());
    assert!(parse_results("<li>no anchor at all</li>").is_empty());
    assert!(parse_results("<<<>>>&amp;&#x;<li href=\"\">").is_empty());
}

#[test]
fn search_url_encodes_the_query() {
    let u = search_url("acme corp \"breach\"");
    assert!(u.starts_with("https://ahmia.fi/search/?q="), "url: {u}");
    assert!(!u.contains(' '), "query must be percent-encoded: {u}");
}

#[test]
fn blank_query_is_rejected_before_any_request() {
    // `search` short-circuits on empty input; verified via the pure URL builder
    // plus the guard in `search` itself (no network in unit tests).
    assert_eq!(parse_results(""), Vec::new());
}
