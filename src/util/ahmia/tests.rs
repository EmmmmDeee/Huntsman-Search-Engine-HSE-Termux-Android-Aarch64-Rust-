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
fn redirect_url_is_cut_at_the_next_query_parameter() {
    // The original fixture put `redirect_url` LAST, so it never exercised the
    // other ordering. It turns out no manual cut is needed — `urldecode` is
    // form-urlencoded and that grammar already ends a value at `&` — but that is
    // a property of a shared helper this module does not own, so pin it here:
    // swapping `urldecode` for a naive percent-decoder would silently append
    // `&search_term=…` to every recorded onion address.
    let html = r#"<li class="result">
        <h4><a href="/search/redirect?redirect_url=http%3A%2F%2Fcutme123456789abc.onion%2Fp&amp;search_term=acme">T</a></h4>
        <p>d</p></li>"#;
    let r = parse_results(html);
    assert_eq!(r.len(), 1);
    assert_eq!(
        r[0].onion_url, "http://cutme123456789abc.onion/p",
        "the following query parameter must not be swallowed into the URL"
    );
}

#[test]
fn onion_host_is_matched_case_insensitively_and_past_a_port() {
    // Ahmia can surface an uppercase host or an explicit port. Matching the raw
    // host chain missed both and silently dropped the hit.
    let html = r#"
      <li class="result"><h4><a href="HTTP://UPPER1234567890AB.ONION/x">U</a></h4><p>d</p></li>
      <li class="result"><h4><a href="http://ported1234567890a.onion:8080/y">P</a></h4><p>d</p></li>
    "#;
    let urls: Vec<_> = parse_results(html)
        .into_iter()
        .map(|r| r.onion_url)
        .collect();
    assert_eq!(
        urls,
        vec![
            "HTTP://UPPER1234567890AB.ONION/x".to_string(),
            "http://ported1234567890a.onion:8080/y".to_string(),
        ],
        "uppercase and :port onion hosts must both be recognised"
    );
}

#[test]
fn entities_are_decoded_exactly_once() {
    // `strip_tags_plain` does not decode, so exactly ONE `decode_entities` pass
    // runs here — the round-trip property `decode_entities` documents. The
    // indexed page contains the escaped text `&amp;lt;`, which denotes the
    // literal four characters `&lt;`; decoding once yields exactly that. A
    // second pass (which `strip_html`, decoding internally, would have caused)
    // collapses it further to `<` and diverges from every other title HSE
    // decodes.
    let html = r#"<li class="result"><h4><a href="http://enttest1234567890.onion/">A &amp;lt; B</a></h4><p>x</p></li>"#;
    let r = parse_results(html);
    assert_eq!(r.len(), 1);
    assert_eq!(
        r[0].title, "A &lt; B",
        "one decode pass must leave the escaped entity intact, not collapse it to `<`"
    );
}
