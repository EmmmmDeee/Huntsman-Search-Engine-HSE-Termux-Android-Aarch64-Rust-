use super::*;
use crate::core::entity::EntityKind;

#[test]
fn next_js_pages_router_email_and_phone_are_extracted() {
    // Real Next.js Pages Router shape (getInlineScriptSource's documented
    // output): id first, then type, matching the framework's fixed JSX literal.
    let html = r#"<!DOCTYPE html><html><body><div id="__next"></div>
        <script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"contact":{"email":"support@example.com","phone":"+61 2 9374 4000"}}},"page":"/","query":{},"buildId":"abc123"}</script>
        </body></html>"#;
    let found = extract_hydration_entities(html);
    assert!(
        found
            .iter()
            .any(|c| c.kind == EntityKind::Email && c.value == "support@example.com"),
        "expected the embedded email, got {found:?}"
    );
}

#[test]
fn nuxt3_devalue_array_email_is_extracted() {
    // Real Nuxt 3/4 shape: `type` before `id` (opposite order to Next.js),
    // body is devalue's flattened array wire format. The walk doesn't need to
    // understand devalue's index-referencing scheme — it just needs to find
    // the string leaf regardless of which array/object slot holds it.
    let html = r#"<script type="application/json" data-nuxt-data="nuxt-app" data-ssr="true" id="__NUXT_DATA__" data-src="/_payload.json?x">[{"contact":1},{"email":"contact@example.org"},"/",1234567890]</script>"#;
    let found = extract_hydration_entities(html);
    assert!(
        found
            .iter()
            .any(|c| c.kind == EntityKind::Email && c.value == "contact@example.org"),
        "expected the embedded email, got {found:?}"
    );
}

#[test]
fn single_quoted_marker_is_recognised() {
    let html = r#"<script id='__NEXT_DATA__' type='application/json'>{"props":{"pageProps":{"email":"single@quoted.example"}}}</script>"#;
    let found = extract_hydration_entities(html);
    assert!(found.iter().any(|c| c.value == "single@quoted.example"));
}

#[test]
fn no_hydration_marker_returns_empty() {
    let html = "<html><body><h1>Just a plain static page</h1><p>contact us</p></body></html>";
    assert!(extract_hydration_entities(html).is_empty());
}

#[test]
fn truncated_json_without_closing_script_tag_returns_empty() {
    // BODY_CAP can slice a large payload mid-document, dropping the closing
    // </script> entirely — must not panic, must yield nothing.
    let html = r#"<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"email":"cut-off@ex"#;
    assert!(extract_hydration_entities(html).is_empty());
}

#[test]
fn malformed_json_returns_empty_not_panic() {
    // Closing tag present, but the captured text isn't valid JSON.
    let html = r#"<script id="__NEXT_DATA__" type="application/json">{not valid json at all}</script>"#;
    assert!(extract_hydration_entities(html).is_empty());
}

#[test]
fn empty_payload_returns_empty() {
    let html = r#"<script id="__NEXT_DATA__" type="application/json">   </script>"#;
    assert!(extract_hydration_entities(html).is_empty());
}

#[test]
fn deeply_nested_json_does_not_panic_or_hang() {
    // Build a document nested well past MAX_WALK_DEPTH. Whether serde_json's
    // own recursion guard rejects it outright, or it parses and the walk's
    // depth cap simply stops early, the only property this test needs is:
    // the call returns (doesn't panic, doesn't stack-overflow, doesn't hang).
    let depth = 100;
    let mut body = String::new();
    body.push_str(&"[".repeat(depth));
    body.push_str("\"buried-deep@example.com\"");
    body.push_str(&"]".repeat(depth));
    let html = format!(r#"<script id="__NEXT_DATA__" type="application/json">{body}</script>"#);
    // No assertion on the result's contents — completing at all is the property under test.
    let _ = extract_hydration_entities(&html);
}

#[test]
fn short_leaves_below_min_length_are_ignored() {
    // "en" (a locale code) and "/" (a bare path) are exactly the kind of
    // short, meaningless leaves a real hydration payload is full of.
    let html = r#"<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"locale":"en","path":"/"}},"page":"/"}</script>"#;
    assert!(extract_hydration_entities(html).is_empty());
}

#[test]
fn text_with_no_recognisable_shape_yields_nothing() {
    // extract() only surfaces candidates matching one of its specific
    // locator shapes (URL/email/IP/domain/digit-run/@handle) — arbitrary UI
    // copy strings embedded in the payload must not become spurious entities.
    let html = r#"<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"heading":"Welcome to our website","subtitle":"The best product on the market"}}}</script>"#;
    assert!(extract_hydration_entities(html).is_empty());
}

#[test]
fn marker_outside_a_script_tag_is_not_treated_as_hydration_data() {
    // The literal id string appearing in ordinary page text (not inside a
    // <script> opening tag) must not be mistaken for a real hydration blob —
    // whatever text happens to follow it (even if it parses as JSON) is not
    // this page's SPA state.
    let html = r#"<p>This tutorial explains the id="__NEXT_DATA__" convention.</p>
        <script>console.log("unrelated script, not a hydration payload");</script>
        {"email":"decoy@example.com"}"#;
    assert!(extract_hydration_entities(html).is_empty());
}

#[test]
fn marker_after_an_unrelated_closed_script_tag_is_not_treated_as_hydration_data() {
    // A <script> tag closes BEFORE the marker text appears later in the body
    // (e.g. in a subsequent, unrelated element) — the backward scan must
    // recognise that the nearest preceding `<script` already closed via its
    // own `>`, so it is not this marker's opening tag.
    let html = r#"<script>var x = 1;</script>
        <div data-note='mentions id="__NEXT_DATA__" in passing'>{"email":"decoy2@example.com"}</div>"#;
    assert!(extract_hydration_entities(html).is_empty());
}

#[test]
fn a_decoy_marker_mention_does_not_hide_a_real_later_hydration_script() {
    // Regression: a page can genuinely mention the marker string in passing
    // (a tutorial paragraph, doc comment, quoted example) BEFORE the
    // framework's own real hydration script appears later in the same body.
    // Anchoring on only the leftmost occurrence and giving up when it fails
    // to validate would silently miss the real, later, perfectly valid
    // script — this must fall through to the next candidate instead.
    let html = r#"<p>This tutorial explains the id="__NEXT_DATA__" convention.</p>
        <script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"email":"real@example.com"}}}</script>"#;
    let found = extract_hydration_entities(html);
    assert!(
        found.iter().any(|c| c.kind == EntityKind::Email && c.value == "real@example.com"),
        "expected the real later script's email to be found despite the earlier decoy mention, got {found:?}"
    );
}

#[test]
fn two_decoy_mentions_before_a_real_script_still_resolve_to_the_real_payload() {
    // Same regression, hardened: multiple non-script mentions of the marker
    // preceding the real tag must all be tried and skipped in turn.
    let html = r#"<p>First mention: id="__NEXT_DATA__".</p>
        <div data-note='Second mention: id="__NEXT_DATA__"'></div>
        <script id="__NEXT_DATA__" type="application/json">{"contact":"multi-decoy@example.com"}</script>"#;
    let found = extract_hydration_entities(html);
    assert!(found.iter().any(|c| c.value == "multi-decoy@example.com"), "got {found:?}");
}
