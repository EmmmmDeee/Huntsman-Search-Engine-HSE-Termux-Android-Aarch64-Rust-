use super::MwError;
use serde::Deserialize;

/// A stand-in for a real caller's response struct: a payload array plus the
/// shared error envelope. Mirrors how `wiki_geosearch::GeoResp` /
/// `wikidata::SearchResp` embed `error`.
#[derive(Deserialize, Default)]
struct Resp {
    #[serde(default)]
    items: Vec<String>,
    #[serde(default)]
    error: Option<MwError>,
}

#[test]
fn a_present_error_envelope_is_a_hard_error_naming_the_module() {
    // MediaWiki's HTTP-200 error envelope must NOT read as "no items". It
    // deserialises into `error`, and `check` turns it into a module-named Err.
    let body = r#"{"error":{"code":"maxlag","info":"Waiting for a database server"}}"#;
    let resp: Resp = serde_json::from_str(body).expect("envelope deserialises");
    assert!(resp.items.is_empty(), "the error envelope carries no items");
    let err = MwError::check(&resp.error, "test_mod")
        .expect_err("a present error envelope must be a hard error");
    let msg = err.to_string();
    assert!(msg.contains("test_mod"), "error names the module: {msg}");
    assert!(msg.contains("maxlag"), "error carries the API code: {msg}");
    assert!(
        msg.contains("Waiting for a database server"),
        "error carries the API info: {msg}"
    );
}

#[test]
fn a_normal_response_has_no_error_and_passes_the_check() {
    let body = r#"{"items":["a","b"]}"#;
    let resp: Resp = serde_json::from_str(body).expect("deserialises");
    assert_eq!(resp.items.len(), 2);
    assert!(
        MwError::check(&resp.error, "test_mod").is_ok(),
        "a response with no error envelope passes the check"
    );
}

#[test]
fn an_empty_result_with_no_error_is_a_genuine_negative() {
    // The legitimate "found nothing" case: 200, no error, empty payload. This
    // must stay a clean pass — the guard only fires on an actual error envelope.
    let body = r#"{"items":[]}"#;
    let resp: Resp = serde_json::from_str(body).expect("deserialises");
    assert!(resp.items.is_empty());
    assert!(
        MwError::check(&resp.error, "test_mod").is_ok(),
        "a genuine empty result is not an error"
    );
}
