use super::{EntityKind, SourceOutcomeKind, Transport, account_name, lookup};
use crate::test_support::OneResponse;

/// A transport that must never be touched: it proves a path short-circuits before any request.
struct Never;
impl Transport for Never {
    fn send(
        &self,
        _request: &crate::http::Request,
    ) -> Result<crate::http::Response, crate::http::TransportFailure> {
        panic!("network must not be used")
    }
}

const TWO_EDITS: &str = r#"{
  "batchcomplete": true,
  "query": {
    "usercontribs": [
      {"userid": 7, "user": "Jane Citizen", "pageid": 100, "revid": 555001, "ns": 0,
       "title": "Open-source intelligence", "timestamp": "2024-03-01T12:00:00Z",
       "comment": "fixed a citation"},
      {"userid": 7, "user": "Jane Citizen", "pageid": 101, "revid": 555002, "ns": 0,
       "title": "Geolocation", "timestamp": "2024-02-14T08:30:00Z", "comment": ""}
    ]
  }
}"#;

#[test]
fn invalid_selector_is_inconclusive_without_network() {
    assert_eq!(
        lookup(&Never, "", "scan", 1).unwrap().outcome.kind,
        SourceOutcomeKind::Inconclusive
    );
    let too_long = "a".repeat(300);
    assert_eq!(
        lookup(&Never, &too_long, "scan", 1).unwrap().outcome.kind,
        SourceOutcomeKind::Inconclusive
    );
}

#[test]
fn an_empty_contributions_list_is_valid_zero() {
    let got = lookup(
        &OneResponse::json(200, r#"{"batchcomplete":true,"query":{"usercontribs":[]}}"#),
        "nobodyhere",
        "scan",
        1,
    )
    .unwrap();
    assert_eq!(got.outcome.kind, SourceOutcomeKind::ValidZero);
    assert!(got.entities.is_empty());
}

/// A name `MediaWiki` cannot read as a user can be no account, as current `MediaWiki` (`baduser`)
/// and releases before 1.35 (`baduser_ucuser`) say it.
#[test]
fn an_api_error_is_a_clean_negative() {
    for code in ["baduser", "baduser_ucuser"] {
        let body = format!(
            r#"{{"error":{{"code":"{code}","info":"Invalid value for user parameter."}}}}"#
        );
        let got = lookup(&OneResponse::json(200, &body), "bad|name", "scan", 1).unwrap();
        assert_eq!(got.outcome.kind, SourceOutcomeKind::ValidZero, "{code}");
        assert!(got.entities.is_empty());
    }
}

#[test]
fn an_unexpected_api_error_is_not_a_clean_negative() {
    let got = lookup(
        &OneResponse::json(200, r#"{"error":{"code":"readonly","info":"Maintenance"}}"#),
        "jane",
        "scan",
        1,
    )
    .unwrap();
    assert_eq!(got.outcome.kind, SourceOutcomeKind::Inconclusive);
    assert!(got.entities.is_empty());
}

#[test]
fn api_rate_limit_is_retryable_and_not_a_clean_negative() {
    let got = lookup(
        &OneResponse::json(
            200,
            r#"{"error":{"code":"ratelimited","info":"Slow down"}}"#,
        ),
        "jane",
        "scan",
        1,
    )
    .unwrap();
    assert_eq!(got.outcome.kind, SourceOutcomeKind::RateLimited);
    assert!(got.entities.is_empty());
}

#[test]
fn edits_become_tagged_revision_urls_with_a_contributions_anchor() {
    // `MediaWiki` reads `Jane_Citizen` as the account `Jane Citizen` that made these edits.
    let got = lookup(
        &OneResponse::json(200, TWO_EDITS),
        "Jane_Citizen",
        "scan",
        1,
    )
    .unwrap();
    assert_eq!(got.outcome.kind, SourceOutcomeKind::Success);

    // Each edit is the exact revision as a URL, tagged so it maps to WIKIPEDIA_PAGE_EDIT.
    let edits: Vec<_> = got
        .entities
        .iter()
        .filter(|entity| {
            entity.kind == EntityKind::Url && entity.has_tag(crate::tags::WIKIPEDIA_EDIT)
        })
        .collect();
    assert_eq!(edits.len(), 2, "{:?}", got.entities);
    assert!(
        edits
            .iter()
            .any(|entity| entity.value.contains("oldid=555001"))
    );
    assert!(
        edits
            .iter()
            .any(|entity| entity.value.contains("oldid=555002"))
    );

    // The account's contributions page anchors the edits and is not itself an edit.
    assert!(
        got.entities
            .iter()
            .any(|entity| entity.kind == EntityKind::Url
                && entity.has_tag("wikipedia")
                && !entity.has_tag(crate::tags::WIKIPEDIA_EDIT)
                && entity.value.contains("Special"))
    );
}

#[test]
fn a_log_entry_without_a_revision_is_skipped() {
    let only_a_log = r#"{"query":{"usercontribs":[
      {"user":"X","revid":0,"title":"Special:Log/move","timestamp":"2024-01-01T00:00:00Z","comment":"moved"}
    ]}}"#;
    let got = lookup(&OneResponse::json(200, only_a_log), "x", "scan", 1).unwrap();
    assert_eq!(got.outcome.kind, SourceOutcomeKind::ValidZero);
    assert!(got.entities.is_empty());
}

#[test]
fn a_missing_contributions_payload_is_not_a_clean_negative() {
    // Only query.usercontribs: [] establishes an empty successful lookup.
    // Missing query data, including a null array, is an incomplete provider
    // response and must not be interpreted as evidence of no edits.
    for body in [
        "{}",
        r#"{"batchcomplete":true}"#,
        r#"{"query":{}}"#,
        r#"{"query":{"usercontribs":null}}"#,
        r#"{"query":{"usercontribs":{}}}"#,
    ] {
        let got = lookup(&OneResponse::json(200, body), "jane", "scan", 1).unwrap();
        assert_eq!(
            got.outcome.kind,
            SourceOutcomeKind::ParserDrift,
            "incomplete Wikipedia body: {body}"
        );
        assert!(got.entities.is_empty(), "{body}");
    }
}

#[test]
fn a_wrong_typed_contributions_list_is_parser_drift_that_quotes_none_of_it() {
    let got = lookup(
        &OneResponse::json(200, r#"{"query":{"usercontribs":"secret@example.com"}}"#),
        "jane",
        "scan",
        1,
    )
    .unwrap();
    assert_eq!(got.outcome.kind, SourceOutcomeKind::ParserDrift);
    let detail = got.outcome.detail.unwrap_or_default();
    assert!(!detail.contains("secret@example.com"), "{detail}");
}

#[test]
fn a_body_that_is_not_json_is_parser_drift() {
    let got = lookup(
        &OneResponse::json(200, "not json at all"),
        "jane",
        "scan",
        1,
    )
    .unwrap();
    assert_eq!(got.outcome.kind, SourceOutcomeKind::ParserDrift);
}

#[test]
fn a_name_is_read_as_mediawiki_reads_an_account_name() {
    // Only the first letter is capitalised and underscores are spaces; every other letter keeps
    // its case, so a case-folded handle names another account.
    assert_eq!(account_name("JohnDoe"), "JohnDoe");
    assert_eq!(account_name("johnDoe"), "JohnDoe");
    assert_eq!(account_name("johndoe"), "Johndoe");
    assert_eq!(account_name("jane_citizen"), "Jane citizen");
    assert_eq!(account_name(" Jane__Citizen "), "Jane Citizen");
    assert_eq!(account_name("93.184.216.34"), "93.184.216.34");
    // An editor without an account is its address, sanitised as `MediaWiki` stores it.
    assert_eq!(account_name("093.184.216.034"), "93.184.216.34");
    assert_eq!(account_name("000.1.2.3"), "0.1.2.3");
    assert_eq!(account_name("1.2.3.256"), "1.2.3.256");
}

#[test]
fn an_address_editor_is_found_however_its_parts_are_padded() {
    let edit = r#"{"query":{"usercontribs":[
      {"user":"93.184.216.34","revid":555003,"title":"T","timestamp":"2024-01-01T00:00:00Z","comment":""}
    ]}}"#;
    let got = lookup(&OneResponse::json(200, edit), "093.184.216.34", "scan", 1).unwrap();
    assert_eq!(got.outcome.kind, SourceOutcomeKind::Success);
}

#[test]
fn edits_of_another_account_are_never_credited_to_the_queried_name() {
    // `jane_citizen` is the account `Jane citizen`; edits the API credits to `Jane Citizen` are
    // another account's, so none is reported, and the answer is no clean negative either.
    let got = lookup(
        &OneResponse::json(200, TWO_EDITS),
        "jane_citizen",
        "scan",
        1,
    )
    .unwrap();
    assert_eq!(got.outcome.kind, SourceOutcomeKind::SemanticDrift);
    assert!(got.entities.is_empty(), "{:?}", got.entities);
    let detail = got.outcome.detail.unwrap_or_default();
    assert!(!detail.contains("Jane Citizen"), "{detail}");
}
