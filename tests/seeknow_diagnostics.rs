use huntsman_recon::http::{Method, Response};
use huntsman_recon::seeknow::{
    MAX_FIELD_CHARS, MAX_FIELDS_PER_ROW, SEARCH_LIMIT_MAX, SeekNowQueryType, SeekNowSearch,
    credits, search_fast, status,
};
use huntsman_recon::source_outcome::SourceOutcomeKind;

#[allow(dead_code)]
#[path = "support/seeknow_doubles.rs"]
mod seeknow_doubles;

use seeknow_doubles::{ScriptedTransport, credential};

/// A 200 response with `body`, which is what these tests script.
fn response(body: &str) -> Response {
    seeknow_doubles::response(200, body)
}

#[test]
fn credits_and_status_are_authenticated_zero_redirect_gets() {
    let transport = ScriptedTransport::new(vec![
        response(r#"{"success":true,"credits_remaining":123,"daily_limit":500}"#),
        response(r#"{"success":true,"status":"ok","version":"v1"}"#),
    ]);
    let credential = credential();

    let credits_result = credits(&transport, &credential, 10).unwrap();
    assert_eq!(credits_result.outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(credits_result.remaining, Some(123));
    assert_eq!(credits_result.limit, Some(500));

    let status_result = status(&transport, &credential, 11).unwrap();
    assert_eq!(status_result.outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(
        status_result.fields.get("status").map(String::as_str),
        Some("ok")
    );

    let seen = transport.seen.borrow();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].method, Method::Get);
    assert_eq!(seen[0].url, "https://see-know.ru/api/v1/credits");
    assert_eq!(seen[1].method, Method::Get);
    assert_eq!(seen[1].url, "https://see-know.ru/api/v1/status");
    assert_eq!(seen[0].header_value("x-api-key"), Some("seek-test-secret"));
    assert_eq!(seen[1].header_value("x-api-key"), Some("seek-test-secret"));
}

#[test]
fn a_2xx_success_false_envelope_is_never_a_successful_diagnostic() {
    let transport = ScriptedTransport::new(vec![
        response(r#"{"success":false,"error":"maintenance","credits_remaining":5}"#),
        response(r#"{"success":false,"error":"maintenance"}"#),
    ]);
    let credential = credential();

    let credits_result = credits(&transport, &credential, 14).unwrap();
    assert_eq!(credits_result.outcome.kind, SourceOutcomeKind::Inconclusive);
    assert_eq!(credits_result.outcome.http_status, Some(200));
    assert_eq!(credits_result.remaining, None);

    let status_result = status(&transport, &credential, 15).unwrap();
    assert_eq!(status_result.outcome.kind, SourceOutcomeKind::Inconclusive);
    assert_eq!(
        status_result.outcome.detail.as_deref(),
        Some("provider reported request failure")
    );
    assert!(status_result.fields.is_empty());
}

#[test]
fn upstream_arrays_survive_as_multiple_values_for_lineage() {
    let transport = ScriptedTransport::new(vec![response(
        r#"{"success":true,"data":[{"email":"a@example.com","dbname":["Dataset A","Dataset B"],"source":["mirror-1","mirror-2"],"record_id":"r1"}]}"#,
    )]);
    let result = search_fast(
        &transport,
        &credential(),
        &SeekNowSearch {
            query: "a@example.com".into(),
            query_type: SeekNowQueryType::Email,
            limit: SEARCH_LIMIT_MAX,
        },
        12,
    )
    .unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(
        result.rows[0].upstream.dbname,
        vec!["Dataset A".to_owned(), "Dataset B".to_owned()]
    );
    assert_eq!(
        result.rows[0].upstream.source,
        vec!["mirror-1".to_owned(), "mirror-2".to_owned()]
    );
    assert_eq!(result.rows[0].upstream.record_id.as_deref(), Some("r1"));
}

#[test]
fn rows_fields_and_strings_are_bounded_with_visible_truncation() {
    let huge = "x".repeat(MAX_FIELD_CHARS + 100);
    let mut row = serde_json::Map::new();
    row.insert(
        "email".into(),
        serde_json::Value::String("a@example.com".into()),
    );
    row.insert("bio".into(), serde_json::Value::String(huge));
    for i in 0..(MAX_FIELDS_PER_ROW + 20) {
        row.insert(
            format!("field_{i}"),
            serde_json::Value::String(format!("v{i}")),
        );
    }
    let rows = (0..(SEARCH_LIMIT_MAX as usize + 5))
        .map(|_| serde_json::Value::Object(row.clone()))
        .collect::<Vec<_>>();
    let body = serde_json::json!({"success": true, "data": rows}).to_string();
    let transport = ScriptedTransport::new(vec![response(&body)]);
    let result = search_fast(
        &transport,
        &credential(),
        &SeekNowSearch {
            query: "a@example.com".into(),
            query_type: SeekNowQueryType::Email,
            limit: SEARCH_LIMIT_MAX,
        },
        13,
    )
    .unwrap();

    assert_eq!(result.rows.len(), SEARCH_LIMIT_MAX as usize);
    assert!(result.meta.normalized_rows_truncated);
    assert!(result.rows[0].fields.len() <= MAX_FIELDS_PER_ROW);
    assert!(result.rows[0].truncated_fields.contains("bio"));
    assert!(!result.rows[0].fields.contains_key("bio"));
    assert!(result.rows[0].fields_truncated);
}

#[test]
fn upstream_arrays_are_bounded_with_visible_truncation() {
    let names = (0..=MAX_FIELDS_PER_ROW)
        .map(|i| format!("Dataset {i}"))
        .collect::<Vec<_>>();
    let huge = "x".repeat(MAX_FIELD_CHARS + 1);
    let edge = "y".repeat(MAX_FIELD_CHARS);
    let body = serde_json::json!({"success": true, "data": [
        {"email": "a@example.com", "dbname": names},
        {"email": "b@example.com", "source": ["mirror-1", huge]},
        // A null element is dropped by type, not by a bound.
        {"email": "c@example.com", "dbname": ["Dataset A", null]},
        // An element exactly at the bound is kept.
        {"email": "d@example.com", "dbname": [edge]},
        // A dropped scalar and a cut array both mark the row; neither unmarks it.
        {"email": "e@example.com", "bio": huge, "dbname": names},
    ]})
    .to_string();
    let transport = ScriptedTransport::new(vec![response(&body)]);
    let result = search_fast(
        &transport,
        &credential(),
        &SeekNowSearch {
            query: "a@example.com".into(),
            query_type: SeekNowQueryType::Email,
            limit: SEARCH_LIMIT_MAX,
        },
        16,
    )
    .unwrap();

    assert_eq!(result.rows.len(), 5);
    assert_eq!(
        result.rows[0].upstream.dbname,
        names[..MAX_FIELDS_PER_ROW].to_vec()
    );
    assert!(result.rows[0].fields_truncated);
    assert_eq!(result.rows[1].upstream.source, vec!["mirror-1".to_owned()]);
    assert!(result.rows[1].fields_truncated);
    assert_eq!(result.rows[2].upstream.dbname, vec!["Dataset A".to_owned()]);
    assert!(!result.rows[2].fields_truncated);
    assert_eq!(result.rows[3].upstream.dbname, vec![edge]);
    assert!(!result.rows[3].fields_truncated);
    assert_eq!(result.rows[4].upstream.dbname.len(), MAX_FIELDS_PER_ROW);
    assert!(result.rows[4].fields_truncated);
}
