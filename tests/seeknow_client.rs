use huntsman_recon::http::{Method, Response};
use huntsman_recon::seeknow::{
    SEARCH_LIMIT_MAX, SeekNowQueryType, SeekNowSearch, search_deep, search_fast,
};
use huntsman_recon::source_outcome::SourceOutcomeKind;

#[allow(dead_code)]
#[path = "support/seeknow_doubles.rs"]
mod seeknow_doubles;

use seeknow_doubles::{ScriptedTransport, credential, response_with};

/// A 200 response with `body`, which is what most of these tests script.
fn response(body: &str) -> Response {
    seeknow_doubles::response(200, body)
}

fn auto_search() -> SeekNowSearch {
    SeekNowSearch {
        query: "alice@example.com".into(),
        query_type: SeekNowQueryType::Auto,
        limit: SEARCH_LIMIT_MAX,
    }
}

#[test]
fn fast_auto_search_omits_type_clamps_limit_and_sends_key_only_at_transport() {
    let transport = ScriptedTransport::new(vec![response(r#"{"success":true,"data":[]}"#)]);
    let search = SeekNowSearch {
        query: "alice@example.com".into(),
        query_type: SeekNowQueryType::Auto,
        limit: SEARCH_LIMIT_MAX + 50,
    };

    let result = search_fast(&transport, &credential(), &search, 7).unwrap();
    assert_eq!(result.outcome.kind, SourceOutcomeKind::ValidZero);

    let seen = transport.seen.borrow();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert_eq!(request.method, Method::Post);
    assert_eq!(request.url, "https://see-know.ru/api/v1/search");
    assert_eq!(
        request.header_value("content-type"),
        Some("application/json")
    );
    assert_eq!(request.header_value("x-api-key"), Some("seek-test-secret"));
    assert!(!format!("{request:?}").contains("seek-test-secret"));

    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["query"], "alice@example.com");
    assert_eq!(body["limit"], SEARCH_LIMIT_MAX);
    assert!(body.get("type").is_none());
}

#[test]
fn deep_typed_search_uses_documented_path_and_type() {
    let transport = ScriptedTransport::new(vec![response(r#"{"success":true,"results":[]}"#)]);
    let search = SeekNowSearch {
        query: "alice".into(),
        query_type: SeekNowQueryType::Username,
        limit: 0,
    };

    let result = search_deep(&transport, &credential(), &search, 8).unwrap();
    assert_eq!(result.outcome.kind, SourceOutcomeKind::ValidZero);

    let seen = transport.seen.borrow();
    let request = &seen[0];
    assert_eq!(request.url, "https://see-know.ru/api/v1/stealer");
    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["type"], "username");
    assert_eq!(body["limit"], 1);
}

#[test]
fn query_types_are_rejected_before_transport_when_endpoint_does_not_support_them() {
    let fast_transport = ScriptedTransport::new(Vec::new());
    let fast = SeekNowSearch {
        query: "https://example.com/login".into(),
        query_type: SeekNowQueryType::Url,
        limit: 25,
    };
    assert!(search_fast(&fast_transport, &credential(), &fast, 9).is_err());
    assert!(fast_transport.seen.borrow().is_empty());

    let stealer_transport = ScriptedTransport::new(Vec::new());
    let name = SeekNowSearch {
        query: "Example Person".into(),
        query_type: SeekNowQueryType::Name,
        limit: 25,
    };
    assert!(search_deep(&stealer_transport, &credential(), &name, 10).is_err());
    assert!(stealer_transport.seen.borrow().is_empty());

    assert!(SeekNowQueryType::Name.supports_search());
    assert!(!SeekNowQueryType::Name.supports_stealer());
    assert!(!SeekNowQueryType::Url.supports_search());
    assert!(SeekNowQueryType::Url.supports_stealer());
    assert_eq!(SeekNowQueryType::MachineId.api_value(), Some("machine_id"));
    assert_eq!(SEARCH_LIMIT_MAX, 1000);
}

#[test]
fn provider_failures_are_classified_from_top_level_envelope_only() {
    let cases = [
        (
            200,
            r#"{"success":false,"error":"invalid_api_key","message":"bad key"}"#,
            SourceOutcomeKind::AuthRejected,
        ),
        (
            403,
            r#"{"success":false,"error":"plan_required","message":"upgrade plan"}"#,
            SourceOutcomeKind::EntitlementDenied,
        ),
        (
            429,
            r#"{"success":false,"error":"quota_exhausted","credits_remaining":0}"#,
            SourceOutcomeKind::QuotaExhausted,
        ),
        (
            429,
            r#"{"success":false,"error":"rate_limited","credits_remaining":42}"#,
            SourceOutcomeKind::RateLimited,
        ),
        // A 2xx that says `success: false` is a failed request: not a validated zero, and
        // not a success even when rows came with it.
        (
            200,
            r#"{"success":false,"error":"search backend unavailable","data":[]}"#,
            SourceOutcomeKind::Inconclusive,
        ),
        (
            200,
            r#"{"success":false,"error":"partial failure","data":[{"email":"alice@example.com"}]}"#,
            SourceOutcomeKind::Inconclusive,
        ),
    ];

    for (status, body, expected) in cases {
        // fetch reads a 429's Retry-After; refining the JSON envelope must keep it.
        let headers = if status == 429 {
            vec![("Retry-After".into(), "30".into())]
        } else {
            Vec::new()
        };
        let transport = ScriptedTransport::new(vec![response_with(status, body, headers, false)]);
        let result = search_fast(&transport, &credential(), &auto_search(), 9).unwrap();
        assert_eq!(result.outcome.kind, expected, "{body}");
        assert_eq!(result.rows.len(), 0);
        assert_eq!(
            result.outcome.retry_after_secs,
            (status == 429).then_some(30),
            "{body}"
        );
    }

    // Without `success: false` a 2xx is read as an answer, `error` string or not, and a 4xx
    // that is not a key, plan or rate refusal keeps the kind fetch gave it.
    for (status, body, expected, rows) in [
        (
            200,
            r#"{"error":"note","data":[]}"#,
            SourceOutcomeKind::ValidZero,
            0,
        ),
        (
            200,
            r#"{"error":"note","data":[{"email":"alice@example.com"}]}"#,
            SourceOutcomeKind::Success,
            1,
        ),
        (
            404,
            r#"{"success":false,"error":"not_found"}"#,
            SourceOutcomeKind::Upstream4xx,
            0,
        ),
    ] {
        let transport =
            ScriptedTransport::new(vec![response_with(status, body, Vec::new(), false)]);
        let result = search_fast(&transport, &credential(), &auto_search(), 9).unwrap();
        assert_eq!(result.outcome.kind, expected, "{body}");
        assert_eq!(result.rows.len(), rows, "{body}");
    }

    let leaked_text = r#"{
        "success":true,
        "data":[{
            "email":"alice@example.com",
            "dbname":"Example Breach",
            "note":"application logged invalid_api_key during an old incident"
        }]
    }"#;
    let transport = ScriptedTransport::new(vec![response(leaked_text)]);
    let result = search_fast(&transport, &credential(), &auto_search(), 10).unwrap();
    assert_eq!(result.outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(result.rows.len(), 1);
    assert_eq!(
        result.rows[0].fields.get("dbname"),
        Some(&"Example Breach".into())
    );
}

#[test]
fn positive_last_credit_is_kept_and_rate_headers_are_metadata() {
    let transport = ScriptedTransport::new(vec![response_with(
        200,
        r#"{"success":true,"credits_remaining":0,"data":[{"email":"alice@example.com","breach":"B1"}]}"#,
        vec![
            ("X-RateLimit-Limit".into(), "500".into()),
            ("X-RateLimit-Remaining".into(), "0".into()),
            ("X-RateLimit-Reset".into(), "12345".into()),
        ],
        false,
    )]);
    let result = search_fast(&transport, &credential(), &auto_search(), 11).unwrap();
    assert_eq!(result.outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.meta.rate_limit_limit, Some(500));
    assert_eq!(result.meta.rate_limit_remaining, Some(0));
    assert_eq!(result.meta.rate_limit_reset.as_deref(), Some("12345"));
}

#[test]
fn malformed_truncated_waf_and_upstream_failure_never_become_zero() {
    let cases = [
        (
            response_with(200, "{not-json", Vec::new(), false),
            SourceOutcomeKind::ParserDrift,
        ),
        (
            response_with(200, r#"{"success":true,"message":"ok"}"#, Vec::new(), false),
            SourceOutcomeKind::SchemaDrift,
        ),
        (
            response_with(200, r#"{"success":true,"data":[]}"#, Vec::new(), true),
            SourceOutcomeKind::ParserDrift,
        ),
        (
            response_with(
                403,
                "<html>checking your browser cloudflare</html>",
                Vec::new(),
                false,
            ),
            SourceOutcomeKind::BotWaf,
        ),
        (
            response_with(503, "unavailable", Vec::new(), false),
            SourceOutcomeKind::Upstream5xx,
        ),
    ];

    for (response, expected) in cases {
        let transport = ScriptedTransport::new(vec![response]);
        let result = search_fast(&transport, &credential(), &auto_search(), 12).unwrap();
        assert_eq!(result.outcome.kind, expected);
        assert_ne!(result.outcome.kind, SourceOutcomeKind::ValidZero);
    }
}

#[test]
fn sensitive_result_values_are_discarded_but_upstream_lineage_fields_survive() {
    let secret = "raw-password-value-that-must-never-survive";
    let body = format!(
        r#"{{"success":true,"data":[{{
            "email":"alice@example.com",
            "dbname":"Dataset A",
            "breach":"Breach A",
            "source_db":"Source DB A",
            "database_name":"Database A",
            "dataset":"Corpus A",
            "source":"provider-x",
            "record_id":"row-1",
            "password":"{secret}",
            "access_token":"tok-secret",
            "cookie":"sid=secret"
        }}]}}"#
    );
    let transport = ScriptedTransport::new(vec![response(&body)]);
    let result = search_fast(&transport, &credential(), &auto_search(), 13).unwrap();
    assert_eq!(result.outcome.kind, SourceOutcomeKind::Success);
    let row = &result.rows[0];

    for key in [
        "dbname",
        "breach",
        "source_db",
        "database_name",
        "dataset",
        "source",
        "record_id",
    ] {
        assert!(row.fields.contains_key(key), "missing {key}");
    }
    for key in ["password", "access_token", "cookie"] {
        assert!(!row.fields.contains_key(key));
        assert!(row.sensitive_fields.contains(key));
    }
    let rendered = serde_json::to_string(&result).unwrap();
    assert!(!rendered.contains(secret));
    assert!(!rendered.contains("tok-secret"));
    assert!(!rendered.contains("sid=secret"));
}

#[test]
fn variant_secret_field_names_are_dropped_without_losing_safe_evidence() {
    let body = serde_json::json!({
        "success": true,
        "data": [{
            "email": "alice@example.com",
            "source": "Dataset A",
            "record_id": "row-1",
            "api_version": "v1",
            "passwordHash": "must-not-retain-1",
            "password.hint": "must-not-retain-2",
            "accessToken": "must-not-retain-3",
            "refresh-token": "must-not-retain-4",
            "sessionCookie": "must-not-retain-5",
            "apiKey": "must-not-retain-6",
            "privateKey": "must-not-retain-7",
            "recoveryCodes": "must-not-retain-8",
            "jwt": "must-not-retain-9",
            "otp": "must-not-retain-10",
            "credentials": "must-not-retain-11"
        }]
    })
    .to_string();
    let transport = ScriptedTransport::new(vec![response(&body)]);
    let result = search_fast(&transport, &credential(), &auto_search(), 17).unwrap();
    assert_eq!(result.outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(result.rows.len(), 1);

    let row = &result.rows[0];
    for key in ["email", "source", "record_id", "api_version"] {
        assert!(row.fields.contains_key(key), "lost safe field {key}");
    }
    for key in [
        "passwordHash",
        "password.hint",
        "accessToken",
        "refresh-token",
        "sessionCookie",
        "apiKey",
        "privateKey",
        "recoveryCodes",
        "jwt",
        "otp",
        "credentials",
    ] {
        assert!(!row.fields.contains_key(key), "leaked {key}");
        assert!(row.sensitive_fields.contains(key), "unreported redaction {key}");
    }
    let serialized = serde_json::to_string(&result).unwrap();
    assert!(!serialized.contains("must-not-retain-"));
}
