use super::*;
use crate::core::{
    entity::EntityKind,
    module::ModuleResult,
    scan::{Target, TargetKind},
};
use crate::modules::abn_lookup::parse::{parse_abn_result, parse_name_results};

#[test]
fn accepts_org_and_abn() {
    let m = AbnLookup;
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "BHP")));
    assert!(m.accepts(&Target::new(TargetKind::AbnAcn, "19415776361")));
    assert!(m.accepts(&Target::new(TargetKind::FullName, "John Smith")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
}

#[test]
fn parse_abn_response() {
    let data = serde_json::json!({
        "Abn": "19415776361",
        "EntityName": "BHP GROUP LIMITED",
        "EntityTypeCode": "PUB",
        "EntityTypeName": "Australian Public Company",
        "AbnStatus": "Active",
        "AddressState": "VIC",
        "AddressPostcode": "3000",
        "Gst": "2000-07-01",
        "BusinessName": ["BHP"]
    });

    let mut result = ModuleResult::new();
    parse_abn_result(&data, "test", &mut result);

    assert!(result.entities.len() >= 3);
    let org = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("should succeed");
    assert_eq!(org.value, "BHP GROUP LIMITED");
    assert!(org.tags.contains(&"abr".to_string()));
    assert!(org.tags.contains(&"active".to_string()));

    let abn = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::AbnAcn)
        .expect("should succeed");
    assert_eq!(abn.value, "19415776361");

    let addr = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("should succeed");
    assert!(addr.value.contains("VIC"));
}

#[test]
fn parse_name_search_response() {
    let data = serde_json::json!({
        "Names": [
            {
                "Abn": "19415776361",
                "Name": "BHP GROUP LIMITED",
                "NameType": "Entity Name",
                "State": "VIC",
                "Postcode": "3000",
                "Score": 100
            },
            {
                "Abn": "49004028077",
                "Name": "BHP BILLITON LIMITED",
                "NameType": "Former Name",
                "State": "VIC",
                "Postcode": "3000",
                "Score": 85
            }
        ]
    });

    let mut result = ModuleResult::new();
    parse_name_results(&data, "BHP", "test", &mut result);

    assert!(result.entities.len() >= 4);
    let orgs: Vec<_> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
        .collect();
    assert_eq!(orgs.len(), 2);
}

#[test]
fn name_results_are_not_truncated_at_the_old_cap_of_ten() {
    // The ABR MatchingNames endpoint sets no server-side cap, so every ranked
    // candidate must survive (no-omission directive). Build 12 distinct hits.
    let entries: Vec<_> = (0..12)
        .map(|i| {
            serde_json::json!({
                "Abn": format!("1941577636{i:02}"),
                "Name": format!("CANDIDATE {i} PTY LTD"),
                "NameType": "Entity Name",
                "State": "VIC",
                "Postcode": "3000",
                "Score": 90
            })
        })
        .collect();
    let data = serde_json::json!({ "Names": entries });
    let mut result = ModuleResult::new();
    parse_name_results(&data, "CANDIDATE", "test", &mut result);
    let orgs = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
        .count();
    assert_eq!(orgs, 12, "all 12 ranked candidates must emit, not just 10");
}

#[test]
fn all_distinct_trading_names_are_emitted() {
    // A single ABN past the old take(5) cap must still surface every distinct
    // registered trading name.
    let data = serde_json::json!({
        "Abn": "19415776361",
        "EntityName": "PARENTCO PTY LTD",
        "EntityTypeCode": "PRV",
        "AbnStatus": "Active",
        "AddressState": "VIC",
        "AddressPostcode": "3000",
        "BusinessName": [
            "Trade One", "Trade Two", "Trade Three",
            "Trade Four", "Trade Five", "Trade Six", "Trade Seven"
        ]
    });
    let mut result = ModuleResult::new();
    parse_abn_result(&data, "test", &mut result);
    for n in [
        "Trade One",
        "Trade Two",
        "Trade Three",
        "Trade Four",
        "Trade Five",
        "Trade Six",
        "Trade Seven",
    ] {
        assert!(
            result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Organisation && e.value == n),
            "trading name {n:?} must be emitted"
        );
    }
}

#[test]
fn parse_empty_response() {
    let data = serde_json::json!({"Message": "No records found"});
    let mut result = ModuleResult::new();
    parse_abn_result(&data, "test", &mut result);
    assert!(result.entities.is_empty());
}

#[test]
fn jsonp_strip() {
    let raw = r#"cb({"Abn":"123"})"#;
    let json_str = raw.strip_prefix("cb(").and_then(|s| s.strip_suffix(')'));
    assert_eq!(json_str, Some(r#"{"Abn":"123"}"#));
}

#[test]
fn parse_jsonp_body_strips_wrapper_and_deserializes() {
    use super::fetch::parse_jsonp_body;
    let v = parse_jsonp_body(r#"cb({"Abn":"123","EntityName":"ACME"})"#).expect("should succeed");
    assert_eq!(v.get("Abn").and_then(|x| x.as_str()), Some("123"));
    assert_eq!(v.get("EntityName").and_then(|x| x.as_str()), Some("ACME"));
}

#[test]
fn parse_jsonp_body_returns_none_without_wrapper() {
    use super::fetch::parse_jsonp_body;
    assert!(parse_jsonp_body(r#"{"Abn":"123"}"#).is_none());
    assert!(parse_jsonp_body(r#"cb({"Abn":"123"}"#).is_none());
}

#[test]
fn parse_jsonp_body_returns_none_for_malformed_inner_json() {
    use super::fetch::parse_jsonp_body;
    assert!(parse_jsonp_body("cb(not json)").is_none());
    assert!(parse_jsonp_body(r#"cb({"Abn":})"#).is_none());
}

#[test]
fn is_invalid_guid_message_matches_the_real_live_confirmed_abr_wording() {
    use super::fetch::is_invalid_guid_message;
    // Live-confirmed 2026-07-15: a garbage GUID against the real ABR endpoint
    // returns HTTP 200 with exactly this message (every other field blank) —
    // the API never signals a bad credential via status code at all.
    assert!(is_invalid_guid_message(
        "The GUID entered is not recognised as a Registered Party"
    ));
}

#[test]
fn is_invalid_guid_message_is_case_insensitive() {
    use super::fetch::is_invalid_guid_message;
    assert!(is_invalid_guid_message("guid revoked"));
    assert!(is_invalid_guid_message("GUID REVOKED"));
    assert!(is_invalid_guid_message("Invalid Guid supplied"));
}

#[test]
fn is_invalid_guid_message_does_not_false_positive_on_a_genuine_no_match() {
    use super::fetch::is_invalid_guid_message;
    // The existing fixture used by `parse_abn_response`'s sibling "no match"
    // test elsewhere in this file — a real ABR "clean miss" message must
    // never be misread as a bad-credential signal.
    assert!(!is_invalid_guid_message("No records found"));
    assert!(!is_invalid_guid_message(""));
}

#[test]
fn split_curl_headers_extracts_retry_after_and_the_real_body() {
    use super::fetch::split_curl_headers;
    let raw = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 30\r\nContent-Type: text/plain\r\n\r\ncb({\"Abn\":\"123\"})";
    let (body, retry_after) = split_curl_headers(raw);
    assert_eq!(body, "cb({\"Abn\":\"123\"})");
    assert_eq!(retry_after.as_deref(), Some("30"));
}

#[test]
fn split_curl_headers_uses_only_the_final_hop_after_a_redirect() {
    use super::fetch::split_curl_headers;
    // -L follows redirects, so curl's -D - dump can contain multiple header
    // blocks — only the LAST one belongs to the response actually returned.
    // A Retry-After on an earlier (redirect) hop must not leak through.
    let raw = "HTTP/1.1 302 Found\r\nRetry-After: 999\r\nLocation: https://x/y\r\n\r\nHTTP/1.1 429 Too Many Requests\r\nRetry-After: 12\r\n\r\ncb({})";
    let (body, retry_after) = split_curl_headers(raw);
    assert_eq!(body, "cb({})");
    assert_eq!(
        retry_after.as_deref(),
        Some("12"),
        "must use the final hop's header, not an earlier redirect's"
    );
}

#[test]
fn split_curl_headers_returns_none_when_header_absent() {
    use super::fetch::split_curl_headers;
    let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\ncb({\"Abn\":\"123\"})";
    let (body, retry_after) = split_curl_headers(raw);
    assert_eq!(body, "cb({\"Abn\":\"123\"})");
    assert_eq!(retry_after, None);
}

#[test]
fn split_curl_headers_falls_back_to_whole_input_as_body_when_no_header_block() {
    use super::fetch::split_curl_headers;
    // Defensive fallback: if -D - somehow produced no header block at all,
    // treat the whole input as body rather than losing it.
    let (body, retry_after) = split_curl_headers("cb({\"Abn\":\"123\"})");
    assert_eq!(body, "cb({\"Abn\":\"123\"})");
    assert_eq!(retry_after, None);
}

#[test]
fn str_field_returns_nonempty_string_else_none() {
    use super::parse::str_field;
    let v = serde_json::json!({"Abn": "123", "Empty": "", "Num": 7, "Null": null});
    assert_eq!(str_field(&v, "Abn"), Some("123".to_string()));
    assert_eq!(str_field(&v, "Empty"), None);
    assert_eq!(str_field(&v, "Num"), None);
    assert_eq!(str_field(&v, "Null"), None);
    assert_eq!(str_field(&v, "Absent"), None);
}

#[test]
fn max_timeout_covers_worst_case_retry_path() {
    // Regression guard: fetch_jsonp's worst case is curl(12s tokio
    // timeout) + sleep(up to 8s max on a 429, whether from a real
    // Retry-After header or the no-header default) + curl(12s) ≈ 32s. If a
    // future edit drops the override back to the 3s default (or raises the
    // Retry-After clamp without raising this budget to match), the engine
    // kills process() before the first fetch returns and the module
    // silently yields nothing on any real network.
    let curl_timeout_ms = 10_000 + 2_000; // see curl_with_status
    let max_retry_after_sleep_ms = 8_000; // parse_retry_after_secs's max_secs in fetch_jsonp
    let worst_case = curl_timeout_ms * 2 + max_retry_after_sleep_ms;
    assert!(
        AbnLookup.max_timeout_ms() >= worst_case,
        "budget {} < worst-case retry path {worst_case}ms",
        AbnLookup.max_timeout_ms()
    );
}
