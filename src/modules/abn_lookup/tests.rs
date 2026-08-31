use super::*;
use crate::core::{
    confidence,
    entity::EntityKind,
    module::ModuleResult,
    scan::{Target, TargetKind},
};
use crate::modules::abn_lookup::parse::{parse_abn_result, parse_name_results};

/// Regression: an unedited `hse provision` template writes the literal
/// placeholder string into `~/.huntsman.env` uncommented, and this module
/// used to read it via bare `ctx.key_opt` — bypassing `resolve_key`'s
/// blank/placeholder filter — so it would have forwarded
/// `"insert_abr_guid_here"` to the live ABR API as a credential instead of
/// cleanly skipping. Must behave identically to a missing key.
#[tokio::test]
async fn placeholder_key_is_a_clean_skip_not_a_forwarded_credential() {
    let m = AbnLookup;
    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let mut keys = std::collections::HashMap::new();
    keys.insert(KEY_ENV.to_string(), "insert_abr_guid_here".to_string());
    let ctx = ModuleContext {
        scan_id: "scan".into(),
        bus,
        http: reqwest::Client::new(),
        keys,
        cancel: crate::core::cancel::CancelHandle::new(),
    };
    let target = Target::new(TargetKind::AbnAcn, "19415776361");
    let result = m.process(&target, &ctx).await.expect("must not error");
    assert!(
        result.entities.is_empty(),
        "an unedited template placeholder must be treated as no key configured"
    );
}

/// Regression (silent-failure-swallow audit): a TOTAL transport failure of the
/// module's SOLE ABR source must surface as an `Err`, not collapse into the
/// `Ok(None)` "no record" answer. Previously `fetch_jsonp`'s two
/// `None => return Ok(None)` arms mapped a curl spawn error / connection
/// failure / timeout (no HTTP status ever returned) to the same value as a
/// genuine miss, so a dead ABR endpoint showed the operator a false "no ABN
/// found". This asserts the fixed contract — matching the sibling AU scrapers
/// (au_seifa/au_geo/asic_*) and this function's own 429-after-retry error path.
///
/// A closed loopback port makes curl's connect fail fast and deterministically;
/// if `curl` is unavailable in the test environment the spawn fails, which is
/// the same transport-failure class and yields the same `Err`.
#[tokio::test]
async fn transport_failure_surfaces_as_error_not_a_false_no_match() {
    // Bind then immediately drop a loopback socket to obtain a port with no
    // listener behind it.
    let dead_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let url =
        format!("http://127.0.0.1:{dead_port}/AbnDetails.aspx?abn=19415776361&callback=cb&guid=x");

    let (bus, _rx) = tokio::sync::broadcast::channel(1);
    let ctx = ModuleContext {
        scan_id: "scan".into(),
        bus,
        http: reqwest::Client::new(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    };

    let result = super::fetch::fetch_jsonp(&ctx, "x", &url).await;
    assert!(
        result.is_err(),
        "a total transport failure of the sole ABR source must be Err, not Ok(None): got {result:?}"
    );
}

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

    // Regression: `NameType: "Former Name"` was captured into evidence but
    // never changed the entity's tags or confidence — a former legal name
    // read identically to the entity's current one.
    let current = orgs
        .iter()
        .find(|e| e.value == "BHP GROUP LIMITED")
        .expect("current name entity");
    assert!(!current.has_tag("former-name"));
    let former = orgs
        .iter()
        .find(|e| e.value == "BHP BILLITON LIMITED")
        .expect("former name entity");
    assert!(former.has_tag("former-name"));
    assert!(
        former.confidence < confidence::HIGH_PLUSPLUS,
        "a former name must rank below its un-demoted score-90 tier: {}",
        former.confidence
    );
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
fn a_cancelled_abn_demotes_every_derived_entity_not_just_the_organisation() {
    // Regression: `AbnStatus: "Cancelled"` demoted only the Organisation
    // entity's confidence — the registered Address, its derived Coordinates,
    // every trading BusinessName, and the sole-trader Person all still
    // emitted at their full, undemoted confidence from the same stale
    // record, with no `status`/`inactive` signal on any of them.
    let data = serde_json::json!({
        "Abn": "19415776361",
        "EntityName": "Jane Citizen",
        "EntityTypeCode": "IND",
        "AbnStatus": "Cancelled",
        "AddressState": "VIC",
        "AddressPostcode": "3000",
        "BusinessName": ["Jane's Cakes"]
    });
    let mut result = ModuleResult::new();
    parse_abn_result(&data, "test", &mut result);

    let org = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.value == "Jane Citizen")
        .expect("organisation");
    assert!(org.has_tag("inactive"));
    assert!(
        org.confidence < confidence::VERY_HIGH_PLUS,
        "organisation must already be demoted: {}",
        org.confidence
    );

    let addr = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("address");
    assert!(
        addr.has_tag("inactive"),
        "a stale record's address is not confirmed current"
    );
    assert!(
        addr.confidence < confidence::VERY_HIGH,
        "address must be demoted like the organisation: {}",
        addr.confidence
    );
    assert_eq!(
        addr.evidence[0]
            .attributes
            .get("business_status")
            .map(String::as_str),
        Some("Cancelled")
    );

    let trading_name = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Organisation && e.value == "Jane's Cakes")
        .expect("trading name");
    assert!(trading_name.has_tag("inactive"));
    assert!(trading_name.confidence < confidence::HIGH_PLUSPLUS);

    let person = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("sole-trader person");
    assert!(person.has_tag("inactive"));
    assert!(person.confidence < confidence::HIGH_PLUSPLUS);

    if let Some(coords) = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Coordinates)
    {
        assert!(coords.has_tag("inactive"));
        assert!(coords.confidence < confidence::HIGH);
    }
}

#[test]
fn an_active_abn_does_not_demote_or_tag_inactive_on_any_entity() {
    // Counter-case: an active ABN's derived entities must NOT carry the
    // `inactive` tag or a demoted confidence — the fix must not over-fire.
    let data = serde_json::json!({
        "Abn": "19415776361",
        "EntityName": "Jane Citizen",
        "EntityTypeCode": "IND",
        "AbnStatus": "Active",
        "AddressState": "VIC",
        "AddressPostcode": "3000",
        "BusinessName": ["Jane's Cakes"]
    });
    let mut result = ModuleResult::new();
    parse_abn_result(&data, "test", &mut result);
    assert!(
        result.entities.iter().all(|e| !e.has_tag("inactive")),
        "an active record must not tag anything inactive: {:?}",
        result.entities
    );
}

#[test]
fn a_status_of_literally_inactive_is_not_misread_as_active() {
    // Regression: `is_inactive` used to be `!status.to_lowercase().contains("active")`
    // — a raw substring check, and "inactive" contains "active" as a substring
    // (i-n-ACTIVE), so `AbnStatus: "Inactive"` inverted to `is_inactive == false`
    // (and, on the old `else if status.to_lowercase().contains("active")` arm,
    // even picked up the `active` tag) — the exact opposite of correct.
    let data = serde_json::json!({
        "Abn": "19415776361",
        "EntityName": "Jane Citizen",
        "EntityTypeCode": "IND",
        "AbnStatus": "Inactive",
        "AddressState": "VIC",
        "AddressPostcode": "3000"
    });
    let mut result = ModuleResult::new();
    parse_abn_result(&data, "test", &mut result);

    let org = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("organisation");
    assert!(
        org.has_tag("inactive"),
        "a status of \"Inactive\" must be recognised as inactive: {org:?}"
    );
    assert!(
        !org.has_tag("active"),
        "a status of \"Inactive\" must never be tagged active: {org:?}"
    );
    assert!(org.confidence < confidence::VERY_HIGH_PLUS);
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
