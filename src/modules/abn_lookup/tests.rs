use super::*;
use crate::core::{entity::EntityKind, module::ModuleResult, scan::{Target, TargetKind}};
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
        .unwrap();
    assert_eq!(org.value, "BHP GROUP LIMITED");
    assert!(org.tags.contains(&"abr".to_string()));
    assert!(org.tags.contains(&"active".to_string()));

    let abn = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::AbnAcn)
        .unwrap();
    assert_eq!(abn.value, "19415776361");

    let addr = result
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .unwrap();
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
fn max_timeout_covers_worst_case_retry_path() {
    // Regression guard: fetch_jsonp's worst case is curl(12s tokio
    // timeout) + sleep(5s on 429) + curl(12s) ≈ 29s. If a future edit
    // drops the override back to the 3s default, the engine kills
    // process() before the first fetch returns and the module silently
    // yields nothing on any real network.
    let curl_timeout_ms = 10_000 + 2_000; // see curl_with_status
    let sleep_ms = 5_000; // 429 backoff in fetch_jsonp
    let worst_case = curl_timeout_ms * 2 + sleep_ms;
    assert!(
        AbnLookup.max_timeout_ms() >= worst_case,
        "budget {} < worst-case retry path {worst_case}ms",
        AbnLookup.max_timeout_ms()
    );
}
