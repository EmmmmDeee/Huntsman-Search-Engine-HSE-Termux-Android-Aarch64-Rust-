use super::types::PrefixResp;

#[test]
fn deserializes_prefix_response() {
    let json = r#"{
        "status": "ok",
        "data": {
            "ipv4_prefixes": [],
            "ipv6_prefixes": [
                { "prefix": "2001:db8::/32", "name": "TEST", "description": "Test prefix", "country_code": "AU" }
            ]
        }
    }"#;
    let resp: PrefixResp = serde_json::from_str(json).unwrap();
    assert_eq!(resp.status.as_deref(), Some("ok"));
    let data = resp.data.unwrap();
    assert_eq!(data.ipv6_prefixes.len(), 1);
    assert_eq!(data.ipv6_prefixes[0].prefix, "2001:db8::/32");
    assert_eq!(data.ipv6_prefixes[0].country_code.as_deref(), Some("AU"));
}

#[test]
fn handles_empty_ipv6_prefixes() {
    let json = r#"{"status":"ok","data":{"ipv4_prefixes":[],"ipv6_prefixes":[]}}"#;
    let resp: PrefixResp = serde_json::from_str(json).unwrap();
    assert!(resp.data.unwrap().ipv6_prefixes.is_empty());
}
