// Tests included into `types.rs` via `include!("tests.rs")`.
// `super` resolves to `types` when included from there.
use super::{Ipv6Prefix, PrefixData, PrefixResponse};

#[test]
fn deserialize_prefix_response_with_ipv6() {
    let json = r#"{
        "status": "ok",
        "data": {
            "ipv4_prefixes": [],
            "ipv6_prefixes": [
                {
                    "prefix": "2001:db8::/32",
                    "name": "EXAMPLE-NET",
                    "description": "Example network",
                    "country_code": "AU"
                }
            ]
        }
    }"#;
    let r: PrefixResponse = serde_json::from_str(json).unwrap();
    let data = r.data.unwrap();
    assert_eq!(data.ipv6_prefixes.len(), 1);
    let p = &data.ipv6_prefixes[0];
    assert_eq!(p.prefix, "2001:db8::/32");
    assert_eq!(p.name.as_deref(), Some("EXAMPLE-NET"));
    assert_eq!(p.description.as_deref(), Some("Example network"));
    assert_eq!(p.country_code.as_deref(), Some("AU"));
}

#[test]
fn deserialize_prefix_response_missing_optional_fields() {
    let json = r#"{
        "data": {
            "ipv6_prefixes": [
                {"prefix": "2001:db8:1::/48"}
            ]
        }
    }"#;
    let r: PrefixResponse = serde_json::from_str(json).unwrap();
    let p = &r.data.unwrap().ipv6_prefixes[0];
    assert_eq!(p.prefix, "2001:db8:1::/48");
    assert!(p.name.is_none());
    assert!(p.description.is_none());
    assert!(p.country_code.is_none());
}

#[test]
fn deserialize_prefix_response_empty_ipv6_list() {
    let json = r#"{"data": {"ipv6_prefixes": []}}"#;
    let r: PrefixResponse = serde_json::from_str(json).unwrap();
    assert!(r.data.unwrap().ipv6_prefixes.is_empty());
}

#[test]
fn deserialize_prefix_response_no_data() {
    let json = r#"{}"#;
    let r: PrefixResponse = serde_json::from_str(json).unwrap();
    assert!(r.data.is_none());
}

// Keep the compiler happy — these types are only used via super in mod.rs
#[allow(dead_code)]
fn _use_types(_: Ipv6Prefix, _: PrefixData) {}
