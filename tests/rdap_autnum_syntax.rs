//! Registry numeric metadata follows the same ASN syntax as canonical queries; raw data stays intact.
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};
use huntsman_recon::rdap::{self, Answer};
use serde_json::{Value, json};

struct Registry {
    body: String,
}
impl Transport for Registry {
    fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
        let body = if request.url == "https://data.iana.org/rdap/asn.json" {
            r#"{"services":[[["13335"],["https://rdap-fixture.invalid/"]]]}"#.to_owned()
        } else {
            assert_eq!(request.url, "https://rdap-fixture.invalid/autnum/13335");
            self.body.clone()
        };
        Ok(Response {
            status: 200,
            headers: Vec::new(),
            body: body.into_bytes(),
            truncated: false,
        })
    }
}
fn record(start: Value, end: Value) -> rdap::Record {
    let mut value =
        json!({"objectClassName":"autnum","handle":"AS13335","name":"fixture registry"});
    value["startAutnum"] = start;
    value["endAutnum"] = end;
    let body = value.to_string();
    let registry = Registry { body: body.clone() };
    let Ok(Answer::Registered(record)) = rdap::lookup_asn(&registry, 13335, 1_000) else {
        panic!("the offline registry must keep its record");
    };
    assert!(
        record.raw == body,
        "the entire registry response must remain unchanged"
    );
    assert_eq!(record.handle.as_deref(), Some("AS13335"));
    *record
}
#[test]
fn malformed_prefixes_cannot_invent_an_as_range() {
    for value in [
        "SAS13335",
        "ASAS13335",
        "A13335",
        "S13335",
        "asS13335",
        "+13335",
        "AS+13335",
        "AS-13335",
        "ΑΣ13335",
    ] {
        assert!(
            record(json!(value), json!(13335)).autnums.is_none(),
            "malformed text is raw evidence, not an AS number"
        );
    }
}
#[test]
fn a_malformed_end_keeps_the_existing_single_number_fallback() {
    assert_eq!(
        record(json!(13335), json!("ASAS13399")).autnums,
        Some((13335, 13335))
    );
    assert_eq!(
        record(json!(13335), json!("AS13399")).autnums,
        Some((13335, 13399))
    );
}
#[test]
fn canonical_prefix_whitespace_has_the_query_parsers_meaning() {
    for text in ["AS 13335", " as\t13335 "] {
        assert_eq!(
            record(json!(text), Value::Null).autnums,
            Some((13335, 13335))
        );
    }
}
#[test]
fn valid_forms_types_and_u32_bounds_are_preserved() {
    for value in [
        json!(13335),
        json!("13335"),
        json!("AS13335"),
        json!("as13335"),
        json!("As13335"),
        json!("aS13335"),
        json!(" AS13335 "),
    ] {
        assert_eq!(record(value, json!(13335)).autnums, Some((13335, 13335)));
    }
    for value in [
        json!(4_294_967_296_u64),
        json!("4294967296"),
        json!("18446744073709551616"),
        json!(-1),
        json!(true),
        Value::Null,
    ] {
        assert!(record(value, Value::Null).autnums.is_none());
    }
    assert_eq!(
        record(json!(u32::MAX), Value::Null).autnums,
        Some((u32::MAX, u32::MAX))
    );
    assert_eq!(
        record(json!("AS4294967295"), Value::Null).autnums,
        Some((u32::MAX, u32::MAX))
    );
}
