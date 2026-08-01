use super::*;

// ── Deserialisation ─────────────────────────────────────────────────
#[test]
fn deserialize_net_response() {
    // A representative (trimmed) PeeringDB `net` payload.
    let json = r#"{"data":[{
        "asn":13335,
        "name":"Cloudflare, Inc.",
        "aka":"Cloudflare",
        "website":"https://www.cloudflare.com",
        "irr_as_set":"AS-CLOUDFLARE",
        "info_type":"Content",
        "info_scope":"Global",
        "policy_general":"Open",
        "info_prefixes4":1000,
        "info_prefixes6":100
    }]}"#;
    let r: NetResponse = serde_json::from_str(json).expect("should parse");
    assert_eq!(r.data.len(), 1);
    assert_eq!(r.data[0].name.as_deref(), Some("Cloudflare, Inc."));
    assert_eq!(r.data[0].info_prefixes4, Some(1000));
}

#[test]
fn deserialize_sparse_and_empty_responses() {
    // Unknown ASN → empty data array (PeeringDB's clean "not found").
    let empty: NetResponse = serde_json::from_str(r#"{"data":[]}"#).expect("empty parses");
    assert!(empty.data.is_empty());
    // A sparse row (only asn+name) must still deserialise — every other field
    // is optional.
    let sparse: NetResponse =
        serde_json::from_str(r#"{"data":[{"asn":64500,"name":"Tiny Net"}]}"#).expect("sparse parses");
    assert_eq!(sparse.data[0].website, None);
    assert_eq!(sparse.data[0].info_prefixes4, None);
}

#[tokio::test]
async fn module_metadata() {
    let m = PeeringDb;
    assert_eq!(m.name(), "peeringdb");
    assert!(!m.description().trim().is_empty());
    assert!(m.accepts(&Target::new(TargetKind::Asn, "AS13335")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
}

// ── Response → entity mapping ────────────────────────────────────────
#[test]
fn net_entities_map_operator_and_website() {
    let net: Net = serde_json::from_str(
        r#"{
            "asn":13335,
            "name":"Cloudflare, Inc.",
            "aka":"Cloudflare",
            "website":"https://www.cloudflare.com",
            "irr_as_set":"AS-CLOUDFLARE",
            "info_type":"Content",
            "info_scope":"Global",
            "policy_general":"Open",
            "info_prefixes4":1500,
            "info_prefixes6":200
        }"#,
    )
    .expect("parses");
    let es = net_entities(&net, 13335, "s");

    let org = es
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("organisation emitted");
    assert!(org.has_tag("peeringdb") && org.has_tag("network-operator"));
    assert!(!org.value.is_empty());
    let ev = &org.evidence[0];
    assert_eq!(ev.attributes.get("asn").map(String::as_str), Some("13335"));
    assert_eq!(
        ev.attributes.get("irr_as_set").map(String::as_str),
        Some("AS-CLOUDFLARE")
    );
    assert_eq!(
        ev.attributes.get("network_type").map(String::as_str),
        Some("Content")
    );
    assert_eq!(
        ev.attributes.get("peering_policy").map(String::as_str),
        Some("Open")
    );
    assert_eq!(
        ev.attributes.get("announced_prefixes_v4").map(String::as_str),
        Some("1500")
    );

    let url = es
        .iter()
        .find(|e| e.kind == EntityKind::Url)
        .expect("website emitted as Url");
    assert!(url.has_tag("operator-website"));
}

#[test]
fn net_entities_without_name_emits_only_website() {
    let net: Net = serde_json::from_str(
        r#"{"asn":64500,"website":"https://example.net"}"#,
    )
    .expect("parses");
    let es = net_entities(&net, 64500, "s");
    assert!(
        es.iter().all(|e| e.kind == EntityKind::Url),
        "no name ⇒ no Organisation entity"
    );
    assert_eq!(es.len(), 1);
}

#[test]
fn net_entities_without_website_emits_only_org() {
    let net: Net = serde_json::from_str(r#"{"asn":64500,"name":"Nameonly Net"}"#).expect("parses");
    let es = net_entities(&net, 64500, "s");
    assert_eq!(es.len(), 1);
    assert_eq!(es[0].kind, EntityKind::Organisation);
}

#[test]
fn net_entities_ignore_non_http_website() {
    // A non-http(s) website value must not become a Url entity, but the
    // organisation is still emitted.
    let net: Net =
        serde_json::from_str(r#"{"asn":64500,"name":"FTP Co","website":"ftp://legacy.example"}"#)
            .expect("parses");
    let es = net_entities(&net, 64500, "s");
    assert_eq!(es.len(), 1);
    assert_eq!(es[0].kind, EntityKind::Organisation);
}

#[test]
fn net_entities_empty_record_yields_nothing() {
    let net: Net = serde_json::from_str("{}").expect("parses");
    assert!(net_entities(&net, 1, "s").is_empty());
}
