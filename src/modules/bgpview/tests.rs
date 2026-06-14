use super::*;

// ── Deserialisation ─────────────────────────────────────────────────
#[test]
fn deserialize_prefix_response() {
    let json = r#"{"data":{"ipv4_prefixes":[{"prefix":"1.0.0.0/24","name":"APNIC"}]}}"#;
    let r: BgpPrefixResponse = serde_json::from_str(json).unwrap();
    assert_eq!(r.data.unwrap().ipv4_prefixes[0].prefix, "1.0.0.0/24");
}

#[test]
fn deserialize_ip_response() {
    let json = r#"{"data":{"ptr_record":["dns.google"],"prefixes":[{"prefix":"8.8.8.0/24","asn":{"asn":15169,"name":"GOOGLE"}}]}}"#;
    let r: BgpIpResponse = serde_json::from_str(json).unwrap();
    let d = r.data.unwrap();
    assert_eq!(d.ptr_record[0], "dns.google");
    assert_eq!(d.prefixes[0].asn.as_ref().unwrap().asn, 15169);
}

#[tokio::test]
async fn module_metadata() {
    let m = BgpView;
    assert!(m.accepts(&Target::new(TargetKind::Asn, "AS13335")));
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
}

// ── ASN → announced prefixes ────────────────────────────────────────
#[test]
fn asn_prefix_entities_map_blocks_with_org_name() {
    let data: BgpPrefixData = serde_json::from_str(
        r#"{"ipv4_prefixes":[
            {"prefix":"104.16.0.0/13","name":"CLOUDFLARENET"},
            {"prefix":"1.1.1.0/24"},
            {"prefix":"  "}
        ]}"#,
    )
    .unwrap();
    let es = asn_prefix_entities(&data, "13335", "s");
    // The blank prefix is skipped.
    assert_eq!(es.len(), 2);
    assert!(
        es.iter()
            .all(|e| e.kind == EntityKind::IpAddress && e.has_tag("bgp-prefix"))
    );
    let cf = &es[0];
    assert_eq!(cf.value, "104.16.0.0/13");
    let ev = &cf.evidence[0];
    assert_eq!(ev.attributes.get("asn").map(String::as_str), Some("13335"));
    assert_eq!(
        ev.attributes.get("prefix").map(String::as_str),
        Some("104.16.0.0/13")
    );
    assert_eq!(
        ev.attributes.get("name").map(String::as_str),
        Some("CLOUDFLARENET")
    );
    // No name → no empty `name` attr (the old code wrote "").
    assert!(!es[1].evidence[0].attributes.contains_key("name"));
}

#[test]
fn asn_prefix_entities_respect_the_cap() {
    let prefixes: Vec<_> = (0..30)
        .map(|i| format!(r#"{{"prefix":"10.{i}.0.0/24"}}"#))
        .collect();
    let data: BgpPrefixData =
        serde_json::from_str(&format!(r#"{{"ipv4_prefixes":[{}]}}"#, prefixes.join(",")))
            .unwrap();
    assert_eq!(
        asn_prefix_entities(&data, "1", "s").len(),
        MAX_ANNOUNCED_PREFIXES
    );
}

// ── IP → PTR + ASN, now WITH the announced CIDR ─────────────────────
#[test]
fn ip_entities_map_ptr_and_asn_with_prefix() {
    let data: BgpIpData = serde_json::from_str(
        r#"{
            "ptr_record":["dns.google.","DNS.GOOGLE.","not-a-host"],
            "prefixes":[{"prefix":"8.8.8.0/24","asn":{"asn":15169,"name":"GOOGLE"}}]
        }"#,
    )
    .unwrap();
    let es = ip_entities(&data, "8.8.8.8", "s");

    // PTRs: trailing dot stripped, lowercased, deduped, non-host dropped.
    let domains: Vec<&Entity> = es.iter().filter(|e| e.kind == EntityKind::Domain).collect();
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].value, "dns.google");
    assert!(domains[0].has_tag("ptr"));

    // ASN entity carries the announced CIDR (the field the old code dropped).
    let asn: Vec<&Entity> = es.iter().filter(|e| e.kind == EntityKind::Asn).collect();
    assert_eq!(asn.len(), 1);
    assert_eq!(asn[0].value, "AS15169");
    let ev = &asn[0].evidence[0];
    assert_eq!(
        ev.attributes.get("prefix").map(String::as_str),
        Some("8.8.8.0/24")
    );
    assert_eq!(
        ev.attributes.get("name").map(String::as_str),
        Some("GOOGLE")
    );
    assert!(asn[0].has_tag("prefix:8.8.8.0/24"));
}

#[test]
fn ip_entities_skip_prefix_without_asn() {
    let data: BgpIpData =
        serde_json::from_str(r#"{"ptr_record":[],"prefixes":[{"prefix":"1.0.0.0/24"}]}"#)
            .unwrap();
    assert!(ip_entities(&data, "1.1.1.1", "s").is_empty());
}

#[test]
fn ip_entities_empty_data_yields_nothing() {
    let data: BgpIpData = serde_json::from_str("{}").unwrap();
    assert!(ip_entities(&data, "9.9.9.9", "s").is_empty());
}
