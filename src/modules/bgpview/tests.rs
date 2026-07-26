use super::*;

// ── Deserialisation ─────────────────────────────────────────────────
#[test]
fn deserialize_prefix_response() {
    let json = r#"{"data":{"ipv4_prefixes":[{"prefix":"1.0.0.0/24","name":"APNIC"}]}}"#;
    let r: BgpPrefixResponse = serde_json::from_str(json).expect("should succeed");
    assert_eq!(r.data.expect("should succeed").ipv4_prefixes[0].prefix, "1.0.0.0/24");
}

#[test]
fn deserialize_ip_response() {
    let json = r#"{"data":{"ptr_record":["dns.google"],"prefixes":[{"prefix":"8.8.8.0/24","asn":{"asn":15169,"name":"GOOGLE"}}]}}"#;
    let r: BgpIpResponse = serde_json::from_str(json).expect("should succeed");
    let d = r.data.expect("should succeed");
    assert_eq!(d.ptr_record[0], "dns.google");
    assert_eq!(d.prefixes[0].asn.as_ref().expect("should succeed").asn, 15169);
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
    .expect("should succeed");
    let es = asn_prefix_entities(&data, "13335", "s");
    // The blank prefix is skipped.
    assert_eq!(es.len(), 2);
    assert!(
        es.iter()
            .all(|e| e.kind == EntityKind::Cidr && e.has_tag("bgp-prefix"))
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
fn asn_prefix_entities_emit_every_block_v4_and_v6() {
    // 30 IPv4 blocks (> the old MAX_ANNOUNCED_PREFIXES = 20) plus 5 IPv6 blocks
    // (previously dropped entirely — the struct never deserialised them). Every
    // announced block the AS owns must surface: they are the direct answer to an
    // ASN lookup, not a truncated sample.
    let v4: Vec<_> = (0..30)
        .map(|i| format!(r#"{{"prefix":"10.{i}.0.0/24"}}"#))
        .collect();
    let v6: Vec<_> = (0..5)
        .map(|i| format!(r#"{{"prefix":"2001:db8:{i}::/48"}}"#))
        .collect();
    let data: BgpPrefixData = serde_json::from_str(&format!(
        r#"{{"ipv4_prefixes":[{}],"ipv6_prefixes":[{}]}}"#,
        v4.join(","),
        v6.join(",")
    ))
    .expect("should succeed");
    let es = asn_prefix_entities(&data, "1", "s");
    assert_eq!(
        es.len(),
        35,
        "every IPv4 (30) and IPv6 (5) announced block emitted, not capped at 20"
    );
    // The IPv6 blocks — 100% dropped before the fix — are present.
    for i in 0..5 {
        let want = format!("2001:db8:{i}::/48");
        assert!(
            es.iter().any(|e| e.kind == EntityKind::Cidr && e.value == want),
            "missing IPv6 block {want}"
        );
    }
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
    .expect("should succeed");
    let es = ip_entities(&data, "8.8.8.8", "s");

    // PTRs: trailing dot stripped, lowercased, deduped, non-host dropped.
    let domains: Vec<&Entity> = es.iter().filter(|e| e.kind == EntityKind::Domain).collect();
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].value, "dns.google");
    assert!(domains[0].has_tag("ptr"));

    // ASN entity carries the announced CIDR in evidence.
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
    // Covering prefix is also a Cidr entity.
    let cidrs: Vec<&Entity> = es.iter().filter(|e| e.kind == EntityKind::Cidr).collect();
    assert_eq!(cidrs.len(), 1);
    assert_eq!(cidrs[0].value, "8.8.8.0/24");
    assert!(cidrs[0].has_tag("bgp-prefix"));
}

#[test]
fn ip_entities_skip_prefix_without_asn() {
    let data: BgpIpData =
        serde_json::from_str(r#"{"ptr_record":[],"prefixes":[{"prefix":"1.0.0.0/24"}]}"#)
            .expect("should succeed");
    assert!(ip_entities(&data, "1.1.1.1", "s").is_empty());
}

#[test]
fn ip_entities_empty_data_yields_nothing() {
    let data: BgpIpData = serde_json::from_str("{}").expect("should succeed");
    assert!(ip_entities(&data, "9.9.9.9", "s").is_empty());
}
