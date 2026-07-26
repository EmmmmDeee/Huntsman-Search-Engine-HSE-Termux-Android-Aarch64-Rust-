use super::*;

#[test]
fn deserialize_abuse_response() {
    let json = r#"{"data":{"abuseConfidenceScore":85,"totalReports":42,"isTor":false,"isp":"Cloudflare","usageType":"Content Delivery Network","countryCode":"US"}}"#;
    let r: AbuseResponse = serde_json::from_str(json).expect("should succeed");
    let d = r.data.expect("should succeed");
    assert_eq!(d.abuse_confidence_score, Some(85));
    assert_eq!(d.total_reports, Some(42));
    assert_eq!(d.country_code.as_deref(), Some("US"));
}

#[tokio::test]
async fn module_metadata() {
    let m = AbuseIpDb;
    assert_eq!(m.cost(), ModuleCost::KeyGated);
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
}

#[test]
fn confidence_formula_score_zero() {
    let score: u32 = 0;
    let conf = confidence::MEDIUM_PLUS + (score as f64 / 100.0) * 0.35;
    assert!((conf - confidence::MEDIUM_PLUS).abs() < 1e-9);
}

#[test]
fn confidence_formula_score_80() {
    let score: u32 = 80;
    let conf = confidence::MEDIUM_PLUS + (score as f64 / 100.0) * 0.35;
    assert!((conf - confidence::EXPERT).abs() < 1e-9);
}

#[test]
fn confidence_formula_score_100() {
    let score: u32 = 100;
    let conf = confidence::MEDIUM_PLUS + (score as f64 / 100.0) * 0.35;
    assert!((conf - confidence::VERY_HIGH_PLUSPLUS).abs() < 1e-9);
}

#[test]
fn deserialize_tor_exit() {
    let json = r#"{"data":{"abuseConfidenceScore":95,"totalReports":200,"isTor":true,"isp":"TorProject","countryCode":"DE"}}"#;
    let r: AbuseResponse = serde_json::from_str(json).expect("should succeed");
    let d = r.data.expect("should succeed");
    assert_eq!(d.is_tor, Some(true));
    assert_eq!(d.abuse_confidence_score, Some(95));
}

#[test]
fn deserialize_null_data() {
    let json = r#"{"data":null}"#;
    let r: AbuseResponse = serde_json::from_str(json).expect("should succeed");
    assert!(r.data.is_none());
}

#[test]
fn deserialize_missing_optional_fields() {
    let json = r#"{"data":{"abuseConfidenceScore":10}}"#;
    let r: AbuseResponse = serde_json::from_str(json).expect("should succeed");
    let d = r.data.expect("should succeed");
    assert_eq!(d.abuse_confidence_score, Some(10));
    assert!(d.total_reports.is_none());
    assert!(d.is_tor.is_none());
    assert!(d.isp.is_none());
    assert!(d.domain.is_none());
    assert!(d.hostnames.is_empty());
}

#[test]
fn build_entities_surfaces_resolved_domains_and_isp() {
    // The verbose /check response carries `domain` + `hostnames` + `isp` —
    // real pivots the module used to discard, leaving only the seed IP.
    let data: AbuseData = serde_json::from_str(
        r#"{"abuseConfidenceScore":90,"totalReports":12,"isTor":false,
            "isp":"DigitalOcean, LLC","usageType":"Data Center/Web Hosting/Transit",
            "countryCode":"US","domain":"digitalocean.com",
            "hostnames":["mail.example.com","example.com","1.2.3.4","digitalocean.com"]}"#,
    )
    .expect("should succeed");
    let ents = build_entities(&data, "1.2.3.4", "s");
    let has = |k: EntityKind, v: &str| ents.iter().any(|e| e.kind == k && e.value == v);

    // The abuse-scored IP is still emitted (with the domain in its evidence).
    assert!(has(EntityKind::IpAddress, "1.2.3.4"));
    let ip = ents
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress)
        .expect("should succeed");
    assert!(ip.has_tag(crate::core::tags::MALICIOUS) && ip.has_tag("high-risk"));
    assert_eq!(
        ip.evidence[0].attributes.get("domain").map(String::as_str),
        Some("digitalocean.com")
    );

    // domain + hostnames → Domain pivots; IP-shaped host dropped.
    assert!(has(EntityKind::Domain, "digitalocean.com"));
    assert!(has(EntityKind::Domain, "mail.example.com"));
    assert!(has(EntityKind::Domain, "example.com"));
    assert!(
        !ents
            .iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "1.2.3.4"),
        "IP-shaped hostname must not become a Domain"
    );
    // `digitalocean.com` is in both `domain` and `hostnames` → deduped to one.
    assert_eq!(
        ents.iter()
            .filter(|e| e.kind == EntityKind::Domain && e.value == "digitalocean.com")
            .count(),
        1
    );
    // ISP → Organisation pivot (value case-normalised by Entity::new).
    assert!(ents.iter().any(|e| e.kind == EntityKind::Organisation
        && e.value.to_lowercase().contains("digitalocean")));
}

#[test]
fn verbose_reports_surface_categories_recency_and_whitelist() {
    let data: AbuseData = serde_json::from_str(
        r#"{"abuseConfidenceScore":30,"totalReports":5,"isWhitelisted":true,
            "lastReportedAt":"2024-05-01T12:00:00+00:00",
            "reports":[
                {"categories":[22,18]},
                {"categories":[22,14]},
                {"categories":[22]}
            ]}"#,
    )
    .expect("should succeed");
    let ip = build_entities(&data, "1.2.3.4", "s")
        .into_iter()
        .find(|e| e.kind == EntityKind::IpAddress)
        .expect("should succeed");

    // Whitelist flag → tag.
    assert!(ip.has_tag("whitelisted"));

    let a = &ip.evidence[0].attributes;
    assert_eq!(
        a.get("last_reported_at").map(String::as_str),
        Some("2024-05-01T12:00:00+00:00")
    );
    // SSH(22) appears 3×, Brute-Force(18) + Port Scan(14) once each — deterministic
    // count-desc, id-asc ordering maps ids to their taxonomy labels.
    assert_eq!(
        a.get("report_categories").map(String::as_str),
        Some("SSH:3, Port Scan:1, Brute-Force:1")
    );
}

#[test]
fn summarize_categories_is_deterministic_and_maps_unknown_to_other() {
    let reports = vec![
        Report {
            categories: vec![99, 14],
        },
        Report {
            categories: vec![14, 99],
        },
    ];
    // 14 (Port Scan) and 99 (unknown→other) each appear twice; id-asc tie-break
    // puts 14 first regardless of input order.
    assert_eq!(
        summarize_categories(&reports),
        "Port Scan:2, other:2"
    );
    assert!(summarize_categories(&[]).is_empty());
}

#[test]
fn usage_type_datacenter_tags_ip_hosting() {
    let dc: AbuseData = serde_json::from_str(
        r#"{"abuseConfidenceScore":10,"usageType":"Data Center/Web Hosting/Transit","isp":"OVH"}"#,
    ).expect("should succeed");
    let ip = build_entities(&dc, "1.2.3.4", "s")
        .into_iter()
        .find(|e| e.kind == EntityKind::IpAddress)
        .expect("should succeed");
    assert!(ip.has_tag("hosting"), "datacenter usage type must tag hosting");

    // A residential/ISP usage type must NOT be tagged hosting.
    let res: AbuseData = serde_json::from_str(
        r#"{"abuseConfidenceScore":5,"usageType":"Fixed Line ISP","isp":"Telstra"}"#,
    ).expect("should succeed");
    let ip2 = build_entities(&res, "5.6.7.8", "s")
        .into_iter()
        .find(|e| e.kind == EntityKind::IpAddress)
        .expect("should succeed");
    assert!(!ip2.has_tag("hosting"));
}
