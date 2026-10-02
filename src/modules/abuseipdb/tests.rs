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
    let conf = super::abuse_confidence(score);
    assert!((conf - confidence::MEDIUM_PLUS).abs() < 1e-9);
}

#[test]
fn confidence_formula_score_80() {
    let score: u32 = 80;
    let conf = super::abuse_confidence(score);
    assert!((conf - confidence::EXPERT).abs() < 1e-9);
}

#[test]
fn confidence_formula_score_100() {
    let score: u32 = 100;
    let conf = super::abuse_confidence(score);
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

#[test]
fn a_clean_verdict_is_never_tagged_threat_intel() {
    // REQ-ABUSEIPDB-001. `THREAT_INTEL` is one of only three
    // `ADJACENCY_BAD_TAGS` (core::correlator::rules), which AU-031
    // "malicious adjacency" reads to raise a **High**-severity finding on any
    // entity one hop from a tag-bearing node. Tagging it unconditionally —
    // before the score branch below it — meant AbuseIPDB's OWN clean verdict
    // (0/100 confidence, 0 reports) still marked the IP known-bad, so any
    // domain resolving to it was reported "adjacent to known-bad
    // infrastructure": a High-severity escalation fabricated out of a
    // NEGATIVE signal, purely because the IP had been looked up at all.
    //
    // Every sibling module gates this tag on a real positive verdict —
    // `virustotal` only when `malicious > 0` (and pins this same negative
    // case in its own tests), `chain_intel` only on the source's own flag
    // ("never when [it] is absent or false, so a source that doesn't report a
    // verdict can't be mistaken for a clean bill of health"), `onyphe` only
    // on a named threat-list match, `pulsedive` returns early when nothing is
    // linked. abuseipdb was the one outlier.
    let data: AbuseData =
        serde_json::from_str(r#"{"abuseConfidenceScore":0,"totalReports":0,"isTor":false}"#)
            .expect("clean fixture parses");
    let ents = build_entities(&data, "8.8.8.8", "s");
    let ip = ents
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress)
        .expect("the queried IP is still emitted for a clean verdict");
    assert!(
        !ip.has_tag(crate::core::tags::THREAT_INTEL),
        "a 0%/0-report clean verdict must not mark the IP known-bad, got tags {:?}",
        ip.tags
    );
    assert!(!ip.has_tag(crate::core::tags::MALICIOUS));
    assert!(!ip.has_tag("suspicious"));
    assert!(!ip.has_tag("high-risk"));
}

#[test]
fn a_real_positive_verdict_still_carries_threat_intel() {
    // Guard for the fix above: the tag must STILL appear at every band the
    // module itself treats as a positive verdict, or the gate has overreached
    // and abuseipdb silently stops feeding adjacency analysis altogether —
    // trading a false positive for a false negative.
    for (score, expect_malicious) in [(40_u32, false), (79, false), (80, true), (100, true)] {
        let json = format!(r#"{{"abuseConfidenceScore":{score},"totalReports":9}}"#);
        let data: AbuseData = serde_json::from_str(&json).expect("scored fixture parses");
        let ents = build_entities(&data, "1.2.3.4", "s");
        let ip = ents
            .iter()
            .find(|e| e.kind == EntityKind::IpAddress)
            .expect("ip emitted");
        assert!(
            ip.has_tag(crate::core::tags::THREAT_INTEL),
            "score {score} is a real positive verdict and must stay THREAT_INTEL"
        );
        assert_eq!(
            ip.has_tag(crate::core::tags::MALICIOUS),
            expect_malicious,
            "score {score}: MALICIOUS gating must be unchanged by this fix"
        );
    }
}

#[test]
fn a_score_below_the_suspicious_band_is_not_threat_intel() {
    // The boundary the fix rests on: AbuseIPDB's own graded score below the
    // module's existing `>= 40` "suspicious" band is not a verdict this
    // engine may escalate on. 39 is the last value that must stay clean.
    for score in [1_u32, 10, 39] {
        let json = format!(r#"{{"abuseConfidenceScore":{score},"totalReports":1}}"#);
        let data: AbuseData = serde_json::from_str(&json).expect("low fixture parses");
        let ents = build_entities(&data, "1.2.3.4", "s");
        let ip = ents
            .iter()
            .find(|e| e.kind == EntityKind::IpAddress)
            .expect("ip emitted");
        assert!(
            !ip.has_tag(crate::core::tags::THREAT_INTEL),
            "score {score} is below the suspicious band and must not be known-bad"
        );
    }
}
