use super::*;
use crate::core::scan::{Target, TargetKind};

#[test]
fn accepts_ip_and_domain_only() {
    assert!(Onyphe.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
    assert!(Onyphe.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!Onyphe.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!Onyphe.accepts(&Target::new(TargetKind::Username, "bob")));
}

#[test]
fn cost_is_key_gated_and_description_present() {
    assert!(matches!(Onyphe.cost(), ModuleCost::KeyGated));
    assert!(!Onyphe.description().is_empty());
}

#[test]
fn attack_techniques_are_all_catalogued() {
    let ids = Onyphe.attack_techniques();
    assert!(!ids.is_empty());
    for id in ids {
        assert!(
            crate::core::attack::technique(id).is_some(),
            "{id} absent from the ATT&CK catalogue"
        );
    }
}

#[test]
fn deserialises_summary_and_flags_success() {
    // Representative ONYPHE v2 `summary/ip` shape: a geoloc document + a resolver
    // document, the two categories that drive geolocation and passive-DNS output.
    let json = r#"{
        "count": 2, "error": 0, "status": "ok", "total": 2,
        "results": [
            {"@category":"geoloc","ip":"8.8.8.8","asn":"AS15169","organization":"Google LLC",
             "country":"US","countryname":"United States","city":"Mountain View",
             "location":"37.4056,-122.0775","subnet":"8.8.8.0/24"},
            {"@category":"resolver","ip":"8.8.8.8","hostname":["dns.google"],"domain":["google.com"]}
        ]
    }"#;
    let resp: OnypheResp = serde_json::from_str(json).unwrap();
    assert_eq!(resp.error, 0);
    assert_eq!(resp.results.len(), 2);
    // Field extraction over the raw documents.
    let geo = &resp.results[0];
    assert_eq!(vstr(geo, "city").as_deref(), Some("Mountain View"));
    assert_eq!(vstr(geo, "asn").as_deref(), Some("AS15169"));
    assert_eq!(vstr(geo, "organization").as_deref(), Some("Google LLC"));
}

#[test]
fn nonzero_error_is_treated_as_no_data() {
    // ONYPHE returns error != 0 for "no results" / rate-limit / plan limit.
    let resp: OnypheResp = serde_json::from_str(r#"{"error": 2, "results": []}"#).unwrap();
    assert_ne!(resp.error, 0);
    assert!(resp.results.is_empty());
}

#[test]
fn coords_from_separate_fields_or_location_string() {
    // Separate numeric latitude/longitude.
    let sep = serde_json::json!({"latitude": -27.47, "longitude": 153.02});
    assert_eq!(coords(&sep), Some((-27.47, 153.02)));
    // ONYPHE's `location` is a "lat,lon" string.
    let (lat, lon) = coords(&serde_json::json!({"location": "37.4056,-122.0775"})).unwrap();
    assert!((lat - 37.4056).abs() < 1e-6 && (lon + 122.0775).abs() < 1e-6);
    // Numbers carried as strings still parse.
    assert_eq!(
        coords(&serde_json::json!({"latitude":"10","longitude":"20"})),
        Some((10.0, 20.0))
    );
    // No coordinate fields → None (no false null-island fix).
    assert_eq!(coords(&serde_json::json!({"city":"X"})), None);
}

#[test]
fn vstrs_handles_string_or_array_shapes() {
    assert_eq!(
        vstrs(&serde_json::json!({"h": "a.com"}), "h"),
        vec!["a.com".to_string()]
    );
    assert_eq!(
        vstrs(&serde_json::json!({"h": ["a.com", "b.com"]}), "h"),
        vec!["a.com".to_string(), "b.com".to_string()]
    );
    assert!(vstrs(&serde_json::json!({"h": 5}), "h").is_empty());
    assert!(vstrs(&serde_json::json!({}), "h").is_empty());
}

#[test]
fn vstr_trims_and_rejects_empty() {
    assert_eq!(
        vstr(&serde_json::json!({"k": "  v  "}), "k").as_deref(),
        Some("v")
    );
    assert_eq!(vstr(&serde_json::json!({"k": "   "}), "k"), None);
    assert_eq!(vstr(&serde_json::json!({"k": 7}), "k"), None);
}

#[test]
fn every_distinct_resolution_is_emitted_no_cap() {
    // A domain summary listing 70 distinct in-scope subdomains (> the old
    // MAX_DOMAINS = 64). Each subdomain is both a record in the output AND a real
    // BFS expansion pivot; the expansion frontier is owned by the engine's ROI
    // Top-K gate (which ranks by weight), so a leaf cap here only hid subdomains
    // from the output by ONYPHE's arbitrary return order. Every distinct one must
    // surface; the seed, a duplicate, and a malformed host are still excluded.
    let subs: Vec<String> = (0..70)
        .map(|i| format!("host{i}.acme-target.com"))
        .collect();
    let doc = serde_json::json!({
        "@category": "resolver",
        "subdomains": subs,
        // A dup of subdomains[0], the seed itself, and a too-short host — all must
        // be dropped regardless of the cap removal.
        "hostname": ["host0.acme-target.com", "acme-target.com", "x"],
    });
    let results = vec![doc];
    let target = Target::new(TargetKind::Domain, "acme-target.com");
    let r = extract_entities(
        &results,
        &target,
        "acme-target.com",
        "domain",
        false,
        "scan",
    );

    let domains: Vec<&str> = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(
        domains.len(),
        70,
        "every distinct subdomain emitted, not capped at 64: got {}",
        domains.len()
    );
    for i in 0..70 {
        let want = format!("host{i}.acme-target.com");
        assert!(domains.contains(&want.as_str()), "missing subdomain {want}");
    }
    assert!(
        !domains.contains(&"acme-target.com"),
        "the seed domain must not be emitted as its own resolution"
    );
    assert!(
        !domains.contains(&"x"),
        "a malformed host must not be emitted"
    );
}
