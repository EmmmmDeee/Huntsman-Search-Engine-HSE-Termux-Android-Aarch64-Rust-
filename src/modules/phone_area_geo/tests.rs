use super::*;

#[test]
fn au_sydney_landline() {
    let geo = lookup_area_code("61212345678").unwrap();
    assert_eq!(geo.location, "Sydney / NSW / ACT");
    assert_eq!(geo.country_code, "AU");
}

#[test]
fn au_melbourne_landline() {
    let geo = lookup_area_code("61312345678").unwrap();
    assert_eq!(geo.location, "Melbourne / VIC / TAS");
}

#[test]
fn au_mobile_returns_none() {
    assert!(
        lookup_area_code("61412345678").is_none(),
        "mobile prefixes should not produce geographic addresses"
    );
}

#[test]
fn uk_london() {
    let geo = lookup_area_code("442012345678").unwrap();
    assert_eq!(geo.location, "London");
    assert_eq!(geo.country_code, "GB");
}

#[test]
fn us_nyc() {
    let geo = lookup_area_code("12125551234").unwrap();
    assert_eq!(geo.location, "New York City");
    assert_eq!(geo.country_code, "US");
}

#[test]
fn de_berlin() {
    let geo = lookup_area_code("493012345678").unwrap();
    assert_eq!(geo.location, "Berlin");
}

#[test]
fn jp_tokyo() {
    let geo = lookup_area_code("81312345678").unwrap();
    assert_eq!(geo.location, "Tokyo");
}

#[test]
fn unknown_prefix_returns_none() {
    assert!(lookup_area_code("99912345678").is_none());
}

#[test]
fn short_number_returns_none() {
    assert!(lookup_area_code("12345").is_none());
}

#[test]
fn area_tables_are_well_formed_and_prefix_ordered() {
    // Country prefixes must not shadow each other (longest-first), or a whole
    // country's table becomes unreachable.
    let mut cc_violations = Vec::new();
    for (i, (earlier, _)) in AREA_CODE_TABLES.iter().enumerate() {
        assert!(
            !earlier.is_empty() && earlier.bytes().all(|b| b.is_ascii_digit()),
            "non-digit country prefix {earlier:?}"
        );
        for (later, _) in &AREA_CODE_TABLES[i + 1..] {
            if later.starts_with(earlier) {
                cc_violations.push(format!("+{later} shadowed by earlier +{earlier}"));
            }
        }
    }
    assert!(
        cc_violations.is_empty(),
        "country-prefix ordering: {cc_violations:?}"
    );

    // Within each country, `lookup_area_code` returns the first area code the
    // national number starts with — so (as with the international country
    // table) no earlier area code may be a string-prefix of a later one, or
    // that city is unreachable. Variable-length tables (GB, DE) are where this
    // bites. Also assert each entry is well-formed.
    for (country_prefix, table) in AREA_CODE_TABLES {
        let mut violations = Vec::new();
        for (i, (earlier, _city, cc)) in table.iter().enumerate() {
            assert!(
                !earlier.is_empty() && earlier.bytes().all(|b| b.is_ascii_digit()),
                "+{country_prefix}: non-digit area code {earlier:?}"
            );
            assert!(
                cc.len() == 2 && cc.bytes().all(|b| b.is_ascii_uppercase()),
                "+{country_prefix}: bad ISO {cc:?}"
            );
            for (later, lcity, _) in &table[i + 1..] {
                if later.starts_with(*earlier) {
                    violations.push(format!("{later} ({lcity}) shadowed by earlier {earlier}"));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "area-code ordering in +{country_prefix}:\n  {}",
            violations.join("\n  ")
        );
    }
}

#[tokio::test]
async fn module_metadata() {
    let m = PhoneAreaGeo;
    assert!(m.is_passive());
    assert!(m.accepts(&Target::new(TargetKind::Phone, "+61212345678")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
}

#[test]
fn country_name_maps_known_iso_codes() {
    assert_eq!(country_name("US"), "United States");
    assert_eq!(country_name("AU"), "Australia");
    assert_eq!(country_name("GB"), "United Kingdom");
    assert_eq!(country_name("JP"), "Japan");
    assert_eq!(country_name("DE"), "Germany");
}

#[test]
fn country_name_unknown_iso_falls_back() {
    assert_eq!(country_name("ZZ"), "Unknown");
    // The table is keyed on uppercase ISO codes, so lowercase misses.
    assert_eq!(country_name("us"), "Unknown");
}

#[tokio::test]
async fn module_produces_address() {
    let m = PhoneAreaGeo;
    let target = Target::new(TargetKind::Phone, "+61 2 1234 5678");
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    let ctx = ModuleContext {
        scan_id: "test".into(),
        bus,
        http: reqwest::Client::new(),
        keys: Default::default(),
        cancel: Default::default(),
        proxy_pool: Default::default(),
    };
    let r = m.process(&target, &ctx).await.unwrap();
    // Address always emitted; Coordinates emitted when city_coords matches.
    assert!(!r.is_empty());
    let addr = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .unwrap();
    assert!(addr.value.contains("Sydney"));
    assert!(addr.has_tag("phone-area-code"));
}
