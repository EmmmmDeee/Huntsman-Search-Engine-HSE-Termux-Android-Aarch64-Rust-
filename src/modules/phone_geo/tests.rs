use crate::core::confidence;
use super::*;
use data::{
    AREA_CODE_TABLES, au_carrier, country_name, identify_carrier, lookup_area_code, uk_carrier,
};

// ── Area-code lookup (ported from the former `phone_area_geo`) ───────────────

#[test]
fn au_sydney_landline() {
    let geo = lookup_area_code("61212345678").unwrap();
    assert_eq!(geo.location, "Sydney / NSW / ACT");
    assert_eq!(geo.country_code, "AU");
}

#[test]
fn au_melbourne_landline() {
    let geo = lookup_area_code("61312345678").unwrap();
    assert_eq!(geo.location, "Melbourne / VIC");
}

#[test]
fn au_tasmania_landline_resolves_to_tas_not_vic() {
    // 03 6234 5678 — the 03 6x block is exclusively Tasmania, so it must beat
    // the "3" Victoria catch-all rather than fall through to it.
    let geo = lookup_area_code("61362345678").unwrap();
    assert_eq!(geo.location, "Hobart / TAS");
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

// ── Carrier identification (ported from the former `phone_carrier_geo`) ──────

#[test]
fn au_telstra_prefix() {
    let c = identify_carrier("61412345678").unwrap();
    assert_eq!(c.carrier, "Telstra");
    assert_eq!(c.country, "Australia");
}

#[test]
fn au_optus_prefix() {
    let c = identify_carrier("61431234567").unwrap();
    assert_eq!(c.carrier, "Optus");
}

#[test]
fn au_vodafone_prefix() {
    let c = identify_carrier("61420123456").unwrap();
    assert_eq!(c.carrier, "Vodafone");
}

#[test]
fn uk_ee_prefix() {
    let c = identify_carrier("447400123456").unwrap();
    assert_eq!(c.carrier, "EE");
    assert_eq!(c.country, "United Kingdom");
}

#[test]
fn carrier_unknown_prefix_returns_none() {
    assert!(identify_carrier("99912345678").is_none());
}

#[test]
fn carrier_too_short_returns_none() {
    assert!(identify_carrier("6141").is_none());
}

#[test]
fn au_carrier_maps_prefixes_with_full_fields() {
    let telstra = au_carrier("400").unwrap();
    assert_eq!(telstra.carrier, "Telstra");
    assert_eq!(telstra.country, "Australia");
    assert_eq!(telstra.confidence, 0.42);
    assert_eq!(telstra.network_hint, "dominant_rural_regional");

    let vodafone = au_carrier("420").unwrap();
    assert_eq!(vodafone.carrier, "Vodafone");
    assert_eq!(vodafone.network_hint, "metro_only");

    let optus = au_carrier("430").unwrap();
    assert_eq!(optus.carrier, "Optus");
    assert_eq!(optus.network_hint, "metro_suburban");

    let mvno = au_carrier("450").unwrap();
    assert_eq!(mvno.carrier, "Pivotel/MVNOs");
    assert_eq!(mvno.network_hint, "mvno");
}

#[test]
fn au_carrier_unknown_prefix_is_none() {
    assert!(au_carrier("999").is_none());
}

#[test]
fn uk_carrier_maps_prefixes_with_full_fields() {
    let ee = uk_carrier("7400").unwrap();
    assert_eq!(ee.carrier, "EE");
    assert_eq!(ee.country, "United Kingdom");
    assert_eq!(ee.confidence, confidence::LOW);
    assert_eq!(ee.network_hint, "mobile");

    assert_eq!(uk_carrier("7410").unwrap().carrier, "Vodafone UK");
    assert_eq!(uk_carrier("7420").unwrap().carrier, "Three UK");
    assert_eq!(uk_carrier("7450").unwrap().carrier, "O2 UK");
}

#[test]
fn uk_carrier_unknown_prefix_is_none() {
    assert!(uk_carrier("9999").is_none());
}

// ── Merged module metadata + end-to-end (both passes in one process()) ───────

#[tokio::test]
async fn module_metadata() {
    let m = PhoneGeo;
    assert_eq!(m.name(), "phone_geo");
    assert_eq!(m.priority(), 93);
    assert!(m.is_passive());
    assert!(matches!(m.category(), ModuleCategory::Geo));
    assert!(m.accepts(&Target::new(TargetKind::Phone, "+61212345678")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    // Union of both source modules' outputs.
    assert!(m.produces().contains(&EntityKind::Address));
    assert!(m.produces().contains(&EntityKind::Coordinates));
}

fn test_ctx() -> ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    ModuleContext {
        scan_id: "test".into(),
        bus,
        http: reqwest::Client::new(),
        keys: Default::default(),
        cancel: Default::default(),
    }
}

#[tokio::test]
async fn landline_runs_area_pass_and_emits_phone_area_geo_source() {
    let m = PhoneGeo;
    let target = Target::new(TargetKind::Phone, "+61 2 1234 5678");
    let r = m.process(&target, &test_ctx()).await.unwrap();
    // Address always emitted; Coordinates emitted when city_coords matches.
    assert!(!r.is_empty());
    let addr = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .unwrap();
    assert!(addr.value.contains("Sydney"));
    assert!(addr.has_tag("phone-area-code"));
    // The area pass must keep stamping the former source string (the correlator
    // keys on it).
    assert!(
        addr.has_evidence_from(SRC_AREA),
        "area-code Address must carry the `phone_area_geo` source needle"
    );
}

#[tokio::test]
async fn mobile_runs_carrier_pass_and_emits_phone_carrier_geo_source() {
    let m = PhoneGeo;
    // AU Telstra mobile: no geographic area code, but a carrier hit.
    let target = Target::new(TargetKind::Phone, "+61 412 345 678");
    let r = m.process(&target, &test_ctx()).await.unwrap();
    let addr = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Address && e.has_tag("carrier-inferred"))
        .expect("carrier pass must emit a coarse Address");
    assert_eq!(addr.value, "Australia");
    assert!(addr.has_tag(crate::core::tags::COARSE));
    assert!(
        addr.has_evidence_from(SRC_CARRIER),
        "carrier Address must carry the `phone_carrier_geo` source needle"
    );
    // A mobile number has no geographic area code, so the area pass is silent —
    // but its silence must not have suppressed the carrier pass (checked above).
    assert!(
        !r.entities.iter().any(|e| e.has_tag("phone-area-code")),
        "AU mobile must not yield an area-code Address"
    );
}

#[tokio::test]
async fn both_passes_independent_no_match_does_not_suppress() {
    // Unknown number: neither pass matches, and process() still succeeds empty.
    let m = PhoneGeo;
    let target = Target::new(TargetKind::Phone, "+99 9 1234 5678");
    let r = m.process(&target, &test_ctx()).await.unwrap();
    assert!(
        r.is_empty(),
        "an unmatched number yields nothing from either pass"
    );
}
