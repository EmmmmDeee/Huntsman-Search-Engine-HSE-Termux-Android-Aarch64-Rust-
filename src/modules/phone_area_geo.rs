//! Phone area code geolocation — refine country-level phone geo to
//! city/region level using area code lookup tables.
//!
//! The existing `geo_intel` module maps phone prefixes to country
//! centroids at 0.52 confidence. This module adds a second layer:
//! for countries with well-defined geographic area codes (Australia,
//! UK, US, Germany, France, Japan), it maps the area code to a
//! city or region, producing an Address entity at higher granularity.
//!
//! For Australia specifically:
//!  - `+617` landlines → SE Queensland (Brisbane / Logan / Gold Coast /
//!    Sunshine Coast); confidence 0.62 (area code is unambiguous for SE QLD,
//!    but the actual city within SE QLD is unknown).
//!  - `+614xx` mobiles → carrier inference via ACMA number-block allocations,
//!    producing a Carrier + likely metro/rural region; confidence 0.42.
//!
//! No network calls. Runs in < 1ms. Priority 93 so it fires before
//! geocoding modules.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "phone_area_geo";

pub struct PhoneAreaGeo;

#[async_trait]
impl Module for PhoneAreaGeo {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Refine phone geolocation from country to city/region via area code lookup"
    }

    fn priority(&self) -> u8 {
        93
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Phone)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Address];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let digits: String = target
            .value
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();

        if digits.len() < 8 {
            return Ok(result);
        }

        if let Some(geo) = lookup_area_code(&digits) {
            let mut e = Entity::new(
                EntityKind::Address,
                geo.location,
                geo.confidence,
                &ctx.scan_id,
            );
            e.tag("geoint");
            e.tag("phone-area-code");
            if geo.country_code == "AU" && geo.area_code == "7" {
                e.tag(crate::core::tags::AU_SE_QLD);
                e.tag(crate::core::tags::AU_RELEVANT);
            }
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "Phone area code {} → {}, {}",
                        geo.area_code, geo.location, geo.country
                    ),
                )
                .with_attr("area_code", geo.area_code)
                .with_attr("country", geo.country)
                .with_attr("country_code", geo.country_code),
            );
            result.push(e);
        }

        // AU mobile carrier inference: +614xx → carrier + likely metro/rural region.
        if let Some(carrier) = au_mobile_carrier(&digits) {
            let label = format!(
                "Australia — {} mobile ({})",
                carrier.region, carrier.carrier_name
            );
            let mut e = Entity::new(EntityKind::Address, label, carrier.confidence, &ctx.scan_id);
            e.tag("geoint");
            e.tag("phone-mobile-carrier");
            e.tag(crate::core::tags::AU_RELEVANT);
            e.tag(format!(
                "{}{}",
                crate::core::tags::AU_CARRIER_PREFIX,
                carrier.carrier_slug
            ));
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "AU mobile prefix +61{} allocated to {} — {}",
                        carrier.prefix, carrier.carrier_name, carrier.region
                    ),
                )
                .with_attr("mobile_prefix", carrier.prefix)
                .with_attr("carrier", carrier.carrier_name)
                .with_attr("country_code", "AU"),
            );
            result.push(e);
        }

        Ok(result)
    }
}

struct AreaCodeGeo {
    location: &'static str,
    country: &'static str,
    country_code: &'static str,
    area_code: &'static str,
    confidence: f64,
}

fn lookup_area_code(digits: &str) -> Option<AreaCodeGeo> {
    for &(country_prefix, table) in AREA_CODE_TABLES {
        let Some(national) = digits.strip_prefix(country_prefix) else {
            continue;
        };
        {
            for &(area, city, cc) in table {
                if national.starts_with(area) {
                    return Some(AreaCodeGeo {
                        location: city,
                        country: country_name(cc),
                        country_code: cc,
                        area_code: area,
                        confidence: 0.58,
                    });
                }
            }
        }
    }
    None
}

fn country_name(cc: &str) -> &'static str {
    // Reuse the canonical ISO→name table (55 countries) rather than maintain a
    // divergent 8-entry copy; every ISO this module's area tables use is covered.
    crate::util::geohash::country_name_for_iso(cc).unwrap_or("Unknown")
}

struct MobileCarrierGeo {
    prefix: String,
    carrier_name: &'static str,
    carrier_slug: &'static str,
    region: &'static str,
    confidence: f64,
}

/// AU mobile carrier inference from ACMA number-block allocations.
///
/// Maps `+614xx` national-number prefixes to the carrier that holds the block
/// and their typical service footprint. Confidence 0.42 — carrier tells us
/// metro vs. regional, not city-level.
fn au_mobile_carrier(digits: &str) -> Option<MobileCarrierGeo> {
    // Must start with AU country code + mobile digit 4.
    let national = digits.strip_prefix("614")?;
    if national.len() < 6 {
        return None;
    }
    // Two-digit block prefix (first two digits of the 8-digit subscriber number).
    let block: u8 = national[..2].parse().ok()?;
    let prefix_str = national[..2].to_string();
    // ACMA block allocations (simplified, as at 2024).
    // Optus: 04 00–09, 04 27–29, 04 30–39, 04 50–59, 04 80–83
    // Telstra: 04 10–26, 04 40–49, 04 60–69, 04 84–99
    // Vodafone/TPG: 04 70–79
    let (carrier_name, carrier_slug, region) = match block {
        0..=9 => ("Optus", "optus", "SE QLD / Sydney / Melbourne (metro)"),
        10..=26 => ("Telstra", "telstra", "Australia-wide (metro + regional)"),
        27..=39 => ("Optus", "optus", "SE QLD / Sydney / Melbourne (metro)"),
        40..=49 => ("Telstra", "telstra", "Australia-wide (metro + regional)"),
        50..=59 => ("Optus", "optus", "SE QLD / Sydney / Melbourne (metro)"),
        60..=69 => ("Telstra", "telstra", "Australia-wide (metro + regional)"),
        70..=79 => ("Vodafone / TPG", "vodafone", "Major metro centres only"),
        80..=83 => ("Optus", "optus", "SE QLD / Sydney / Melbourne (metro)"),
        _ => ("Telstra", "telstra", "Australia-wide (metro + regional)"),
    };
    Some(MobileCarrierGeo {
        prefix: prefix_str,
        carrier_name,
        carrier_slug,
        region,
        confidence: 0.42,
    })
}

// AU landline area codes — expanded to SE QLD city / region granularity.
// Table ordering rule: longer prefix first within a country so lookup_area_code
// finds the most-specific entry. Digit-prefix deduplication is verified by the
// `area_tables_are_well_formed_and_prefix_ordered` test.
const AU_AREAS: &[(&str, &str, &str)] = &[
    // +617 — SE QLD. Broken out so a 07 landline asserts SE QLD,
    // not the whole state.  City-level table omitted because all 07
    // landlines share the same national area digit '7'.
    (
        "7",
        "SE Queensland (Brisbane / Logan / Gold Coast / Sunshine Coast)",
        "AU",
    ),
    ("2", "Sydney / NSW / ACT", "AU"),
    ("3", "Melbourne / VIC / TAS", "AU"),
    ("8", "Perth / SA / NT", "AU"),
];

const GB_AREAS: &[(&str, &str, &str)] = &[
    ("20", "London", "GB"),
    ("121", "Birmingham", "GB"),
    ("131", "Edinburgh", "GB"),
    ("141", "Glasgow", "GB"),
    ("151", "Liverpool", "GB"),
    ("161", "Manchester", "GB"),
    ("113", "Leeds", "GB"),
    ("114", "Sheffield", "GB"),
    ("115", "Nottingham", "GB"),
    ("116", "Leicester", "GB"),
    ("117", "Bristol", "GB"),
    ("118", "Reading", "GB"),
    ("191", "Newcastle upon Tyne", "GB"),
    ("23", "Southampton / Portsmouth", "GB"),
    ("24", "Coventry", "GB"),
    ("28", "Northern Ireland", "GB"),
    ("29", "Cardiff", "GB"),
];

const DE_AREAS: &[(&str, &str, &str)] = &[
    ("30", "Berlin", "DE"),
    ("40", "Hamburg", "DE"),
    ("69", "Frankfurt", "DE"),
    ("89", "Munich", "DE"),
    ("221", "Cologne", "DE"),
    ("211", "Duesseldorf", "DE"),
    ("711", "Stuttgart", "DE"),
    ("511", "Hannover", "DE"),
    ("341", "Leipzig", "DE"),
    ("351", "Dresden", "DE"),
];

const FR_AREAS: &[(&str, &str, &str)] = &[
    ("1", "Paris / Ile-de-France", "FR"),
    ("2", "Northwest France", "FR"),
    ("3", "Northeast France", "FR"),
    ("4", "Southeast France", "FR"),
    ("5", "Southwest France", "FR"),
];

const JP_AREAS: &[(&str, &str, &str)] = &[
    ("3", "Tokyo", "JP"),
    ("6", "Osaka", "JP"),
    ("45", "Yokohama", "JP"),
    ("52", "Nagoya", "JP"),
    ("11", "Sapporo", "JP"),
    ("22", "Sendai", "JP"),
    ("75", "Kyoto", "JP"),
    ("78", "Kobe", "JP"),
    ("82", "Hiroshima", "JP"),
    ("92", "Fukuoka", "JP"),
];

const NZ_AREAS: &[(&str, &str, &str)] = &[
    ("9", "Auckland", "NZ"),
    ("4", "Wellington", "NZ"),
    ("3", "Christchurch / South Island", "NZ"),
    ("7", "Hamilton / Waikato", "NZ"),
];

type AreaTable = &'static [(&'static str, &'static str, &'static str)];

const NANP_AREAS: &[(&str, &str, &str)] = &[
    // US
    ("212", "New York City", "US"),
    ("213", "Los Angeles", "US"),
    ("312", "Chicago", "US"),
    ("415", "San Francisco", "US"),
    ("202", "Washington DC", "US"),
    ("305", "Miami", "US"),
    ("713", "Houston", "US"),
    ("214", "Dallas", "US"),
    ("404", "Atlanta", "US"),
    ("617", "Boston", "US"),
    ("206", "Seattle", "US"),
    ("303", "Denver", "US"),
    ("602", "Phoenix", "US"),
    ("215", "Philadelphia", "US"),
    ("313", "Detroit", "US"),
    ("612", "Minneapolis", "US"),
    ("314", "St. Louis", "US"),
    ("702", "Las Vegas", "US"),
    ("503", "Portland", "US"),
    ("512", "Austin", "US"),
    ("619", "San Diego", "US"),
    ("704", "Charlotte", "US"),
    ("808", "Hawaii", "US"),
    ("907", "Alaska", "US"),
    // Canada
    ("416", "Toronto", "CA"),
    ("604", "Vancouver", "CA"),
    ("514", "Montreal", "CA"),
    ("613", "Ottawa", "CA"),
    ("403", "Calgary", "CA"),
    ("780", "Edmonton", "CA"),
    ("204", "Winnipeg", "CA"),
    ("306", "Saskatchewan", "CA"),
];

const AREA_CODE_TABLES: &[(&str, AreaTable)] = &[
    ("61", AU_AREAS),
    ("44", GB_AREAS),
    ("1", NANP_AREAS),
    ("49", DE_AREAS),
    ("33", FR_AREAS),
    ("81", JP_AREAS),
    ("64", NZ_AREAS),
];

#[cfg(test)]
mod tests {
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
    fn au_se_qld_landline() {
        let geo = lookup_area_code("61712345678").unwrap();
        assert!(
            geo.location.contains("SE Queensland"),
            "expected SE Queensland, got {}",
            geo.location
        );
        assert_eq!(geo.country_code, "AU");
        assert_eq!(geo.area_code, "7");
    }

    #[test]
    fn au_mobile_returns_none_from_area_table() {
        assert!(
            lookup_area_code("61412345678").is_none(),
            "mobile prefixes should not produce geographic addresses via area table"
        );
    }

    #[test]
    fn au_mobile_optus_carrier_inference() {
        // +61 434 215 033 → digits 61434215033, national "34215033", block "34" → Optus
        let c = au_mobile_carrier("61434215033").unwrap();
        assert_eq!(c.carrier_name, "Optus");
        assert!(c.region.contains("metro"));
        assert!((c.confidence - 0.42).abs() < 1e-9);
    }

    #[test]
    fn au_mobile_telstra_carrier_inference() {
        // +61 411 xxx xxx → block "11" → Telstra
        let c = au_mobile_carrier("61411234567").unwrap();
        assert_eq!(c.carrier_name, "Telstra");
        assert!(c.region.contains("regional"));
    }

    #[test]
    fn au_mobile_vodafone_carrier_inference() {
        let c = au_mobile_carrier("61470123456").unwrap();
        assert_eq!(c.carrier_slug, "vodafone");
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

    #[tokio::test]
    async fn module_produces_address_for_landline() {
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
        assert_eq!(r.len(), 1);
        assert_eq!(r.entities[0].kind, EntityKind::Address);
        assert!(r.entities[0].value.contains("Sydney"));
        assert!(r.entities[0].has_tag("phone-area-code"));
    }

    #[tokio::test]
    async fn module_produces_se_qld_for_07_landline() {
        let m = PhoneAreaGeo;
        let target = Target::new(TargetKind::Phone, "+61 7 3333 4444");
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
        assert_eq!(r.len(), 1);
        assert!(r.entities[0].value.contains("SE Queensland"));
        assert!(r.entities[0].has_tag("au-se-qld"));
    }

    #[tokio::test]
    async fn module_produces_carrier_for_au_mobile() {
        let m = PhoneAreaGeo;
        // +61 434 215 033 — Optus mobile (block 34)
        let target = Target::new(TargetKind::Phone, "+61434215033");
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
        // Only carrier entity (no area-code entity for mobiles).
        assert_eq!(r.len(), 1);
        let e = &r.entities[0];
        assert!(e.has_tag("phone-mobile-carrier"));
        assert!(e.has_tag("au-carrier:optus"));
        assert!(e.value.contains("Optus"));
    }
}
