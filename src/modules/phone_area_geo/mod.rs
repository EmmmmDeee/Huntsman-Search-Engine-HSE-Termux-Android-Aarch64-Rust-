//! Phone area code geolocation — refine country-level phone geo to
//! city/region level using area code lookup tables.
//!
//! The existing `geo_intel` module maps phone prefixes to country
//! centroids at 0.52 confidence. This module adds a second layer:
//! for countries with well-defined geographic area codes (Australia,
//! UK, US, Germany, France, Japan), it maps the area code to a
//! city or region, producing an Address entity at higher granularity.
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

#[cfg(test)]
mod tests;

pub(super) const SRC: &str = "phone_area_geo";

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
        const KINDS: &[EntityKind] = &[EntityKind::Address, EntityKind::Coordinates];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let digits: String = target.value.chars().filter(char::is_ascii_digit).collect();

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
            e.tag(format!("country:{}", geo.country_code));
            if geo.country_code == "AU"
                && let Some(sc) = crate::util::address_au::state_code(geo.location)
            {
                e.tag(format!("au-state:{sc}"));
            }
            let ev = Evidence::new(
                SRC,
                format!(
                    "Phone area code {} → {}, {}",
                    geo.area_code, geo.location, geo.country
                ),
            )
            .with_attr("area_code", geo.area_code)
            .with_attr("country", geo.country)
            .with_attr("country_code", geo.country_code);
            e.add_evidence(ev.clone());
            result.push(e);

            // Inline Coordinates: city_coords gives a lat/lon for the primary
            // city named in the location string. Confidence one tier below the
            // Address (area-code geo is city-level, not GPS).
            if let Some((lat, lon)) = crate::util::city_coords::city_coords(geo.location) {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(
                    EntityKind::Coordinates,
                    &coord_val,
                    geo.confidence - 0.08,
                    &ctx.scan_id,
                );
                c.tag("addr-derived");
                c.tag("geoint");
                c.tag("phone-area-code");
                c.tag(format!("country:{}", geo.country_code));
                if geo.country_code == "AU"
                    && let Some(sc) = crate::util::address_au::state_code(geo.location)
                {
                    c.tag(format!("au-state:{sc}"));
                }
                c.add_evidence(ev);
                result.push(c);
            }
        }

        Ok(result)
    }
}

pub(super) struct AreaCodeGeo {
    pub(super) location: &'static str,
    pub(super) country: &'static str,
    pub(super) country_code: &'static str,
    pub(super) area_code: &'static str,
    pub(super) confidence: f64,
}

pub(super) fn lookup_area_code(digits: &str) -> Option<AreaCodeGeo> {
    // First country whose dialling prefix the number carries AND whose table has
    // a matching area code; a prefix match with no area hit falls through to the
    // next country (nested find_map mirrors the original break-to-outer-loop).
    AREA_CODE_TABLES
        .iter()
        .find_map(|&(country_prefix, table)| {
            let national = digits.strip_prefix(country_prefix)?;
            table.iter().find_map(|&(area, city, cc)| {
                national.starts_with(area).then(|| AreaCodeGeo {
                    location: city,
                    country: country_name(cc),
                    country_code: cc,
                    area_code: area,
                    confidence: 0.58,
                })
            })
        })
}

fn country_name(cc: &str) -> &'static str {
    // Reuse the canonical ISO→name table (55 countries) rather than maintain a
    // divergent 8-entry copy; every ISO this module's area tables use is covered.
    crate::util::geohash::country_name_for_iso(cc).unwrap_or("Unknown")
}

const AU_AREAS: &[(&str, &str, &str)] = &[
    ("2", "Sydney / NSW / ACT", "AU"),
    ("3", "Melbourne / VIC / TAS", "AU"),
    ("7", "Brisbane / QLD", "AU"),
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

pub(super) type AreaTable = &'static [(&'static str, &'static str, &'static str)];

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

pub(super) const AREA_CODE_TABLES: &[(&str, AreaTable)] = &[
    ("61", AU_AREAS),
    ("44", GB_AREAS),
    ("1", NANP_AREAS),
    ("49", DE_AREAS),
    ("33", FR_AREAS),
    ("81", JP_AREAS),
    ("64", NZ_AREAS),
];
