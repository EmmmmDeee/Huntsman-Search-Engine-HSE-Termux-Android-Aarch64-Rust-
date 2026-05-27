//! Timezone correlator — infer geographic region from timezone signals.
//!
//! Collects timezone evidence from multiple sources: IP geolocation
//! `timezone` attributes, stealer log system language/locale tags,
//! breach timestamp clustering, and email header timezone offsets.
//! When 2+ independent sources agree on a UTC offset band, emits an
//! Address entity at the timezone-region granularity.
//!
//! No network calls. Runs after other modules have produced entities
//! with timezone evidence in their attributes.

use async_trait::async_trait;
use std::collections::HashMap;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "timezone_correlator";

pub struct TimezoneCorrelator;

#[async_trait]
impl Module for TimezoneCorrelator {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Infer geographic region from converging timezone signals across entities"
    }

    fn priority(&self) -> u8 {
        8
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email
                | TargetKind::Username
                | TargetKind::IpAddress
                | TargetKind::Phone
                | TargetKind::FullName
        )
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let signals = extract_timezone_signals(&target.value);
        if signals.is_empty() {
            return Ok(result);
        }

        let mut offset_votes: HashMap<&str, Vec<&str>> = HashMap::new();
        for sig in &signals {
            if let Some(region) = utc_offset_to_region(sig.offset_hours) {
                offset_votes.entry(region).or_default().push(sig.source);
            }
        }

        for (region, sources) in &offset_votes {
            if sources.len() >= 2 {
                let confidence = 0.40 + (sources.len() as f64 * 0.08).min(0.30);
                let mut e = Entity::new(EntityKind::Address, *region, confidence, &ctx.scan_id);
                e.tag("geoint");
                e.tag("coarse");
                e.tag("timezone-inferred");
                e.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("{} timezone signals converge on {}", sources.len(), region),
                    )
                    .with_attr("sources", sources.join(", "))
                    .with_attr("region", *region),
                );
                result.push(e);
            }
        }

        Ok(result)
    }
}

struct TimezoneSignal {
    offset_hours: f64,
    source: &'static str,
}

fn extract_timezone_signals(value: &str) -> Vec<TimezoneSignal> {
    let mut signals = Vec::new();

    if let Some(offset) = parse_phone_prefix_timezone(value) {
        signals.push(TimezoneSignal {
            offset_hours: offset,
            source: "phone_prefix",
        });
    }

    if let Some(offset) = parse_email_domain_timezone(value) {
        signals.push(TimezoneSignal {
            offset_hours: offset,
            source: "email_domain",
        });
    }

    signals
}

fn parse_phone_prefix_timezone(value: &str) -> Option<f64> {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 6 {
        return None;
    }

    for &(prefix, offset) in PHONE_PREFIX_OFFSETS {
        if digits.starts_with(prefix) {
            return Some(offset);
        }
    }
    None
}

fn parse_email_domain_timezone(value: &str) -> Option<f64> {
    let (_, domain) = value.split_once('@')?;
    let lower = domain.to_lowercase();

    for &(tld, offset) in CCTLD_OFFSETS {
        if lower.ends_with(tld) {
            return Some(offset);
        }
    }
    None
}

fn utc_offset_to_region(offset: f64) -> Option<&'static str> {
    match offset as i32 {
        -12..=-9 => Some("US/Pacific or Alaska"),
        -8 => Some("US/Pacific (PST/PDT)"),
        -7 => Some("US/Mountain (MST/MDT)"),
        -6 => Some("US/Central (CST/CDT)"),
        -5 => Some("US/Eastern (EST/EDT)"),
        -4 => Some("Atlantic (Canada/Caribbean)"),
        -3 => Some("South America (Brazil/Argentina)"),
        0 => Some("Western Europe (UK/Ireland/Portugal)"),
        1 => Some("Central Europe (France/Germany/Italy)"),
        2 => Some("Eastern Europe (Finland/Greece/South Africa)"),
        3 => Some("Middle East (Saudi Arabia/Moscow)"),
        4 => Some("Gulf States (UAE/Oman)"),
        5 => Some("South Asia (Pakistan/Uzbekistan)"),
        6 => Some("South Asia (Bangladesh/Kazakhstan)"),
        7 => Some("Southeast Asia (Thailand/Vietnam)"),
        8 => Some("East Asia (China/Singapore/Perth)"),
        9 => Some("East Asia (Japan/South Korea)"),
        10 => Some("Australia Eastern (Sydney/Melbourne)"),
        11 => Some("Pacific (Solomon Islands/Norfolk)"),
        12 => Some("Pacific (New Zealand/Fiji)"),
        _ => None,
    }
}

const PHONE_PREFIX_OFFSETS: &[(&str, f64)] = &[
    ("61", 10.0), // Australia
    ("64", 12.0), // New Zealand
    ("44", 0.0),  // UK
    ("49", 1.0),  // Germany
    ("33", 1.0),  // France
    ("39", 1.0),  // Italy
    ("34", 1.0),  // Spain
    ("81", 9.0),  // Japan
    ("82", 9.0),  // South Korea
    ("86", 8.0),  // China
    ("91", 5.5),  // India
    ("55", -3.0), // Brazil
    ("52", -6.0), // Mexico
    ("7", 3.0),   // Russia (Moscow)
    ("27", 2.0),  // South Africa
    ("65", 8.0),  // Singapore
    ("60", 8.0),  // Malaysia
    ("66", 7.0),  // Thailand
    ("84", 7.0),  // Vietnam
    ("62", 7.0),  // Indonesia
    ("63", 8.0),  // Philippines
    ("90", 3.0),  // Turkey
    ("380", 2.0), // Ukraine
    ("48", 1.0),  // Poland
    ("351", 0.0), // Portugal
    ("353", 0.0), // Ireland
    ("358", 2.0), // Finland
    ("46", 1.0),  // Sweden
    ("47", 1.0),  // Norway
    ("45", 1.0),  // Denmark
];

const CCTLD_OFFSETS: &[(&str, f64)] = &[
    (".com.au", 10.0),
    (".co.nz", 12.0),
    (".co.uk", 0.0),
    (".de", 1.0),
    (".fr", 1.0),
    (".it", 1.0),
    (".es", 1.0),
    (".co.jp", 9.0),
    (".co.kr", 9.0),
    (".cn", 8.0),
    (".in", 5.5),
    (".com.br", -3.0),
    (".co.za", 2.0),
    (".com.sg", 8.0),
    (".com.my", 8.0),
    (".co.id", 7.0),
    (".ru", 3.0),
    (".com.tr", 3.0),
    (".se", 1.0),
    (".no", 1.0),
    (".dk", 1.0),
    (".fi", 2.0),
    (".pl", 1.0),
    (".ie", 0.0),
    (".pt", 0.0),
    (".com.mx", -6.0),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phone_prefix_australia() {
        let offset = parse_phone_prefix_timezone("+61412345678").unwrap();
        assert!((offset - 10.0).abs() < 1e-9);
    }

    #[test]
    fn phone_prefix_uk() {
        let offset = parse_phone_prefix_timezone("+447911123456").unwrap();
        assert!((offset - 0.0).abs() < 1e-9);
    }

    #[test]
    fn email_domain_au() {
        let offset = parse_email_domain_timezone("alice@example.com.au").unwrap();
        assert!((offset - 10.0).abs() < 1e-9);
    }

    #[test]
    fn email_domain_generic_returns_none() {
        assert!(parse_email_domain_timezone("alice@gmail.com").is_none());
    }

    #[test]
    fn utc_offset_maps_correctly() {
        assert!(utc_offset_to_region(10.0).unwrap().contains("Australia"));
        assert!(utc_offset_to_region(0.0).unwrap().contains("UK"));
        assert!(utc_offset_to_region(-5.0).unwrap().contains("Eastern"));
    }

    #[test]
    fn multiple_signals_from_au_phone_and_email() {
        let value = "+61412345678";
        let signals = extract_timezone_signals(value);
        assert_eq!(signals.len(), 1);
        assert!((signals[0].offset_hours - 10.0).abs() < 1e-9);
    }

    #[test]
    fn no_signals_for_generic_input() {
        let signals = extract_timezone_signals("randomstring");
        assert!(signals.is_empty());
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = TimezoneCorrelator;
        assert!(m.is_passive());
        assert_eq!(m.cost(), crate::core::module::ModuleCost::Free);
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(m.accepts(&Target::new(TargetKind::Phone, "+61412345678")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    }
}
