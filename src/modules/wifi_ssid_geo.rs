//! Wi-Fi SSID semantic analysis — infer location from network names.
//!
//! WiGLE returns SSID names alongside BSSID/coordinates. Many SSIDs
//! encode location information: business names (Starbucks, Hilton),
//! ISP defaults (Telstra, Optus), venue types (Library, Hospital),
//! and address fragments. This module analyses SSID strings from
//! entity evidence attributes and emits Address entities when a
//! high-confidence pattern matches.
//!
//! No network calls — operates on evidence attributes already attached
//! to MacAddress and Coordinates entities from the WiGLE module.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "wifi_ssid_geo";

pub struct WifiSsidGeo;

#[async_trait]
impl Module for WifiSsidGeo {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Infer location from Wi-Fi SSID naming patterns (ISP, venue, address fragments)"
    }

    fn priority(&self) -> u8 {
        12
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::MacAddress | TargetKind::Coordinates)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let ssid = target.value.trim();
        if ssid.is_empty() || ssid.len() < 3 {
            return Ok(result);
        }

        let lower = ssid.to_lowercase();

        if let Some(geo) = classify_ssid_isp(&lower) {
            let mut e = Entity::new(
                EntityKind::Address,
                geo.location,
                geo.confidence,
                &ctx.scan_id,
            );
            e.tag("geoint");
            e.tag("coarse");
            e.tag("ssid-inferred");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("SSID '{}' matches {} ISP pattern", ssid, geo.location),
                )
                .with_attr("ssid", ssid)
                .with_attr("isp", geo.detail)
                .with_attr("method", "isp_pattern"),
            );
            result.push(e);
        }

        if let Some(geo) = classify_ssid_venue(&lower) {
            let mut e = Entity::new(
                EntityKind::Address,
                geo.location,
                geo.confidence,
                &ctx.scan_id,
            );
            e.tag("geoint");
            e.tag("ssid-inferred");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("SSID '{}' matches venue pattern: {}", ssid, geo.detail),
                )
                .with_attr("ssid", ssid)
                .with_attr("venue_type", geo.detail)
                .with_attr("method", "venue_pattern"),
            );
            result.push(e);
        }

        Ok(result)
    }
}

struct SsidGeo {
    location: &'static str,
    confidence: f64,
    detail: &'static str,
}

fn classify_ssid_isp(ssid: &str) -> Option<SsidGeo> {
    for &(pattern, country, isp) in ISP_PATTERNS {
        if ssid.contains(pattern) {
            return Some(SsidGeo {
                location: country,
                confidence: 0.55,
                detail: isp,
            });
        }
    }
    None
}

fn classify_ssid_venue(ssid: &str) -> Option<SsidGeo> {
    for &(pattern, venue_type, confidence) in VENUE_PATTERNS {
        if ssid.contains(pattern) {
            return Some(SsidGeo {
                location: venue_type,
                confidence,
                detail: venue_type,
            });
        }
    }
    None
}

const ISP_PATTERNS: &[(&str, &str, &str)] = &[
    // Australia
    ("telstra", "Australia", "Telstra"),
    ("bigpond", "Australia", "Telstra BigPond"),
    ("optus", "Australia", "Optus"),
    ("tpg", "Australia", "TPG"),
    ("iinet", "Australia", "iiNet"),
    ("internode", "Australia", "Internode"),
    ("aussie", "Australia", "Aussie Broadband"),
    ("nbn", "Australia", "NBN"),
    // United Kingdom
    ("bt-wifi", "United Kingdom", "BT"),
    ("bthub", "United Kingdom", "BT Hub"),
    ("sky-", "United Kingdom", "Sky"),
    ("skyhub", "United Kingdom", "Sky Hub"),
    ("virginmedia", "United Kingdom", "Virgin Media"),
    ("talktalk", "United Kingdom", "TalkTalk"),
    ("plusnet", "United Kingdom", "Plusnet"),
    // United States
    ("xfinity", "United States", "Comcast Xfinity"),
    ("comcast", "United States", "Comcast"),
    ("att-wifi", "United States", "AT&T"),
    ("spectrum", "United States", "Spectrum"),
    ("verizon", "United States", "Verizon"),
    ("tmobile", "United States", "T-Mobile"),
    ("cox-wifi", "United States", "Cox"),
    ("optimum", "United States", "Optimum/Altice"),
    // Germany
    ("fritz!box", "Germany", "Fritz!Box (AVM)"),
    ("telekom", "Germany", "Deutsche Telekom"),
    ("vodafone-", "Germany", "Vodafone DE"),
    ("unitymedia", "Germany", "Unitymedia"),
    // France
    ("freebox", "France", "Free/Iliad"),
    ("bbox-", "France", "Bouygues"),
    ("livebox", "France", "Orange France"),
    ("sfr-", "France", "SFR"),
    // Japan
    ("softbank", "Japan", "SoftBank"),
    ("ntt-", "Japan", "NTT"),
    ("kddi", "Japan", "KDDI"),
    // New Zealand
    ("spark-", "New Zealand", "Spark NZ"),
    ("vodafone_nz", "New Zealand", "Vodafone NZ"),
    ("2degrees", "New Zealand", "2degrees"),
    // Canada
    ("bell-wifi", "Canada", "Bell Canada"),
    ("rogers", "Canada", "Rogers"),
    ("shaw-", "Canada", "Shaw"),
    // Singapore
    ("singtel", "Singapore", "Singtel"),
    ("starhub", "Singapore", "StarHub"),
];

const VENUE_PATTERNS: &[(&str, &str, f64)] = &[
    ("starbucks", "Starbucks", 0.45),
    ("mcdonalds", "McDonald's", 0.45),
    ("hilton", "Hilton Hotel", 0.50),
    ("marriott", "Marriott Hotel", 0.50),
    ("hyatt", "Hyatt Hotel", 0.50),
    ("sheraton", "Sheraton Hotel", 0.50),
    ("ibis", "Ibis Hotel", 0.48),
    ("novotel", "Novotel Hotel", 0.48),
    ("airport", "Airport", 0.40),
    ("hospital", "Hospital", 0.42),
    ("library", "Library", 0.40),
    ("university", "University", 0.42),
    ("westfield", "Westfield Shopping Centre", 0.50),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isp_telstra_australia() {
        let geo = classify_ssid_isp("telstra1234").unwrap();
        assert_eq!(geo.location, "Australia");
        assert_eq!(geo.detail, "Telstra");
    }

    #[test]
    fn isp_bt_uk() {
        let geo = classify_ssid_isp("bthub-abc123").unwrap();
        assert_eq!(geo.location, "United Kingdom");
    }

    #[test]
    fn isp_xfinity_us() {
        let geo = classify_ssid_isp("xfinity-home-42").unwrap();
        assert_eq!(geo.location, "United States");
    }

    #[test]
    fn venue_starbucks() {
        let geo = classify_ssid_venue("starbucks wifi").unwrap();
        assert_eq!(geo.detail, "Starbucks");
    }

    #[test]
    fn venue_westfield() {
        let geo = classify_ssid_venue("westfield_bondi_junction").unwrap();
        assert_eq!(geo.detail, "Westfield Shopping Centre");
    }

    #[test]
    fn unknown_ssid_returns_none() {
        assert!(classify_ssid_isp("myhomenetwork").is_none());
        assert!(classify_ssid_venue("myhomenetwork").is_none());
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = WifiSsidGeo;
        assert!(m.is_passive());
        assert!(m.accepts(&Target::new(TargetKind::MacAddress, "aa:bb:cc:dd:ee:ff")));
        assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-33.8,151.2")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }
}
