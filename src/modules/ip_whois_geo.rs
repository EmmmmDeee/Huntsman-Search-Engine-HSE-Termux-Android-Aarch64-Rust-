//! ipwho.is IP geolocation — free, HTTPS, no API key.
//!
//! Second-source geo module alongside `ip_geo` (ip-api.com, HTTP-only).
//! Having two independent geo sources on the same IP lets the AU-014
//! geolocation-cluster correlation rule fire, corroborating the location.
//!
//! Endpoint: `GET https://ipwho.is/{ip}`
//! Returns JSON with lat, lon, country, city, region, ISP, ASN, timezone.
//! No rate limit documented; we keep requests reasonable via the engine's
//! per-module timeout and inter-module throttle.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::geo::is_valid_coords;
use crate::util::http::fetch_json;

const SRC: &str = "ip_whois_geo";

pub struct IpWhois;

#[derive(Deserialize)]
struct Resp {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    postal: Option<String>,
    #[serde(default)]
    timezone_id: Option<String>,
    #[serde(default)]
    connection: Option<Connection>,
}

#[derive(Deserialize)]
struct Connection {
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default, rename = "asn")]
    asn_num: Option<u64>,
}

#[async_trait]
impl Module for IpWhois {
    fn name(&self) -> &'static str {
        "ip_whois_geo"
    }

    fn description(&self) -> &'static str {
        "HTTPS IP geolocation via ipwho.is (second source for geo-cluster correlation)"
    }

    fn priority(&self) -> u8 {
        27
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Address,
            EntityKind::Asn,
            EntityKind::Coordinates,
            EntityKind::Organisation,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Single network request with no per-request timeout; the 3s default
        // would kill a slow-but-connected response as a spurious "timeout".
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let url = format!("https://ipwho.is/{}", target.value);
        let data: Resp = fetch_json(&ctx.http, SRC, &url).await?;

        if data.success == Some(false) {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        if let (Some(lat), Some(lon)) = (data.latitude, data.longitude) {
            // Shared validator: rejects Null Island AND out-of-range / non-finite
            // values a malformed ipwho.is payload could carry (see util::geo).
            if !is_valid_coords(lat, lon) {
                return Ok(result);
            }

            let coords = format!("{lat:.6},{lon:.6}");
            // Confidence recalibrated 0.68 → 0.55 — WHOIS-based geo is
            // particularly coarse (registrar address, not host
            // location) so this provider should rank below the
            // residential-DB-backed IP-geo modules.
            let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.55, &ctx.scan_id);
            e.tag("geoint");
            if let Some(cc) = data.country_code.as_deref() {
                e.tag(format!("country:{}", cc.to_uppercase()));
            }

            let mut ev = Evidence::new(SRC, format!("IP geolocation for {}", target.value))
                .with_attr("latitude", lat.to_string())
                .with_attr("longitude", lon.to_string())
                .with_attr("source", "ipwho.is");

            if let Some(c) = data.country.as_deref() {
                ev = ev.with_attr("country", c);
            }
            if let Some(cc) = data.country_code.as_deref() {
                ev = ev.with_attr("country_code", cc);
            }
            if let Some(r) = data.region.as_deref() {
                ev = ev.with_attr("region", r);
            }
            if let Some(c) = data.city.as_deref() {
                ev = ev.with_attr("city", c);
            }
            if let Some(p) = data.postal.as_deref() {
                ev = ev.with_attr("postal", p);
            }
            if let Some(tz) = data.timezone_id.as_deref() {
                ev = ev.with_attr("timezone", tz);
            }
            if let Some(conn) = &data.connection {
                if let Some(isp) = conn.isp.as_deref() {
                    ev = ev.with_attr("isp", isp);
                }
                if let Some(asn) = conn.asn_num {
                    ev = ev.with_attr("asn", format!("AS{asn}"));
                }
                if let Some(org) = conn.org.as_deref() {
                    ev = ev.with_attr("org", org);
                }
            }

            e.add_evidence(ev);
            result.push(e);

            // Synthesize an Address entity from the city/region/country
            // so expansion can chain into forward_geocode without an
            // extra API call.
            let parts: Vec<&str> = [
                data.city.as_deref(),
                data.region.as_deref(),
                data.country.as_deref(),
            ]
            .iter()
            .filter_map(|p| *p)
            .filter(|p| !p.is_empty())
            .collect();

            if parts.len() >= 2 {
                let addr_str = parts.join(", ");
                let mut addr = Entity::new(EntityKind::Address, &addr_str, 0.50, &ctx.scan_id);
                addr.tag("geoint");
                addr.tag("derived");
                addr.add_evidence(
                    Evidence::new(
                        "ip_whois_geo",
                        format!("Address derived from IP geo for {}", target.value),
                    )
                    .with_attr("source", "ipwho.is"),
                );
                result.push(addr);
            }
        }

        if let Some(conn) = &data.connection
            && let Some(org) = &conn.org
            && !org.is_empty()
        {
            let mut e = Entity::new(EntityKind::Organisation, org, 0.60, &ctx.scan_id);
            let mut ev = Evidence::new(SRC, format!("IP org for {}", target.value));
            if let Some(asn) = conn.asn_num {
                ev = ev.with_attr("asn", format!("AS{asn}"));
            }
            if let Some(isp) = conn.isp.as_deref() {
                ev = ev.with_attr("isp", isp);
            }
            e.add_evidence(ev);
            result.push(e);
        }

        if let Some(conn) = &data.connection
            && let Some(asn) = conn.asn_num
        {
            let asn_str = format!("AS{asn}");
            let mut ae = Entity::new(EntityKind::Asn, &asn_str, 0.80, &ctx.scan_id);
            ae.tag("ip-whois");
            ae.add_evidence(Evidence::new(SRC, format!("ASN for {}", target.value)));
            result.push(ae);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ip_only() {
        let m = IpWhois;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }

    #[test]
    fn name_and_description() {
        let m = IpWhois;
        assert_eq!(m.name(), "ip_whois_geo");
        assert!(!m.description().is_empty());
    }

    #[test]
    fn priority_below_ip_geo() {
        assert!(IpWhois.priority() < 28, "should run after ip_geo (28)");
    }

    #[test]
    fn resp_deserializes_success() {
        let json = r#"{
            "success": true,
            "ip": "1.1.1.1",
            "country": "Australia",
            "country_code": "AU",
            "region": "Queensland",
            "city": "South Brisbane",
            "latitude": -27.4766,
            "longitude": 153.0166,
            "postal": "4101",
            "timezone_id": "Australia/Brisbane",
            "connection": {
                "isp": "Cloudflare Inc",
                "org": "APNIC Research",
                "asn": 13335,
                "domain": "cloudflare.com"
            }
        }"#;
        let r: Resp = serde_json::from_str(json).unwrap();
        assert_eq!(r.success, Some(true));
        assert!((r.latitude.unwrap() - (-27.4766)).abs() < 0.001);
        assert!((r.longitude.unwrap() - 153.0166).abs() < 0.001);
        assert_eq!(r.city.as_deref(), Some("South Brisbane"));
        assert_eq!(r.connection.as_ref().unwrap().asn_num, Some(13335));
    }

    #[test]
    fn resp_deserializes_failure() {
        let json = r#"{"success": false, "message": "Invalid IP address"}"#;
        let r: Resp = serde_json::from_str(json).unwrap();
        assert_eq!(r.success, Some(false));
        assert!(r.latitude.is_none());
    }

    #[test]
    fn resp_tolerates_missing_fields() {
        let json = r#"{"success": true, "latitude": 0.0, "longitude": 0.0}"#;
        let r: Resp = serde_json::from_str(json).unwrap();
        assert_eq!(r.success, Some(true));
        assert!(r.connection.is_none());
        assert!(r.city.is_none());
    }
}
