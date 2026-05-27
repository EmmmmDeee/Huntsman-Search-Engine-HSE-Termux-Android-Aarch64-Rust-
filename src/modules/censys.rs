//! Censys host search. Key-gated; requires `HUNTSMAN_CENSYS_ID`
//! (API ID) + `HUNTSMAN_CENSYS_SECRET` (API secret).
//!
//! Endpoint: `GET https://search.censys.io/api/v2/hosts/{ip}`
//! Auth:     HTTP Basic (`api_id:api_secret`)
//!
//! Surfaces open ports, service names, transport protocols, and
//! geographic coordinates when the API reports location data.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{error_snippet, handle_keyed_error, urlencode};

const ID_ENV: &str = "HUNTSMAN_CENSYS_ID";
const SECRET_ENV: &str = "HUNTSMAN_CENSYS_SECRET";

// ── API response types ──────────────────────────────────────────────

#[derive(Deserialize)]
struct CensysResp {
    #[serde(default)]
    result: Option<HostResult>,
}

#[derive(Deserialize)]
struct HostResult {
    #[serde(default)]
    services: Vec<Service>,
    #[serde(default)]
    location: Option<Location>,
}

#[derive(Deserialize)]
struct Service {
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    service_name: Option<String>,
    #[serde(default)]
    transport_protocol: Option<String>,
}

#[derive(Deserialize)]
struct Location {
    #[serde(default)]
    coordinates: Option<Coordinates>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    province: Option<String>,
}

#[derive(Deserialize)]
struct Coordinates {
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
}

// ── Module impl ─────────────────────────────────────────────────────

const SRC: &str = "censys";

pub struct Censys;

#[async_trait]
impl Module for Censys {
    fn name(&self) -> &'static str {
        "censys"
    }
    fn description(&self) -> &'static str {
        "Censys host search: open ports, services, and location data"
    }
    fn priority(&self) -> u8 {
        35
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let api_id = match ctx.key_opt(ID_ENV) {
            Some(v) => v,
            None => return Ok(ModuleResult::new()),
        };
        let api_secret = match ctx.key_opt(SECRET_ENV) {
            Some(v) => v,
            None => return Ok(ModuleResult::new()),
        };

        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://search.censys.io/api/v2/hosts/{}", urlencode(ip),);
        let mut retries = 2u8;
        let body: CensysResp = loop {
            let resp = ctx
                .http
                .get(&url)
                .basic_auth(api_id, Some(api_secret))
                .header("Accept", "application/json")
                .send()
                .await
                .map_err(|e| Error::module("censys", e.to_string()))?;

            let status = resp.status();

            // Unknown host returns 404 — not an error, just no data.
            if status.as_u16() == 404 {
                return Ok(ModuleResult::new());
            }

            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, "censys", api_id, ctx).await {
                    continue;
                }
                return Err(Error::module(
                    "censys",
                    format!("HTTP {status}: {}", error_snippet(resp).await),
                ));
            }

            break resp
                .json()
                .await
                .map_err(|e| Error::module("censys", e.to_string()))?;
        };

        let host = match body.result {
            Some(r) => r,
            None => return Ok(ModuleResult::new()),
        };

        if host.services.is_empty() && host.location.is_none() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        // ── IP entity with service evidence ─────────────────────────
        if !host.services.is_empty() {
            let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.90, &ctx.scan_id);
            entity.tag("censys");

            let mut ports: Vec<u16> = host.services.iter().filter_map(|s| s.port).collect();
            ports.sort_unstable();
            ports.dedup();

            let services: Vec<String> = host
                .services
                .iter()
                .filter_map(|s| {
                    let port = s.port?;
                    let name = s.service_name.as_deref().unwrap_or("unknown");
                    let proto = s.transport_protocol.as_deref().unwrap_or("tcp");
                    Some(format!("{port}/{proto} {name}"))
                })
                .collect();

            let protocols: Vec<&str> = host
                .services
                .iter()
                .filter_map(|s| s.transport_protocol.as_deref())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();

            let mut ev = Evidence::new(
                "censys",
                format!(
                    "Censys: {} port(s), {} service(s) on {ip}",
                    ports.len(),
                    host.services.len(),
                ),
            )
            .with_attr("port_count", ports.len().to_string())
            .with_attr(
                "ports",
                ports
                    .iter()
                    .take(20)
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );

            if !services.is_empty() {
                ev = ev.with_attr(
                    "services",
                    services
                        .iter()
                        .take(20)
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join("; "),
                );
            }
            if !protocols.is_empty() {
                let mut protos: Vec<&str> = protocols;
                protos.sort_unstable();
                ev = ev.with_attr("protocols", protos.join(","));
            }

            entity.add_evidence(ev);
            result.push(entity);
        }

        // ── Coordinates entity (geoint) ─────────────────────────────
        if let Some(loc) = &host.location
            && let Some(coords) = &loc.coordinates
            && let (Some(lat), Some(lon)) = (coords.latitude, coords.longitude)
            && (-90.0..=90.0).contains(&lat)
            && (-180.0..=180.0).contains(&lon)
        {
            let coord_str = format!("{lat:.6},{lon:.6}");
            let mut geo = Entity::new(EntityKind::Coordinates, &coord_str, 0.65, &ctx.scan_id);
            geo.tag("geoint");
            geo.tag("censys");
            if let Some(cc) = loc.country_code.as_deref() {
                geo.tag(format!("country:{}", cc.to_uppercase()));
            }

            let mut ev = Evidence::new(SRC, format!("Censys geolocation for {ip}"))
                .with_attr("latitude", lat.to_string())
                .with_attr("longitude", lon.to_string())
                .with_attr("source", "censys");
            if let Some(c) = loc.country.as_deref() {
                ev = ev.with_attr("country", c);
            }
            if let Some(cc) = loc.country_code.as_deref() {
                ev = ev.with_attr("country_code", cc);
            }
            if let Some(city) = loc.city.as_deref() {
                ev = ev.with_attr("city", city);
            }
            if let Some(prov) = loc.province.as_deref() {
                ev = ev.with_attr("province", prov);
            }

            geo.add_evidence(ev);
            result.push(geo);

            let city = loc.city.as_deref().unwrap_or("");
            let province = loc.province.as_deref().unwrap_or("");
            let country = loc.country.as_deref().unwrap_or("");
            if !city.is_empty() && !country.is_empty() {
                let addr = if !province.is_empty() {
                    format!("{city}, {province}, {country}")
                } else {
                    format!("{city}, {country}")
                };
                let mut ae = Entity::new(EntityKind::Address, &addr, 0.60, &ctx.scan_id);
                ae.tag("censys");
                ae.tag("geoint");
                ae.add_evidence(Evidence::new(SRC, format!("Censys location for {ip}")));
                result.push(ae);
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ip_only() {
        let m = Censys;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "user")));
    }

    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(Censys.cost(), ModuleCost::KeyGated));
    }

    #[test]
    fn module_metadata() {
        let m = Censys;
        assert_eq!(m.name(), "censys");
        assert_eq!(m.priority(), 35);
        assert_eq!(m.max_timeout_ms(), 10_000);
        let desc = m.description();
        assert!(desc.contains("Censys"));
        assert!(desc.contains("port"));
    }

    #[test]
    fn deserialise_full_response() {
        let json = r#"{
            "result": {
                "services": [
                    {
                        "port": 80,
                        "service_name": "HTTP",
                        "transport_protocol": "TCP"
                    },
                    {
                        "port": 443,
                        "service_name": "HTTPS",
                        "transport_protocol": "TCP"
                    },
                    {
                        "port": 22,
                        "service_name": "SSH",
                        "transport_protocol": "TCP"
                    }
                ],
                "location": {
                    "coordinates": {
                        "latitude": -33.8688,
                        "longitude": 151.2093
                    },
                    "country": "Australia",
                    "country_code": "AU",
                    "city": "Sydney",
                    "province": "New South Wales"
                }
            }
        }"#;

        let resp: CensysResp = serde_json::from_str(json).unwrap();
        let host = resp.result.unwrap();
        assert_eq!(host.services.len(), 3);
        assert_eq!(host.services[0].port, Some(80));
        assert_eq!(host.services[0].service_name.as_deref(), Some("HTTP"));
        assert_eq!(host.services[0].transport_protocol.as_deref(), Some("TCP"));

        let loc = host.location.unwrap();
        assert_eq!(loc.country.as_deref(), Some("Australia"));
        assert_eq!(loc.country_code.as_deref(), Some("AU"));
        assert_eq!(loc.city.as_deref(), Some("Sydney"));
        let coords = loc.coordinates.unwrap();
        assert!((coords.latitude.unwrap() - (-33.8688)).abs() < 1e-4);
        assert!((coords.longitude.unwrap() - 151.2093).abs() < 1e-4);
    }

    #[test]
    fn deserialise_empty_result() {
        let json = r#"{ "result": { "services": [], "location": null } }"#;
        let resp: CensysResp = serde_json::from_str(json).unwrap();
        let host = resp.result.unwrap();
        assert!(host.services.is_empty());
        assert!(host.location.is_none());
    }

    #[test]
    fn deserialise_missing_fields() {
        let json = r#"{ "result": { "services": [{ "port": 53 }] } }"#;
        let resp: CensysResp = serde_json::from_str(json).unwrap();
        let host = resp.result.unwrap();
        assert_eq!(host.services.len(), 1);
        assert_eq!(host.services[0].port, Some(53));
        assert!(host.services[0].service_name.is_none());
        assert!(host.services[0].transport_protocol.is_none());
    }

    #[test]
    fn deserialise_no_result() {
        let json = r"{}";
        let resp: CensysResp = serde_json::from_str(json).unwrap();
        assert!(resp.result.is_none());
    }
}
