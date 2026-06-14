//! Censys host search. Key-gated; requires `HUNTSMAN_CENSYS_ID`
//! (API ID) + `HUNTSMAN_CENSYS_SECRET` (API secret).
//!
//! Endpoint: `GET https://search.censys.io/api/v2/hosts/{ip}`
//! Auth:     HTTP Basic (`api_id:api_secret`)
//!
//! Surfaces open ports, service names, transport protocols, and
//! geographic coordinates when the API reports location data.

#[cfg(test)]
mod tests;
mod types;

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::geo::is_valid_coords;
use crate::util::http::RequestBuilderExt;
use crate::util::http::{handle_keyed_error, urlencode};

use types::CensysResp;

const ID_ENV: &str = "HUNTSMAN_CENSYS_ID";
const SECRET_ENV: &str = "HUNTSMAN_CENSYS_SECRET";
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
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }
    fn attack_techniques(&self) -> &'static [&'static str] {
        // Censys host search is a scan/exposure database (T1596.005, alongside
        // T1590.005 IP Addresses — the Infrastructure default) that also emits
        // the host's data-centre coordinates + city/region as physical-location
        // entities (T1591.001). Superset of the default — coverage cannot regress.
        &["T1590.005", "T1596.005", "T1591.001"]
    }
    fn produces(&self) -> &'static [EntityKind] {
        // Censys host search corroborates the IP and emits the host's
        // Coordinates (data-centre lat/lon) and city/region/country
        // as Address.
        const KINDS: &[EntityKind] = &[
            EntityKind::IpAddress,
            EntityKind::Coordinates,
            EntityKind::Address,
        ];
        KINDS
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
                .send_tagged(SRC)
                .await?;

            let status = resp.status();

            // Unknown host returns 404 — not an error, just no data.
            if status.as_u16() == 404 {
                return Ok(ModuleResult::new());
            }

            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, SRC, api_id, ctx).await {
                    continue;
                }
                return Err(crate::util::http::http_status_error("censys", resp).await);
            }

            break crate::util::http::json_decode(SRC, resp).await?;
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
                SRC,
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
            // Shared validator: finite + in-range + not-Null-Island. Censys
            // (and data-centre geo APIs generally) emit 0,0 as an
            // "unknown location" placeholder, which the prior range-only
            // check let through as a false Coordinates entity.
            && is_valid_coords(lat, lon)
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
            ev = [
                ("country", loc.country.as_deref()),
                ("country_code", loc.country_code.as_deref()),
                ("city", loc.city.as_deref()),
                ("province", loc.province.as_deref()),
            ]
            .into_iter()
            .filter_map(|(k, v)| v.map(|val| (k, val)))
            .fold(ev, |ev, (k, val)| ev.with_attr(k, val));

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
