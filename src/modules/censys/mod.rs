//! Censys host search. Key-gated; requires `HUNTSMAN_CENSYS_ID`
//! (API ID) + `HUNTSMAN_CENSYS_SECRET` (API secret).
//!
//! Endpoint: `GET https://search.censys.io/api/v2/hosts/{ip}`
//! Auth:     HTTP Basic (`api_id:api_secret`)
//!
//! Surfaces open ports, service names, transport protocols, geographic
//! coordinates, ASN/organisation, reverse-DNS names, and host labels.

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

use types::{CensysResp, HostResult};

const ID_ENV: &str = "HUNTSMAN_CENSYS_ID";
const SECRET_ENV: &str = "HUNTSMAN_CENSYS_SECRET";
const SRC: &str = "censys";

pub struct Censys;

/// Build the [`ModuleResult`] from a parsed [`HostResult`].
///
/// Extracted so unit tests can exercise entity-building without HTTP.
fn build_entities(host: HostResult, ip: &str, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();

    // ── IP entity with service evidence ─────────────────────────
    if !host.services.is_empty() {
        let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.90, scan_id);
        entity.tag("censys");

        // Apply host-level labels as censys:-prefixed tags.
        for label in &host.labels {
            entity.tag(format!("censys:{label}"));
        }

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
                // Prefer extended_service_name when available.
                let ext = s.extended_service_name.as_deref().unwrap_or(name);
                Some(format!("{port}/{proto} {ext}"))
            })
            .collect();

        let protocols: Vec<&str> = host
            .services
            .iter()
            .filter_map(|s| s.transport_protocol.as_deref())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // Collect software across all services.
        let software_strs: Vec<String> = host
            .services
            .iter()
            .flat_map(|s| s.software.iter())
            .filter_map(|sw| {
                let product = sw.product.as_deref()?;
                if let Some(ver) = sw.version.as_deref() {
                    Some(format!("{product}/{ver}"))
                } else {
                    Some(product.to_owned())
                }
            })
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
        if !software_strs.is_empty() {
            let mut sorted = software_strs;
            sorted.sort_unstable();
            ev = ev.with_attr("software", sorted.join(", "));
        }

        // Censys-assigned per-service labels (e.g. "remote-access", "database",
        // "tls") — deduplicated across services, a quick attack-surface tag set.
        let mut svc_labels: Vec<&str> = host
            .services
            .iter()
            .flat_map(|s| s.labels.iter())
            .map(String::as_str)
            .filter(|l| !l.is_empty())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        if !svc_labels.is_empty() {
            svc_labels.sort_unstable();
            ev = ev.with_attr("service_labels", svc_labels.join(","));
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
        let mut geo = Entity::new(EntityKind::Coordinates, &coord_str, 0.65, scan_id);
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
            let mut ae = Entity::new(EntityKind::Address, &addr, 0.60, scan_id);
            ae.tag("censys");
            ae.tag("geoint");
            ae.add_evidence(Evidence::new(SRC, format!("Censys location for {ip}")));
            result.push(ae);
        }
    }

    // ── ASN + Organisation entities ──────────────────────────────
    if let Some(asys) = &host.autonomous_system {
        if let Some(asn_num) = asys.asn {
            let asn_val = format!("AS{asn_num}");
            let mut asn_entity = Entity::new(EntityKind::Asn, &asn_val, 0.80, scan_id);
            asn_entity.tag("censys");
            if let Some(cc) = asys.country_code.as_deref() {
                asn_entity.tag(format!("country:{}", cc.to_uppercase()));
            }

            let mut ev = Evidence::new(SRC, format!("Censys ASN for {ip}: {asn_val}"))
                .with_attr("asn", asn_val.clone());
            if let Some(prefix) = asys.bgp_prefix.as_deref() {
                ev = ev.with_attr("bgp_prefix", prefix);
            }
            if let Some(name) = asys.name.as_deref() {
                ev = ev.with_attr("as_name", name);
            }
            if let Some(desc) = asys.description.as_deref() {
                ev = ev.with_attr("description", desc);
            }
            asn_entity.add_evidence(ev);
            result.push(asn_entity);
        }

        // Organisation from AS name or description.
        let org_name = asys
            .name
            .as_deref()
            .or(asys.description.as_deref())
            .unwrap_or("")
            .trim();
        if !org_name.is_empty() {
            let mut org = Entity::new(EntityKind::Organisation, org_name, 0.70, scan_id);
            org.tag("censys");
            org.add_evidence(
                Evidence::new(SRC, format!("Censys AS organisation for {ip}"))
                    .with_attr("source", "autonomous_system"),
            );
            result.push(org);
        }
    }

    // ── Reverse-DNS → Domain entities ───────────────────────────
    if let Some(dns) = &host.dns
        && let Some(rdns) = &dns.reverse_dns
    {
        for name in &rdns.names {
            let name = name.trim().trim_end_matches('.');
            if name.is_empty() {
                continue;
            }
            let mut dom = Entity::new(EntityKind::Domain, name, 0.75, scan_id);
            dom.tag("censys");
            dom.tag("ptr");
            dom.add_evidence(
                Evidence::new(SRC, format!("Censys reverse-DNS for {ip}: {name}"))
                    .with_attr("ip", ip),
            );
            result.push(dom);
        }
    }

    result
}

#[async_trait]
impl Module for Censys {
    fn name(&self) -> &'static str {
        "censys"
    }
    fn description(&self) -> &'static str {
        "Censys host search: open ports, services, ASN, reverse-DNS, and location data"
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
        // Censys host search corroborates the IP, emits coordinates / address,
        // ASN, organisation, and reverse-DNS domain pivots.
        const KINDS: &[EntityKind] = &[
            EntityKind::IpAddress,
            EntityKind::Coordinates,
            EntityKind::Address,
            EntityKind::Domain,
            EntityKind::Asn,
            EntityKind::Organisation,
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

        if host.services.is_empty()
            && host.location.is_none()
            && host.autonomous_system.is_none()
            && host.dns.is_none()
            && host.labels.is_empty()
        {
            return Ok(ModuleResult::new());
        }

        Ok(build_entities(host, ip, &ctx.scan_id))
    }
}
