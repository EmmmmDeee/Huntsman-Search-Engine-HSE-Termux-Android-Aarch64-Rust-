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
    confidence,
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

#[async_trait]
impl Module for Censys {
    fn name(&self) -> &'static str {
        "censys"
    }
    fn description(&self) -> &'static str {
        "Censys host recon — surfaces open ports, running services, and location data"
    }
    fn priority(&self) -> u8 {
        78
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
        // entities (T1591.001) and the ASN operator as an Organisation
        // (T1591.002 Business Relationships). Superset of the default —
        // coverage cannot regress.
        &["T1590.005", "T1596.005", "T1591.001", "T1591.002"]
    }
    fn produces(&self) -> &'static [EntityKind] {
        // Censys host search corroborates the IP and emits the host's
        // Coordinates (data-centre lat/lon) and city/region/country as Address,
        // plus the announcing ASN, its network-operator Organisation, and the
        // reverse-DNS names as Domain pivots.
        const KINDS: &[EntityKind] = &[
            EntityKind::IpAddress,
            EntityKind::Coordinates,
            EntityKind::Address,
            EntityKind::Asn,
            EntityKind::Organisation,
            EntityKind::Domain,
        ];
        KINDS
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }
    fn cache_ttl_secs(&self) -> u64 {
        // Host scan/exposure data (open ports, services, geo) is the "IP
        // intel: 24h" bracket C9's design sketch names — stable within a day,
        // and censys is one of C9's own named motivating examples for the
        // inter-scan cache (finite paid query allowance).
        86_400
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let api_id = ctx.key(ID_ENV)?;
        let api_secret = ctx.key(SECRET_ENV)?;

        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://search.censys.io/api/v2/hosts/{}", urlencode(ip),);
        let mut retries = 2u8;
        let body: CensysResp = loop {
            if ctx.cancel.is_cancelled() {
                return Ok(ModuleResult::new());
            }
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

        let mut result = ModuleResult::new();
        result.entities = build_entities(&host, ip, &ctx.scan_id);
        Ok(result)
    }
}

/// Map a decoded Censys host record to its entities. **Pure** (no network/IO),
/// so the service→ports/protocols evidence and the location→Coordinates/Address
/// derivation are unit-testable directly off JSON fixtures.
///
/// | source                                  | output                              |
/// |-----------------------------------------|-------------------------------------|
/// | `services` (non-empty)                  | subject `IpAddress` (+ `censys`)    |
/// | `services[].port`/`name`/`proto`        | port/service/protocol evidence      |
/// | `location.coordinates` (valid)          | `Coordinates` (+ `geoint`/`censys`) |
/// | `location.country_code`                 | `country:<CC>` tag (uppercased)     |
/// | `location.city` + `country` (valid geo) | `Address` (+ `censys`/`geoint`)     |
/// | `autonomous_system.asn` (> 0)           | `Asn` (`AS<n>`, + `censys`)         |
/// | `autonomous_system.name`/`.description` | `Organisation` (+ `censys`)         |
/// | `dns.reverse_dns.names`                 | `Domain` pivots (+ `censys`/`ptr`)  |
///
/// Returns empty when the host carries neither services nor a location (the
/// caller previously short-circuited on this). The Coordinates AND the
/// city/country Address are BOTH gated on the shared [`is_valid_coords`] check:
/// a `0,0` location is Censys's "unknown" sentinel, where the city/country are
/// equally unreliable, so it yields neither — keeping placeholder junk out of the
/// graph (false positives are worse than a missed lead here).
fn build_entities(host: &HostResult, ip: &str, scan_id: &str) -> Vec<Entity> {
    if host.services.is_empty()
        && host.location.is_none()
        && host.autonomous_system.is_none()
        && host.dns.is_none()
    {
        return Vec::new();
    }

    let mut result = ModuleResult::new();

    // ── IP entity with service evidence ─────────────────────────
    if !host.services.is_empty() {
        let mut entity = Entity::new(
            EntityKind::IpAddress,
            ip,
            confidence::VERY_HIGH_PLUS,
            scan_id,
        );
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
        let mut geo = Entity::new(
            EntityKind::Coordinates,
            &coord_str,
            confidence::HIGH,
            scan_id,
        );
        geo.tag("geoint");
        geo.tag("censys");
        // Skip a blank country code (no `country:` tag for an empty string).
        if let Some(cc) = loc.country_code.as_deref().filter(|c| !c.is_empty()) {
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
        // Skip blank/empty evidence attributes (dead-field hygiene).
        .filter_map(|(k, v)| v.filter(|val| !val.is_empty()).map(|val| (k, val)))
        .fold(ev, |ev, (k, val)| ev.with_attr(k, val));

        geo.add_evidence(ev);
        result.push(geo);

        let city = loc.city.as_deref().unwrap_or("");
        let province = loc.province.as_deref().unwrap_or("");
        let country = loc.country.as_deref().unwrap_or("");
        if !city.is_empty() && !country.is_empty() {
            let addr = crate::util::geo::compose_address(city, province, country);
            let mut ae = Entity::new(EntityKind::Address, &addr, confidence::MEDIUM_PLUS, scan_id);
            ae.tag("censys");
            ae.tag("geoint");
            ae.add_evidence(Evidence::new(SRC, format!("Censys location for {ip}")));
            result.push(ae);
        }
    }

    // ── ASN + network-operator Organisation ─────────────────────
    // The authoritative attribution block: the announcing ASN and the org that
    // operates it — the two pivots that drive the infrastructure/ownership
    // correlators, matching shodan/criminal_ip/ipqs. A 0/absent AS is skipped.
    if let Some(as_block) = &host.autonomous_system {
        if let Some(asn) = as_block.asn.filter(|n| *n > 0) {
            let asn_str = format!("AS{asn}");
            let mut ae = Entity::new(EntityKind::Asn, &asn_str, 0.80, scan_id);
            ae.tag("censys");
            let mut ev = Evidence::new(SRC, format!("Announcing ASN for {ip}"));
            if let Some(cc) = as_block
                .country_code
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                ev = ev.with_attr("country", cc);
            }
            ae.add_evidence(ev);
            result.push(ae);
        }
        // Operator name — prefer `name`, fall back to the longer `description`.
        if let Some(org) = as_block
            .name
            .as_deref()
            .or(as_block.description.as_deref())
            .map(str::trim)
            .filter(|s| s.len() >= 2)
        {
            let mut oe = Entity::new(EntityKind::Organisation, org, 0.65, scan_id);
            oe.tag("censys");
            oe.add_evidence(Evidence::new(SRC, format!("Network operator for {ip}")));
            result.push(oe);
        }
    }

    // ── Reverse-DNS names → Domain pivots ───────────────────────
    // Deduped; IP-shaped, dotless, and whitespace-bearing hosts dropped.
    if let Some(rev) = host.dns.as_ref().and_then(|d| d.reverse_dns.as_ref()) {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for host_lc in rev
            .names
            .iter()
            .map(|n| n.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|h| {
                !h.is_empty()
                    && h.contains('.')
                    && h.parse::<std::net::IpAddr>().is_err()
                    && !h.contains(char::is_whitespace)
            })
        {
            if !seen.insert(host_lc.clone()) {
                continue;
            }
            let mut d = Entity::new(EntityKind::Domain, &host_lc, 0.72, scan_id);
            d.tag("censys");
            d.tag("ptr");
            d.add_evidence(
                Evidence::new(SRC, format!("Reverse-DNS host for {ip}")).with_attr("ip", ip),
            );
            result.push(d);
        }
    }

    result.entities
}
