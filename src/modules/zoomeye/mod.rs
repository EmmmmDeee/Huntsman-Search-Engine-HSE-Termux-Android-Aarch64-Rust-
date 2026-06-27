//! ZoomEye — internet-wide host/service search engine (Shodan/Censys-class).
//! Key-gated; requires `HUNTSMAN_ZOOMEYE_KEY`.
//!
//! Endpoint: `GET https://api.zoomeye.org/host/search?query={dork}&page=1`
//! Auth:     `API-KEY: {key}` request header (per ZoomEye docs / the service def
//! the key-probe already validates against `…/resources-info`).
//!
//! Given an IP it dorks `ip:{ip}`; a domain, `hostname:{domain}` (the hosts
//! ZoomEye has indexed serving that name); a CIDR, ASN, or organisation, the
//! corresponding set-returning facet (`cidr:{range}` / `asn:{n}` / `org:"{name}"`)
//! that enumerates the hosts in that block / autonomous system / operator. Each
//! match carries `portinfo` (the open
//! port / service / banner) and `geoinfo` (country / city / coordinates / operator
//! org / ISP / ASN). The parser is deliberately schema-tolerant — ZoomEye varies
//! field shapes across plans, and a passive enrichment must degrade to "fewer
//! entities" rather than fail on an unexpected shape (the lesson onyphe codifies).
//!
//! From the result set it surfaces: the host's coordinates (suppressed for a
//! CDN/anycast edge IP, as `ip_geo` does), a city/country `Address`, the AS
//! operator `Organisation` and `Asn`, the exposed ports/services tagged onto the
//! seed IP, and — for a set-returning dork — the member/hosting `IpAddress`
//! entities. Mirrors the shodan/censys/onyphe surface and ATT&CK mapping.

#[cfg(test)]
mod tests;

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::{handle_keyed_error, json_decode, urlencode};

const KEY_ENV: &str = "HUNTSMAN_ZOOMEYE_KEY";
const SRC: &str = "zoomeye";
/// Cap matches processed — a broad dork can return thousands of hosts.
const MAX_MATCHES: usize = 50;
/// Cap distinct exposed ports tagged onto the seed IP.
const MAX_PORTS: usize = 32;
/// Cap member/hosting IPs emitted for a set-returning dork
/// (`hostname:`/`cidr:`/`asn:`/`org:`).
const MAX_IPS: usize = 32;

#[derive(Deserialize, Default)]
struct ZoomResp {
    /// ZoomEye returns `matches` on success; an auth/quota error returns a
    /// `{"error": …}` body with no matches, which deserialises to empty here.
    #[serde(default)]
    matches: Vec<Value>,
}

pub struct ZoomEye;

#[async_trait]
impl Module for ZoomEye {
    fn name(&self) -> &'static str {
        "zoomeye"
    }

    fn description(&self) -> &'static str {
        "ZoomEye host/service search: exposed ports, banners, geoloc, ASN/operator for an IP, domain, CIDR, ASN, or organisation (key-gated)"
    }

    fn priority(&self) -> u8 {
        34
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A genuine internet-scan database (T1596.005) over IP addresses
        // (T1590.005) that also yields the host's physical location
        // (T1591.001) and the AS operator org (T1591.002). Same surface as
        // shodan/censys — no passive-DNS resolver role, so T1596.001 is not
        // claimed.
        &["T1590.005", "T1591.001", "T1591.002", "T1596.005"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::IpAddress,
            EntityKind::Coordinates,
            EntityKind::Address,
            EntityKind::Asn,
            EntityKind::Organisation,
        ];
        KINDS
    }

    fn accepts(&self, t: &Target) -> bool {
        // Five ZoomEye-native selector facets: a single host (`ip:`), a name
        // (`hostname:`), or three set-returning facets that enumerate the hosts
        // in a block / autonomous system / operator (`cidr:` / `asn:` / `org:`).
        matches!(
            t.kind,
            TargetKind::IpAddress
                | TargetKind::Domain
                | TargetKind::Cidr
                | TargetKind::Asn
                | TargetKind::Organisation
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(v) => v,
            None => return Ok(ModuleResult::new()),
        };

        let value = target.value.trim();
        // The selector dork (pure, unit-tested below). A kind ZoomEye can't
        // select on — or an empty / malformed value — yields no dork and a
        // clean empty result rather than a bogus query.
        let dork = match selector_dork(target) {
            Some(d) => d,
            None => return Ok(ModuleResult::new()),
        };
        let url = format!(
            "https://api.zoomeye.org/host/search?query={}&page=1",
            urlencode(&dork)
        );

        let mut retries = 2u8;
        let body: ZoomResp = loop {
            if ctx.cancel.is_cancelled() {
                return Ok(ModuleResult::new());
            }
            let resp = ctx
                .http
                .get(&url)
                .header("API-KEY", key)
                .header("Accept", "application/json")
                .send_tagged(SRC)
                .await?;

            let status = resp.status();
            // 404 = nothing indexed for this selector — a clean miss, not an error.
            if status.as_u16() == 404 {
                return Ok(ModuleResult::new());
            }
            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, SRC, key, ctx).await {
                    continue;
                }
                return Err(crate::util::http::http_status_error(SRC, resp).await);
            }
            break json_decode(SRC, resp).await?;
        };

        if body.matches.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        let mut seen: HashSet<String> = HashSet::new();
        // For a CDN/anycast edge IP the geoloc is the answering datacentre, not
        // the subject — suppress coordinates (as ip_geo / onyphe do).
        let skip_coords = matches!(target.kind, TargetKind::IpAddress)
            && crate::core::validation::is_cdn_edge_ip(value);
        // Distinct exposed ports/services, collected across matches to tag the
        // seed IP once with its full service surface.
        let mut ports: Vec<String> = Vec::new();
        let mut ips_emitted = 0usize;

        for m in body.matches.iter().take(MAX_MATCHES) {
            let ev = || Evidence::new(SRC, format!("ZoomEye host match for {value}"));

            // ── Coordinates ─────────────────────────────────────────────────
            if !skip_coords
                && let Some((lat, lon)) = coords(m)
                && seen.insert(format!("@coord:{lat:.4},{lon:.4}"))
                && let Some(mut ce) =
                    crate::util::geo::coarse_provider_coords(lat, lon, 0.55, &ctx.scan_id)
            {
                if let Some(cc) = geo_country_code(m) {
                    ce.tag(format!("country:{}", cc.to_uppercase()));
                }
                ce.add_evidence(ev());
                result.push(ce);
            }

            // ── City / country as an Address ────────────────────────────────
            if let Some(addr) = geo_address(m)
                && seen.insert(format!("@addr:{}", addr.to_lowercase()))
            {
                let mut ae = Entity::new(EntityKind::Address, &addr, 0.55, &ctx.scan_id);
                ae.tag(crate::core::tags::GEOINT);
                ae.add_evidence(ev());
                result.push(ae);
            }

            // ── ASN + operator org ──────────────────────────────────────────
            if let Some(asn) = geo_asn(m)
                && seen.insert(asn.to_lowercase())
            {
                let mut ae = Entity::new(EntityKind::Asn, &asn, 0.75, &ctx.scan_id);
                ae.add_evidence(ev());
                result.push(ae);
            }
            if let Some(org) = geo_org(m).filter(|o| o.len() >= 3)
                && seen.insert(format!("@org:{}", org.to_lowercase()))
            {
                let mut oe = Entity::new(EntityKind::Organisation, &org, 0.55, &ctx.scan_id);
                oe.add_evidence(ev());
                result.push(oe);
            }

            // ── Exposed port / service (tags the seed IP below) ─────────────
            if ports.len() < MAX_PORTS
                && let Some(label) = port_label(m)
                && seen.insert(format!("@port:{label}"))
            {
                ports.push(label);
            }

            // ── Member / hosting IPs (set-returning dorks) ──────────────────
            // `hostname:`/`cidr:`/`asn:`/`org:` each return a *set* of distinct
            // hosts; surfacing every member IP is the actionable pivot (the
            // value the domain dork has always provided). An `ip:` dork has a
            // single seed and skips this. `ip != value` is a no-op for the
            // non-domain facets (their seed value is never an IP), kept so the
            // domain dork still excludes its own seed.
            if matches!(
                target.kind,
                TargetKind::Domain | TargetKind::Cidr | TargetKind::Asn | TargetKind::Organisation
            ) && ips_emitted < MAX_IPS
                && let Some(ip) = vstr(m, "ip")
                && ip != value
                && seen.insert(format!("@ip:{ip}"))
            {
                let mut ie = Entity::new(EntityKind::IpAddress, &ip, 0.70, &ctx.scan_id);
                ie.tag(SRC);
                ie.add_evidence(ev());
                result.push(ie);
                ips_emitted += 1;
            }
        }

        // For an IP target, fold the exposed service surface onto the seed entity.
        if matches!(target.kind, TargetKind::IpAddress) && !ports.is_empty() {
            let mut e = target.to_entity(0.60, &ctx.scan_id);
            e.tag(SRC);
            for label in &ports {
                e.tag(format!("port:{label}"));
            }
            e.add_evidence(
                Evidence::new(SRC, format!("ZoomEye: {} exposed service(s)", ports.len()))
                    .with_attr("ports", ports.join(", ")),
            );
            result.push(e);
        }

        Ok(result)
    }
}

/// Build the ZoomEye `host/search` selector dork for a seed target, or `None`
/// for a kind ZoomEye can't select on (the module then returns no result).
///
/// Each facet is ZoomEye-native grammar:
/// - `ip:{ip}`           — the single host (queried verbatim).
/// - `hostname:{domain}` — hosts ZoomEye has indexed serving that name.
/// - `cidr:{range}`      — every indexed host in the address block.
/// - `asn:{n}`           — every indexed host in the autonomous system. The
///   seed is normalised through [`crate::util::str_util::parse_asn`] to the
///   bare number ZoomEye expects (`AS15169`/`15169` → `15169`); a malformed
///   ASN yields `None`.
/// - `org:"{name}"`      — hosts whose AS operator/organisation matches. The
///   name is quoted so its spaces stay a single phrase rather than splitting
///   into separate terms.
fn selector_dork(target: &Target) -> Option<String> {
    let value = target.value.trim();
    if value.is_empty() {
        return None;
    }
    match target.kind {
        TargetKind::IpAddress => Some(format!("ip:{value}")),
        TargetKind::Domain => Some(format!("hostname:{value}")),
        TargetKind::Cidr => Some(format!("cidr:{value}")),
        TargetKind::Asn => crate::util::str_util::parse_asn(value).map(|n| format!("asn:{n}")),
        TargetKind::Organisation => Some(format!("org:\"{value}\"")),
        _ => None,
    }
}

/// A trimmed, non-empty string field at the top level of a match document.
fn vstr(v: &Value, key: &str) -> Option<String> {
    let s = v.get(key)?.as_str()?.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// A trimmed, non-empty string at a JSON pointer path (e.g. a nested `geoinfo`
/// field), tolerating ZoomEye's nested-object shapes.
fn pstr(v: &Value, path: &str) -> Option<String> {
    let s = v.pointer(path)?.as_str()?.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// `geoinfo.location.{lat,lon}` (ZoomEye returns them as strings or numbers).
fn coords(m: &Value) -> Option<(f64, f64)> {
    let num = |path: &str| {
        m.pointer(path)
            .and_then(|x| x.as_f64().or_else(|| x.as_str()?.trim().parse().ok()))
    };
    let lat = num("/geoinfo/location/lat")?;
    let lon = num("/geoinfo/location/lon")?;
    Some((lat, lon))
}

/// `geoinfo.country.code` — the ISO country code, when present.
fn geo_country_code(m: &Value) -> Option<String> {
    pstr(m, "/geoinfo/country/code")
}

/// A `"City, Country"` (or whichever part is present) address from `geoinfo`.
fn geo_address(m: &Value) -> Option<String> {
    let city = pstr(m, "/geoinfo/city/names/en");
    let country = pstr(m, "/geoinfo/country/names/en").or_else(|| geo_country_code(m));
    match (city, country) {
        (Some(c), Some(co)) => Some(format!("{c}, {co}")),
        (Some(c), None) => Some(c),
        (None, Some(co)) => Some(co),
        (None, None) => None,
    }
}

/// `geoinfo.organization` (string), else the ISP, as the AS operator org.
fn geo_org(m: &Value) -> Option<String> {
    pstr(m, "/geoinfo/organization").or_else(|| pstr(m, "/geoinfo/isp"))
}

/// `geoinfo.asn` (number or string) normalised to `AS<n>`.
fn geo_asn(m: &Value) -> Option<String> {
    let node = m.pointer("/geoinfo/asn")?;
    let raw = node
        .as_i64()
        .map(|n| n.to_string())
        .or_else(|| node.as_str().map(str::to_string))?;
    crate::util::str_util::parse_asn(&raw).map(|n| format!("AS{n}"))
}

/// `portinfo.port[/service]` — the exposed service label.
fn port_label(m: &Value) -> Option<String> {
    let node = m.pointer("/portinfo/port")?;
    let port = node
        .as_u64()
        .map(|n| n.to_string())
        .or_else(|| node.as_str().map(|s| s.trim().to_string()))?;
    if port.is_empty() {
        return None;
    }
    match pstr(m, "/portinfo/service") {
        Some(svc) => Some(format!("{port}/{svc}")),
        None => Some(port),
    }
}
