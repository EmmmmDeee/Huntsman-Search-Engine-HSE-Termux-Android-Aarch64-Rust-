//! ZoomEye — internet-wide host/service search engine (Shodan/Censys-class).
//! Key-gated; requires `HUNTSMAN_ZOOMEYE_KEY`.
//!
//! Endpoint: `GET https://api.zoomeye.org/host/search?query={dork}&page=1`
//! Auth:     `API-KEY: {key}` request header (per ZoomEye docs / the service def
//! the key-probe already validates against `…/resources-info`).
//!
//! Given an IP it dorks `ip:{ip}`; given a domain, `hostname:{domain}` (the hosts
//! ZoomEye has indexed serving that name). Each match carries `portinfo` (the open
//! port / service / detected app / banner) and `geoinfo` (country / city /
//! coordinates / operator org / ISP / ASN). The parser is deliberately
//! schema-tolerant — ZoomEye varies field shapes across plans, and a passive
//! enrichment must degrade to "fewer entities" rather than fail on an
//! unexpected shape (the lesson onyphe codifies).
//!
//! From the result set it surfaces: the host's coordinates (suppressed for a
//! CDN/anycast edge IP, as `ip_geo` does), a city/country `Address`, the AS
//! operator `Organisation` and `Asn`, the exposed ports/services tagged onto the
//! seed IP, and — for a domain dork — the hosting `IpAddress` entities. Mirrors
//! the shodan/censys/onyphe surface and ATT&CK mapping.

#[cfg(test)]
mod tests;

use std::collections::HashSet;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{json_decode, urlencode};

const KEY_ENV: &str = "HUNTSMAN_ZOOMEYE_KEY";
const SRC: &str = "zoomeye";
/// Cap matches processed — a broad dork can return thousands of hosts.
const MAX_MATCHES: usize = 50;
/// Cap distinct exposed ports tagged onto the seed IP.
const MAX_PORTS: usize = 32;
/// Cap hosting IPs emitted for a domain dork.
const MAX_IPS: usize = 32;

#[derive(Deserialize, Default)]
struct ZoomResp {
    /// ZoomEye returns `matches` on success; an auth/quota error returns a
    /// `{"error": …}` body with no matches, which deserialises to empty here.
    #[serde(default)]
    matches: Vec<Value>,
}

/// Build the ZoomEye selector dork for a target — `ip:{ip}` or
/// `hostname:{domain}` — or `None` when the target can't address one.
///
/// # Why this validates rather than escapes
///
/// The whole dork is URL-encoded for transport (`urlencode(&dork)` at the
/// call site), but that only protects the HTTP query string — ZoomEye's own
/// server decodes it back to plain text before its dork parser ever sees it.
/// Unlike [`crate::modules::fofa::fofa_filter`]'s `field="value"` shape,
/// ZoomEye's `field:value` dork has no quoting to escape a value into: a
/// value containing whitespace or a second `:` would simply read as
/// additional dork tokens once decoded server-side (ZoomEye's own docs
/// describe space-separated `field:value` terms), the same class of
/// query-injection FOFA's quoted filter was fixed against, just with no
/// escape sequence available for this grammar.
///
/// So this validates instead of escaping — reachable via the same
/// unvalidated-pivot-target path documented on `fofa_filter` (a Domain/IP
/// entity minted straight from a provider's own response, e.g. this
/// module's own `geoinfo`/hostname fields, then pivoted into a `Target`
/// without going through [`Target::validate`](crate::core::scan::Target::validate)):
///
/// - `IpAddress` is parsed through [`std::net::IpAddr`] and the **parsed,
///   reformatted** address is used — not the raw string — so even a
///   technically-parseable-but-unusual representation is canonicalized
///   before it reaches the dork. A real parser rather than a character-class
///   check, consistent with how the standalone IPv4/IPv6 extractors validate.
/// - `Domain` is checked against the exact ASCII alphanumeric/`.`/`-`/`_`
///   class [`Target::validate`] already enforces for a *seed* Domain — a
///   pivot value failing that same class is exactly the malformed/malicious
///   case to reject, not the ordinary case to accept.
#[must_use]
fn zoomeye_dork(target: &Target) -> Option<String> {
    match target.kind {
        TargetKind::IpAddress => {
            let addr: std::net::IpAddr = target.value.trim().parse().ok()?;
            Some(format!("ip:{addr}"))
        }
        TargetKind::Domain => {
            let domain = target.value.trim();
            let valid = !domain.is_empty()
                && domain
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
            valid.then(|| format!("hostname:{domain}"))
        }
        _ => None,
    }
}

pub struct ZoomEye;

#[async_trait]
impl Module for ZoomEye {
    fn name(&self) -> &'static str {
        "zoomeye"
    }

    fn description(&self) -> &'static str {
        "ZoomEye host/service recon — enumerates exposed ports, banners, geoloc, and ASN/operator for an IP or domain (key-gated)"
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
        matches!(t.kind, TargetKind::IpAddress | TargetKind::Domain)
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let initial_key = match ctx.key_opt(KEY_ENV) {
            Some(v) => v,
            None => return Ok(ModuleResult::new()),
        };

        let value = target.value.trim();
        let Some(dork) = zoomeye_dork(target) else {
            return Ok(ModuleResult::new());
        };
        let url = format!(
            "https://api.zoomeye.org/host/search?query={}&page=1",
            urlencode(&dork)
        );

        // Key cascade via the shared primitive: on a terminal key quota/auth
        // failure, rotate to the next untried usable pooled key so one call
        // spends every credential the pool holds. `absent_statuses: &[404]` —
        // 404 means nothing indexed for this selector, a clean miss rather than
        // an error, exactly as this module treated it before.
        let Some(resp) = crate::util::http::keyed_cascade(ctx, SRC, initial_key, &[404], |key| {
            ctx.http
                .get(&url)
                .header("API-KEY", key)
                .header("Accept", "application/json")
        })
        .await?
        else {
            return Ok(ModuleResult::new());
        };
        let body: ZoomResp = json_decode(SRC, resp).await?;

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
        // Per-port app/banner detail (only for ports that have one), reported
        // as a separate evidence attribute so the raw banner text never
        // pollutes the short `port:<label>` tag.
        let mut port_details: Vec<String> = Vec::new();
        let mut ips_emitted = 0usize;

        for m in body.matches.iter().take(MAX_MATCHES) {
            let ev = || Evidence::new(SRC, format!("ZoomEye host match for {value}"));

            // ── Coordinates ─────────────────────────────────────────────────
            if !skip_coords
                && let Some((lat, lon)) = coords(m)
                && seen.insert(format!("@coord:{lat:.4},{lon:.4}"))
                && let Some(mut ce) = crate::util::geo::coarse_provider_coords(
                    lat,
                    lon,
                    confidence::MEDIUM_HIGH,
                    &ctx.scan_id,
                )
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
                let mut ae = Entity::new(
                    EntityKind::Address,
                    &addr,
                    confidence::MEDIUM_HIGH,
                    &ctx.scan_id,
                );
                ae.tag(crate::core::tags::GEOINT);
                ae.add_evidence(ev());
                result.push(ae);
            }

            // ── ASN + operator org ──────────────────────────────────────────
            if let Some(asn) = geo_asn(m)
                && seen.insert(asn.to_lowercase())
            {
                let mut ae =
                    Entity::new(EntityKind::Asn, &asn, confidence::VERY_HIGH, &ctx.scan_id);
                ae.add_evidence(ev());
                result.push(ae);
            }
            if let Some(org) = geo_org(m).filter(|o| o.len() >= 3)
                && seen.insert(format!("@org:{}", org.to_lowercase()))
            {
                let mut oe = Entity::new(
                    EntityKind::Organisation,
                    &org,
                    confidence::MEDIUM_HIGH,
                    &ctx.scan_id,
                );
                oe.add_evidence(ev());
                result.push(oe);
            }

            // ── Exposed port / service (tags the seed IP below) ─────────────
            if ports.len() < MAX_PORTS
                && let Some(label) = port_label(m)
                && seen.insert(format!("@port:{label}"))
            {
                if let Some(detail) = port_detail(m, &label) {
                    port_details.push(detail);
                }
                ports.push(label);
            }

            // ── Hosting IPs (domain dork) ───────────────────────────────────
            if matches!(target.kind, TargetKind::Domain)
                && ips_emitted < MAX_IPS
                && let Some(ip) = vstr(m, "ip")
                && ip != value
                && seen.insert(format!("@ip:{ip}"))
            {
                let mut ie = Entity::new(
                    EntityKind::IpAddress,
                    &ip,
                    confidence::HIGH_PLUS,
                    &ctx.scan_id,
                );
                ie.tag(SRC);
                ie.add_evidence(ev());
                result.push(ie);
                ips_emitted += 1;
            }
        }

        // For an IP target, fold the exposed service surface onto the seed entity.
        if matches!(target.kind, TargetKind::IpAddress) && !ports.is_empty() {
            let mut e = target.to_entity(confidence::MEDIUM_PLUS, &ctx.scan_id);
            e.tag(SRC);
            for label in &ports {
                e.tag(format!("port:{label}"));
            }
            let mut ev = Evidence::new(SRC, format!("ZoomEye: {} exposed service(s)", ports.len()))
                .with_attr("ports", ports.join(", "));
            if !port_details.is_empty() {
                // Full-fidelity policy (mirrors `webserver_banner`): a
                // detected app/banner reaches the operator verbatim, paired
                // with its port label so it stays traceable to one service.
                ev = ev.with_attr("service_details", port_details.join("; "));
            }
            e.add_evidence(ev);
            result.push(e);
        }

        Ok(result)
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

/// `portinfo.app` — the detected application/product name for a service
/// (e.g. `"nginx"`, `"OpenSSH"`), when ZoomEye's plan includes it.
fn port_app(m: &Value) -> Option<String> {
    pstr(m, "/portinfo/app")
}

/// `portinfo.banner` — the raw service banner ZoomEye captured for this
/// match, preserved verbatim (full-fidelity policy — mirrors
/// `webserver_banner`: an authentic captured banner must reach the operator
/// unclipped, not summarised or truncated).
fn port_banner(m: &Value) -> Option<String> {
    pstr(m, "/portinfo/banner")
}

/// `label` annotated with its detected app/banner, when either is present on
/// this match — `None` when neither is, so callers can skip a no-op detail
/// rather than emit a bare duplicate of `label`.
fn port_detail(m: &Value, label: &str) -> Option<String> {
    let app = port_app(m);
    let banner = port_banner(m);
    if app.is_none() && banner.is_none() {
        return None;
    }
    let mut s = label.to_string();
    if let Some(a) = &app {
        s.push_str(&format!(" ({a})"));
    }
    if let Some(b) = &banner {
        s.push_str(&format!(" — banner: {b}"));
    }
    Some(s)
}
