//! Criminal IP (criminalip.io) — IP threat scoring. Key-gated.
//!
//! Endpoint: `GET https://api.criminalip.io/v1/asset/ip/report?ip={ip}`
//! Auth:     `x-api-key: <key>` request header.
//!
//! Surfaces the inbound/outbound risk classification, open ports count,
//! ASN/ISP/country, and any vulnerability count. The full per-port
//! breakdown is left out of evidence (verbose and changes frequently);
//! consumers can re-query the API for the full record.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::handle_keyed_error;

const KEY_ENV: &str = "HUNTSMAN_CRIMINALIP_KEY";

#[derive(Deserialize)]
struct Resp {
    #[serde(default)]
    status: Option<i32>,
    #[serde(default)]
    issues: Option<Issues>,
    #[serde(default)]
    score: Option<Score>,
    #[serde(default)]
    whois: Option<WhoisBlock>,
    #[serde(default)]
    port: Option<PortBlock>,
    #[serde(default)]
    vulnerability: Option<VulnBlock>,
}

#[derive(Deserialize)]
struct Issues {
    #[serde(default)]
    is_vpn: Option<bool>,
    #[serde(default)]
    is_proxy: Option<bool>,
    #[serde(default)]
    is_tor: Option<bool>,
    #[serde(default)]
    is_hosting: Option<bool>,
    #[serde(default)]
    is_anonymous_vpn: Option<bool>,
    #[serde(default)]
    is_cloud: Option<bool>,
    #[serde(default)]
    is_scanner: Option<bool>,
    #[serde(default)]
    is_dark_web: Option<bool>,
}

impl Issues {
    /// The issue flags that are set, each paired with its `(tag, evidence-attr)`
    /// names. Single-sourced (CONVENTIONS rule 3): a flag's short tag (`vpn`)
    /// and its evidence key (`is_vpn`) live in one table, so the two passes —
    /// tagging the subject and recording evidence — cannot drift apart.
    fn active(&self) -> impl Iterator<Item = (&'static str, &'static str)> {
        [
            (self.is_vpn, "vpn", "is_vpn"),
            (self.is_proxy, "proxy", "is_proxy"),
            (self.is_tor, "tor", "is_tor"),
            (self.is_hosting, "hosting", "is_hosting"),
            (self.is_anonymous_vpn, "anonymous-vpn", "is_anonymous_vpn"),
            (self.is_cloud, "cloud", "is_cloud"),
            (self.is_scanner, "scanner", "is_scanner"),
            (self.is_dark_web, "dark-web", "is_dark_web"),
        ]
        .into_iter()
        .filter(|(flag, _, _)| *flag == Some(true))
        .map(|(_, tag, attr)| (tag, attr))
    }
}

#[derive(Deserialize)]
struct Score {
    #[serde(default)]
    inbound: Option<String>,
    #[serde(default)]
    outbound: Option<String>,
}

#[derive(Deserialize)]
struct WhoisBlock {
    #[serde(default)]
    data: Vec<WhoisRow>,
}

#[derive(Deserialize)]
struct WhoisRow {
    #[serde(default)]
    as_no: Option<i64>,
    #[serde(default)]
    as_name: Option<String>,
    #[serde(default)]
    org_name: Option<String>,
    #[serde(default)]
    org_country_code: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
}

#[derive(Deserialize)]
struct PortBlock {
    #[serde(default)]
    count: Option<i64>,
}

#[derive(Deserialize)]
struct VulnBlock {
    #[serde(default)]
    count: Option<i64>,
}

const SRC: &str = "criminal_ip";

/// Criminal IP grades risk as a textual band; only the top three bands warrant
/// a `high-risk-*` tag on the subject IP.
fn risk_is_high(level: &str) -> bool {
    matches!(level, "Critical" | "Dangerous" | "High")
}

/// `Some(trimmed)` only when a field is present and non-blank — keeps empty API
/// strings out of evidence (the same dead-field hygiene applied tree-wide).
fn nonblank(v: Option<&str>) -> Option<&str> {
    v.map(str::trim).filter(|s| !s.is_empty())
}

/// Map a decoded Criminal IP report to its entities. **Pure** (no network/IO),
/// so the whole risk→tag→evidence→pivot mapping is unit-testable directly.
///
/// | source                                  | output                                |
/// |-----------------------------------------|---------------------------------------|
/// | the queried IP                          | subject `IpAddress` (+ `criminal_ip`) |
/// | `score.inbound`/`outbound` in top bands | `high-risk-inbound`/`-outbound` tags  |
/// | `issues.is_*` flags that are `true`     | one tag each + an `is_*=true` attr     |
/// | `whois[0].org_country_code`             | `country:<CC>` tag (uppercased)       |
/// | `score.*`, `whois[0].*`, `port`, `vuln` | evidence attributes                   |
/// | `whois[0].org_name` (non-blank)         | `Organisation` pivot                   |
/// | `whois[0].as_no`                        | `Asn` pivot (`AS<n>`)                  |
/// | `whois[0].latitude`/`longitude` (valid) | `Coordinates` pivot (`geoint`)        |
/// | `whois[0].city`/`region`/country        | `Address` pivot (`geoint`)            |
///
/// The subject is always emitted (the caller has already gated on a
/// `status == 200` report); the Organisation/Asn/geo pivots only when the whois
/// block carries them. A whois latitude/longitude is trusted only through
/// [`crate::util::geo::is_valid_coords`], so the API's null-island `(0,0)`
/// placeholder never becomes a spurious equatorial fix.
fn build_entities(body: &Resp, target: &Target, scan_id: &str) -> Vec<Entity> {
    let ip = target.value.trim();
    let mut out = Vec::new();

    let mut entity = target.to_entity(confidence::EXPERT, scan_id);
    entity.tag("criminal_ip");
    if let Some(s) = &body.score {
        if s.inbound.as_deref().is_some_and(risk_is_high) {
            entity.tag("high-risk-inbound");
        }
        if s.outbound.as_deref().is_some_and(risk_is_high) {
            entity.tag("high-risk-outbound");
        }
    }
    if let Some(issues) = &body.issues {
        for (tag, _) in issues.active() {
            entity.tag(tag);
        }
    }
    if let Some(cc) = body
        .whois
        .as_ref()
        .and_then(|w| w.data.first())
        .and_then(|w| nonblank(w.org_country_code.as_deref()))
    {
        entity.tag(format!("country:{}", cc.to_uppercase()));
    }

    let mut ev = Evidence::new(SRC, format!("Criminal IP report for {ip}"));
    if let Some(s) = body.score.as_ref() {
        if let Some(i) = nonblank(s.inbound.as_deref()) {
            ev = ev.with_attr("inbound_risk", i);
        }
        if let Some(o) = nonblank(s.outbound.as_deref()) {
            ev = ev.with_attr("outbound_risk", o);
        }
    }
    if let Some(w) = body.whois.as_ref().and_then(|w| w.data.first()) {
        if let Some(v) = w.as_no {
            ev = ev.with_attr("asn", v.to_string());
        }
        if let Some(v) = nonblank(w.as_name.as_deref()) {
            ev = ev.with_attr("as_name", v);
        }
        if let Some(v) = nonblank(w.org_name.as_deref()) {
            ev = ev.with_attr("org", v);
        }
        if let Some(v) = nonblank(w.org_country_code.as_deref()) {
            ev = ev.with_attr("country", v);
        }
    }
    if let Some(p) = body.port.as_ref().and_then(|p| p.count) {
        ev = ev.with_attr("open_port_count", p.to_string());
    }
    if let Some(v) = body.vulnerability.as_ref().and_then(|v| v.count) {
        ev = ev.with_attr("vuln_count", v.to_string());
    }
    if let Some(issues) = &body.issues {
        ev = issues
            .active()
            .fold(ev, |ev, (_, attr)| ev.with_attr(attr, "true"));
    }
    entity.add_evidence(ev);
    out.push(entity);

    if let Some(w) = body.whois.as_ref().and_then(|w| w.data.first()) {
        if let Some(org) = nonblank(w.org_name.as_deref()) {
            let mut oe = Entity::new(EntityKind::Organisation, org, confidence::HIGH, scan_id);
            oe.tag("criminal_ip");
            oe.add_evidence(Evidence::new(SRC, format!("IP org for {ip}")));
            out.push(oe);
        }
        if let Some(asn) = w.as_no {
            let asn_str = format!("AS{asn}");
            let mut ae = Entity::new(
                EntityKind::Asn,
                &asn_str,
                confidence::HIGH_PLUSPLUS,
                scan_id,
            );
            ae.tag("criminal_ip");
            ae.add_evidence(Evidence::new(SRC, format!("ASN for {ip}")));
            out.push(ae);
        }
        // Whois geolocation → a real `Coordinates` fix (guarded so the API's
        // `(0,0)` null-island placeholder is never trusted) plus a
        // `City, Region, Country` `Address`. Both are IP-infrastructure geo, so
        // they carry `geoint` and stay at modest confidence — the ASN operator's
        // registered location, not proof of the subject's whereabouts.
        if let (Some(lat), Some(lon)) = (w.latitude, w.longitude)
            && crate::util::geo::is_valid_coords(lat, lon)
        {
            let coord_val = format!("{lat:.4},{lon:.4}");
            let mut ce = Entity::new(EntityKind::Coordinates, &coord_val, 0.45, scan_id);
            ce.tag("criminal_ip");
            ce.tag("geoint");
            ce.add_evidence(Evidence::new(SRC, format!("Whois geolocation for {ip}")));
            out.push(ce);
        }
        let city = nonblank(w.city.as_deref()).unwrap_or("");
        if !city.is_empty() {
            let region = nonblank(w.region.as_deref()).unwrap_or("");
            let country = nonblank(w.org_country_code.as_deref())
                .map(str::to_uppercase)
                .unwrap_or_default();
            let addr = crate::util::geo::compose_address(city, region, &country);
            let mut ae = Entity::new(EntityKind::Address, &addr, 0.50, scan_id);
            ae.tag("criminal_ip");
            ae.tag("geoint");
            ae.add_evidence(Evidence::new(SRC, format!("Whois location for {ip}")));
            out.push(ae);
        }
    }

    out
}

pub struct CriminalIp;

#[async_trait]
impl Module for CriminalIp {
    fn name(&self) -> &'static str {
        "criminal_ip"
    }
    fn description(&self) -> &'static str {
        "Criminal IP recon — scores IP risk and surfaces threat classification"
    }
    fn priority(&self) -> u8 {
        103
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

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Criminal IP is a paid threat-intel vendor (risk scoring + VPN/proxy/
        // tor/scanner classification), so beyond the Infrastructure default
        // (T1590.005 IP Addresses + T1596.005 Scan Databases) it is Search
        // Closed Sources: Threat Intel Vendors (T1597.001). Surfaces the ASN
        // operator as an Organisation entity → T1591.002 Business Relationships,
        // and the whois city/region/lat-lon as Address/Coordinates →
        // T1591.001 Physical Locations.
        &[
            "T1590.005",
            "T1591.001",
            "T1591.002",
            "T1596.005",
            "T1597.001",
        ]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::IpAddress,
            EntityKind::Organisation,
            EntityKind::Asn,
            EntityKind::Coordinates,
            EntityKind::Address,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let initial_key = ctx.key(KEY_ENV)?;
        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }
        let url = format!("https://api.criminalip.io/v1/asset/ip/report?ip={ip}");
        // Key cascade: begin on the hot-injected key and, on a terminal key
        // failure — an HTTP 401/403/429 OR an in-body 401/402/429 status (Criminal
        // IP reports a dead key that way on an HTTP 200) — rotate to the next
        // usable pooled key and retry, so one process() call spends every
        // credential the pool holds before it fails. `tried` stops a burned key
        // being re-handed.
        let mut tried: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut key = initial_key.to_string();
        let body: Resp = 'cascade: loop {
            tried.insert(key.clone());
            let mut retries = 2u8;
            let parsed: Resp = loop {
                if ctx.cancel.is_cancelled() {
                    return Ok(ModuleResult::new());
                }
                let resp = ctx
                    .http
                    .get(&url)
                    .header("x-api-key", &key)
                    .send_tagged(SRC)
                    .await?;
                let status = resp.status();
                if !status.is_success() {
                    let code = status.as_u16();
                    if handle_keyed_error(code, resp.headers(), &mut retries, SRC, &key, ctx).await
                    {
                        continue;
                    }
                    if crate::util::http::is_keyed_error_status(code)
                        && let Some(next) = ctx.next_pooled_key(SRC, &tried)
                    {
                        key = next;
                        continue 'cascade;
                    }
                    return Err(crate::util::http::http_status_error("criminal_ip", resp).await);
                }
                break crate::util::http::json_decode(SRC, resp).await?;
            };
            // Criminal IP reports auth/quota failures as an IN-BODY status on an
            // HTTP 200, so a dead/exhausted key would otherwise be indistinguishable
            // from a clean empty result. On 401/402/429 cascade to the next pooled
            // key (and, if none remains, surface report + Err so the failure is
            // visible); any other non-200 stays a genuine empty result.
            match parsed.status {
                Some(200) => break 'cascade parsed,
                Some(code @ (401 | 402 | 429)) => {
                    ctx.report_key_exhausted(SRC, &key, code as u16);
                    if let Some(next) = ctx.next_pooled_key(SRC, &tried) {
                        key = next;
                        continue 'cascade;
                    }
                    return Err(crate::core::error::Error::module(
                        SRC,
                        format!("criminal_ip in-body status {code} (key auth/quota failure)"),
                    ));
                }
                _ => return Ok(ModuleResult::new()),
            }
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(&body, target, &ctx.scan_id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
