//! IPQuery.io — free IP risk assessment + geolocation (no key, unlimited).
//!
//! Endpoint: `GET https://api.ipquery.io/{ip}`
//! Auth: None. Completely free with no rate limit published.
//!
//! Returns ISP/ASN/org, city/state/country/coordinates, and risk flags
//! (mobile, VPN, Tor, proxy, datacenter) with a 0-100 risk score.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "ipquery";

#[derive(Deserialize)]
struct Resp {
    #[serde(default)]
    isp: Option<IspBlock>,
    #[serde(default)]
    location: Option<LocationBlock>,
    #[serde(default)]
    risk: Option<RiskBlock>,
}

#[derive(Deserialize)]
struct IspBlock {
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    isp: Option<String>,
}

#[derive(Deserialize)]
struct LocationBlock {
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    zipcode: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    timezone: Option<String>,
}

#[derive(Deserialize)]
struct RiskBlock {
    #[serde(default)]
    is_mobile: Option<bool>,
    #[serde(default)]
    is_vpn: Option<bool>,
    #[serde(default)]
    is_tor: Option<bool>,
    #[serde(default)]
    is_proxy: Option<bool>,
    #[serde(default)]
    is_datacenter: Option<bool>,
    #[serde(default)]
    risk_score: Option<u32>,
}

pub struct IpQuery;

#[async_trait]
impl Module for IpQuery {
    fn name(&self) -> &'static str {
        "ipquery"
    }
    fn description(&self) -> &'static str {
        "ipquery.io recon — resolves an IP to risk assessment and geolocation (free, no key, unlimited)"
    }
    fn priority(&self) -> u8 {
        27
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Infrastructure default (T1590.005 + T1596.005) covers IP info but
        // ipquery.io is a passive geolocation API, not a scan database (T1596.005).
        // It maps IPs to physical location (T1591.001) and identifies the ISP/ASN
        // operator as an Organisation (T1591.002).
        &["T1590.005", "T1591.001", "T1591.002"]
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

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // ipquery.io is IPv4-only — universal dispatcher gate lets
        // public IPv6 through, so reject it here.
        if crate::util::preflight::should_skip_external_ipv4(&target.value) {
            return Ok(ModuleResult::new());
        }
        let ip = target.value.trim();

        let url = format!("https://api.ipquery.io/{ip}");
        let resp = ctx
            .http
            .get(&url)
            .timeout(std::time::Duration::from_secs(6))
            .send_tagged(SRC)
            .await?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let data: Resp = crate::util::http::json_decode(SRC, resp).await?;

        let mut result = ModuleResult::new();

        let risk = data.risk.as_ref();
        let risk_score = risk.and_then(|r| r.risk_score).unwrap_or(0);

        let mut ip_entity = target.to_entity(confidence::HIGH_PLUSPLUS, &ctx.scan_id);
        ip_entity.tag("ipquery");
        [
            (risk.and_then(|r| r.is_vpn), tags::VPN),
            (risk.and_then(|r| r.is_tor), tags::TOR_EXIT),
            (risk.and_then(|r| r.is_proxy), tags::PROXY),
            (risk.and_then(|r| r.is_mobile), "mobile"),
            (risk.and_then(|r| r.is_datacenter), "hosting"),
        ]
        .into_iter()
        .filter(|(flag, _)| *flag == Some(true))
        .for_each(|(_, tag)| ip_entity.tag(tag));
        if risk_score >= 70 {
            ip_entity.tag("high-risk");
        }

        let isp = data.isp.as_ref();
        let ev = [
            ("isp", isp.and_then(|i| i.isp.as_deref())),
            ("org", isp.and_then(|i| i.org.as_deref())),
            ("asn", isp.and_then(|i| i.asn.as_deref())),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|v| (key, v)))
        .fold(
            Evidence::new(SRC, format!("IPQuery risk assessment for {ip}"))
                .with_attr("risk_score", risk_score.to_string()),
            |ev, (key, v)| ev.with_attr(key, v),
        );
        ip_entity.add_evidence(ev);
        result.push(ip_entity);

        // Geolocation is only the SUBJECT's when the IP isn't a CDN edge or an
        // anonymiser/datacenter exit; otherwise the coords are the facility, not
        // the person. Log the suppression reason for the operator; the builder
        // applies the same gate.
        if let Some(reason) = untrusted_geo_reason(ip, data.risk.as_ref()) {
            tracing::debug!(
                module = SRC,
                %ip,
                reason,
                "skipping IP-geo Coordinates/Address — location is the infrastructure, not the subject"
            );
        }
        for e in build_geo_isp_entities(ip, &data, &ctx.scan_id) {
            result.push(e);
        }

        Ok(result)
    }
}

/// Reason an IP's geolocation must NOT be trusted as the *subject's* location,
/// or `None` when it can. A CDN/anycast edge resolves to the answering
/// datacenter; a VPN / Tor / proxy / datacenter IP resolves to the
/// anonymiser-exit or hosting facility — in every case the coordinates are
/// infrastructure, so admitting them as a person's location poisons
/// identity-location correlation. (Mobile IPs are *not* suppressed: a carrier
/// IP still places the subject in a real region.) **Pure.**
fn untrusted_geo_reason(ip: &str, risk: Option<&RiskBlock>) -> Option<&'static str> {
    // Shared base gate (CDN/anycast edge, and any future infra rule) …
    if let Some(reason) = crate::core::validation::untrusted_ip_geo_reason(ip) {
        return Some(reason);
    }
    // … plus ipquery's risk-flag signals layered on top.
    let r = risk?;
    if r.is_tor == Some(true) {
        return Some("tor exit");
    }
    if r.is_vpn == Some(true) {
        return Some("vpn");
    }
    if r.is_proxy == Some(true) {
        return Some("proxy");
    }
    if r.is_datacenter == Some(true) {
        return Some("datacenter");
    }
    None
}

/// Build the geolocation + ISP entities for an ipquery response. **Pure** (no
/// IO) so the untrusted-geo suppression, AU tagging, and ISO-country / timezone
/// surfacing are unit-tested directly.
///
/// `Coordinates` / `Address` are emitted only when [`untrusted_geo_reason`]
/// clears the IP; the previously-discarded `country_code` (→ `country_iso` +
/// the `country:AU` tag) and `timezone` (a chronolocation lead) are stamped on
/// the geo evidence. `Asn` / `Organisation` describe the infrastructure itself
/// and are always emitted.
fn build_geo_isp_entities(ip: &str, data: &Resp, scan_id: &str) -> Vec<Entity> {
    let mut out: Vec<Entity> = Vec::new();
    let trusted_geo = untrusted_geo_reason(ip, data.risk.as_ref()).is_none();

    if let Some(loc) = data.location.as_ref().filter(|_| trusted_geo) {
        let cc = loc.country_code.as_deref().unwrap_or("");
        let tz = loc.timezone.as_deref().unwrap_or("");
        let zip = loc.zipcode.as_deref().unwrap_or("");
        let geo_ev = || {
            // The originating IP, recorded explicitly so a finalise pass can
            // robustly tie this coordinate back to its source IpAddress (e.g.
            // to recognise a person's breach login IP) without parsing the
            // summary string — mirrors `ip_geo`'s identical attribute. Without
            // it, `person_login_ip_coords` (the shared definition
            // `best_au_location_estimate` and `au_location_corroboration` both
            // use) can never recognise this provider's fix as a login-IP
            // location.
            let mut ev = Evidence::new(SRC, format!("Geolocation for {ip}")).with_attr("ip", ip);
            if !cc.is_empty() {
                ev = ev.with_attr("country_iso", cc);
            }
            if !tz.is_empty() {
                ev = ev.with_attr("timezone", tz);
            }
            // Residential postcode — a finer geo grain than city/state, folded
            // onto both the Coordinates and the Address (both carry geo_ev()).
            if !zip.is_empty() {
                ev = ev.with_attr("postcode", zip);
            }
            ev
        };

        // Confidence recalibrated 0.68 → 0.58 — see ip_geo.rs.
        if let (Some(lat), Some(lon)) = (loc.latitude, loc.longitude)
            && let Some(mut ce) = crate::util::geo::coarse_provider_coords(
                lat,
                lon,
                confidence::MEDIUM_SOLID,
                scan_id,
            )
        {
            ce.tag("ipquery");
            crate::util::geo::tag_au_state(&mut ce, lat, lon);
            ce.add_evidence(geo_ev());
            out.push(ce);
        }

        let city = loc.city.as_deref().unwrap_or("");
        let state = loc.state.as_deref().unwrap_or("");
        let country = loc.country.as_deref().unwrap_or("");
        if !city.is_empty() && !country.is_empty() {
            let addr = crate::util::geo::compose_address(city, state, country);
            let mut ae = Entity::new(EntityKind::Address, &addr, confidence::NOTABLE, scan_id);
            ae.tag("ipquery");
            if cc.eq_ignore_ascii_case("AU") {
                ae.tag("country:AU");
            }
            ae.add_evidence(geo_ev());
            out.push(ae);
        }
    }

    if let Some(isp) = &data.isp {
        if let Some(asn) = isp.asn.as_deref().filter(|s| !s.is_empty()) {
            let mut ae = crate::util::geo::ip_asn_entity(asn, SRC, ip, scan_id);
            ae.tag("ipquery");
            out.push(ae);
        }
        if let Some(org) = isp.org.as_deref().filter(|s| !s.is_empty()) {
            let mut oe = Entity::new(EntityKind::Organisation, org, confidence::HIGH, scan_id);
            oe.tag("ipquery");
            oe.add_evidence(Evidence::new(SRC, format!("ISP org for {ip}")));
            out.push(oe);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
