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
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{error_snippet, handle_keyed_error};

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

pub struct CriminalIp;

#[async_trait]
impl Module for CriminalIp {
    fn name(&self) -> &'static str {
        "criminal_ip"
    }
    fn description(&self) -> &'static str {
        "IP risk scoring and threat classification"
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
        // Querying Criminal IP's pre-built threat/scan database (incl. the
        // host's vulnerability count) is T1596.005 Scan Databases, already
        // covered by the Infrastructure default — not T1595.002, which would be
        // actively vulnerability-scanning the target ourselves.
        ModuleCategory::Infrastructure
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Organisation, EntityKind::Asn];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };
        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }
        let url = format!("https://api.criminalip.io/v1/asset/ip/report?ip={ip}");
        let mut retries = 2u8;
        let body: Resp = loop {
            let resp = ctx
                .http
                .get(&url)
                .header("x-api-key", key)
                .send()
                .await
                .map_err(|e| Error::module(SRC, e.to_string()))?;
            let status = resp.status();
            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, SRC, key, ctx).await {
                    continue;
                }
                return Err(Error::module(
                    "criminal_ip",
                    format!("HTTP {status}: {}", error_snippet(resp).await),
                ));
            }
            break resp
                .json()
                .await
                .map_err(|e| Error::module(SRC, e.to_string()))?;
        };
        if body.status != Some(200) {
            return Ok(ModuleResult::new());
        }

        let mut entity = target.to_entity(0.88, &ctx.scan_id);
        entity.tag("criminal_ip");
        if let Some(s) = &body.score {
            if let Some(i) = s.inbound.as_deref()
                && matches!(i, "Critical" | "Dangerous" | "High")
            {
                entity.tag("high-risk-inbound");
            }
            if let Some(o) = s.outbound.as_deref()
                && matches!(o, "Critical" | "Dangerous" | "High")
            {
                entity.tag("high-risk-outbound");
            }
        }
        if let Some(is) = &body.issues {
            if is.is_vpn == Some(true) {
                entity.tag("vpn");
            }
            if is.is_proxy == Some(true) {
                entity.tag("proxy");
            }
            if is.is_tor == Some(true) {
                entity.tag("tor");
            }
            if is.is_hosting == Some(true) {
                entity.tag("hosting");
            }
            if is.is_anonymous_vpn == Some(true) {
                entity.tag("anonymous-vpn");
            }
            if is.is_cloud == Some(true) {
                entity.tag("cloud");
            }
            if is.is_scanner == Some(true) {
                entity.tag("scanner");
            }
            if is.is_dark_web == Some(true) {
                // Canonical darknet-exposure tag (same one IntelX's darknet.*
                // buckets emit) so both sources group in adjacency analysis,
                // rather than this signal sitting under an unmatched "dark-web".
                entity.tag(crate::core::tags::DARKNET);
            }
        }
        if let Some(w) = body.whois.as_ref().and_then(|w| w.data.first())
            && let Some(c) = w.org_country_code.as_deref()
        {
            entity.tag(format!("country:{}", c.to_uppercase()));
        }

        let mut ev = Evidence::new(SRC, format!("Criminal IP report for {ip}"));
        if let Some(s) = body.score.as_ref() {
            if let Some(i) = s.inbound.as_deref() {
                ev = ev.with_attr("inbound_risk", i);
            }
            if let Some(o) = s.outbound.as_deref() {
                ev = ev.with_attr("outbound_risk", o);
            }
        }
        if let Some(w) = body.whois.as_ref().and_then(|w| w.data.first()) {
            if let Some(v) = w.as_no {
                ev = ev.with_attr("asn", v.to_string());
            }
            if let Some(v) = w.as_name.as_deref() {
                ev = ev.with_attr("as_name", v);
            }
            if let Some(v) = w.org_name.as_deref() {
                ev = ev.with_attr("org", v);
            }
            if let Some(v) = w.org_country_code.as_deref() {
                ev = ev.with_attr("country", v);
            }
        }
        if let Some(p) = body.port.and_then(|p| p.count) {
            ev = ev.with_attr("open_port_count", p.to_string());
        }
        if let Some(v) = body.vulnerability.and_then(|v| v.count) {
            ev = ev.with_attr("vuln_count", v.to_string());
        }
        if let Some(is) = &body.issues {
            if is.is_vpn == Some(true) {
                ev = ev.with_attr("is_vpn", "true");
            }
            if is.is_proxy == Some(true) {
                ev = ev.with_attr("is_proxy", "true");
            }
            if is.is_tor == Some(true) {
                ev = ev.with_attr("is_tor", "true");
            }
            if is.is_hosting == Some(true) {
                ev = ev.with_attr("is_hosting", "true");
            }
            if is.is_anonymous_vpn == Some(true) {
                ev = ev.with_attr("is_anonymous_vpn", "true");
            }
            if is.is_cloud == Some(true) {
                ev = ev.with_attr("is_cloud", "true");
            }
            if is.is_scanner == Some(true) {
                ev = ev.with_attr("is_scanner", "true");
            }
            if is.is_dark_web == Some(true) {
                ev = ev.with_attr("is_dark_web", "true");
            }
        }
        entity.add_evidence(ev);
        let mut result = ModuleResult::new();
        result.push(entity);

        if let Some(w) = body.whois.as_ref().and_then(|w| w.data.first()) {
            if let Some(org) = w.org_name.as_deref()
                && !org.is_empty()
            {
                let mut oe = Entity::new(EntityKind::Organisation, org, 0.65, &ctx.scan_id);
                oe.tag("criminal_ip");
                oe.add_evidence(Evidence::new(SRC, format!("IP org for {ip}")));
                result.push(oe);
            }
            if let Some(asn) = w.as_no {
                let asn_str = format!("AS{asn}");
                let mut ae = Entity::new(EntityKind::Asn, &asn_str, 0.80, &ctx.scan_id);
                ae.tag("criminal_ip");
                ae.add_evidence(Evidence::new(SRC, format!("ASN for {ip}")));
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
    fn accepts_only_ip() {
        let m = CriminalIp;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
    }
    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(CriminalIp.cost(), ModuleCost::KeyGated));
    }

    #[test]
    fn dark_web_flag_drives_canonical_darknet_tag() {
        // The is_dark_web issue flag is what process() turns into the canonical
        // tags::DARKNET tag (grouping with IntelX darknet exposure in adjacency
        // analysis). Lock the field name + the constant it maps to.
        let issues: Issues =
            serde_json::from_str(r#"{"is_dark_web":true,"is_tor":false}"#).unwrap();
        assert_eq!(issues.is_dark_web, Some(true));
        assert_eq!(crate::core::tags::DARKNET, "darknet");
    }
}
