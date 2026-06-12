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
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Criminal IP is a paid threat-intel vendor (risk scoring + VPN/proxy/
        // tor/scanner classification), so beyond the Infrastructure default
        // (T1590.005 IP Addresses + T1596.005 Scan Databases) it is Search
        // Closed Sources: Threat Intel Vendors (T1597.001). Superset of the
        // default — coverage cannot regress.
        &["T1590.005", "T1596.005", "T1597.001"]
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
                .send_tagged(SRC)
                .await?;
            let status = resp.status();
            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, SRC, key, ctx).await {
                    continue;
                }
                return Err(crate::util::http::http_status_error("criminal_ip", resp).await);
            }
            break crate::util::http::json_decode(SRC, resp).await?;
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
            // Each true issue flag raises its tag — one table, one pass.
            [
                (is.is_vpn, "vpn"),
                (is.is_proxy, "proxy"),
                (is.is_tor, "tor"),
                (is.is_hosting, "hosting"),
                (is.is_anonymous_vpn, "anonymous-vpn"),
                (is.is_cloud, "cloud"),
                (is.is_scanner, "scanner"),
                (is.is_dark_web, "dark-web"),
            ]
            .into_iter()
            .filter(|(flag, _)| *flag == Some(true))
            .for_each(|(_, tag)| entity.tag(tag));
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
            // Mirror the true issue flags as evidence attributes in one fold.
            ev = [
                (is.is_vpn, "is_vpn"),
                (is.is_proxy, "is_proxy"),
                (is.is_tor, "is_tor"),
                (is.is_hosting, "is_hosting"),
                (is.is_anonymous_vpn, "is_anonymous_vpn"),
                (is.is_cloud, "is_cloud"),
                (is.is_scanner, "is_scanner"),
                (is.is_dark_web, "is_dark_web"),
            ]
            .into_iter()
            .filter(|(flag, _)| *flag == Some(true))
            .fold(ev, |ev, (_, k)| ev.with_attr(k, "true"));
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
}
