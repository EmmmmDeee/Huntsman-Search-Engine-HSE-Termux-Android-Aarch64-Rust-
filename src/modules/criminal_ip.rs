use std::collections::HashMap;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::core::{
    entity::Evidence,
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

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
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
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
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Deserialize)]
struct Score {
    #[serde(default)]
    inbound: Option<String>,
    #[serde(default)]
    outbound: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
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
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
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

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;
        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }
        let url = format!("https://api.criminalip.io/v1/asset/ip/report?ip={ip}");
        let resp = ctx
            .http
            .get(&url)
            .header("x-api-key", key)
            .send()
            .await
            .map_err(|e| Error::module("criminal_ip", e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::module(
                "criminal_ip",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }
        let body: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module("criminal_ip", e.to_string()))?;
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
            entity.tag_opt(is.is_vpn, "vpn");
            entity.tag_opt(is.is_proxy, "proxy");
            entity.tag_opt(is.is_tor, "tor");
            entity.tag_opt(is.is_hosting, "hosting");
            entity.tag_opt(is.is_anonymous_vpn, "anonymous-vpn");
            entity.tag_opt(is.is_cloud, "cloud");
            entity.tag_opt(is.is_scanner, "scanner");
            entity.tag_opt(is.is_dark_web, "dark-web");
        }
        if let Some(w) = body.whois.as_ref().and_then(|w| w.data.first())
            && let Some(c) = w.org_country_code.as_deref()
        {
            entity.tag(format!("country:{}", c.to_uppercase()));
        }

        let mut ev = Evidence::new("criminal_ip", format!("Criminal IP report for {ip}"));
        if let Some(s) = body.score.as_ref() {
            ev = ev
                .with_opt_attr("inbound_risk", s.inbound.as_deref())
                .with_opt_attr("outbound_risk", s.outbound.as_deref());
        }
        if let Some(w) = body.whois.as_ref().and_then(|w| w.data.first()) {
            ev = ev
                .with_opt_attr("asn", w.as_no.map(|v| v.to_string()))
                .with_opt_attr("as_name", w.as_name.as_deref())
                .with_opt_attr("org", w.org_name.as_deref())
                .with_opt_attr("country", w.org_country_code.as_deref());
        }
        ev = ev
            .with_opt_attr(
                "open_port_count",
                body.port.and_then(|p| p.count).map(|v| v.to_string()),
            )
            .with_opt_attr(
                "vuln_count",
                body.vulnerability
                    .and_then(|v| v.count)
                    .map(|v| v.to_string()),
            );
        if let Some(is) = &body.issues {
            ev = ev
                .with_opt_attr("is_vpn", is.is_vpn.filter(|&v| v).map(|_| "true"))
                .with_opt_attr("is_proxy", is.is_proxy.filter(|&v| v).map(|_| "true"))
                .with_opt_attr("is_tor", is.is_tor.filter(|&v| v).map(|_| "true"))
                .with_opt_attr("is_hosting", is.is_hosting.filter(|&v| v).map(|_| "true"))
                .with_opt_attr(
                    "is_anonymous_vpn",
                    is.is_anonymous_vpn.filter(|&v| v).map(|_| "true"),
                )
                .with_opt_attr("is_cloud", is.is_cloud.filter(|&v| v).map(|_| "true"))
                .with_opt_attr("is_scanner", is.is_scanner.filter(|&v| v).map(|_| "true"))
                .with_opt_attr("is_dark_web", is.is_dark_web.filter(|&v| v).map(|_| "true"));
        }
        // Store overflow fields from top-level response
        for (k, v) in &body.extra {
            let val_str = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            ev = ev.with_attr(format!("criminal_ip_{k}"), val_str);
        }
        // Store overflow fields from issues sub-object
        if let Some(issues) = &body.issues {
            for (k, v) in &issues.extra {
                let val_str = match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                ev = ev.with_attr(format!("criminal_ip_{k}"), val_str);
            }
        }
        // Store overflow fields from score sub-object
        if let Some(score) = &body.score {
            for (k, v) in &score.extra {
                let val_str = match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                ev = ev.with_attr(format!("criminal_ip_score_{k}"), val_str);
            }
        }
        // Store overflow fields from whois rows
        if let Some(w) = body.whois.as_ref() {
            for row in &w.data {
                for (k, v) in &row.extra {
                    let val_str = match v {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    ev = ev.with_attr(format!("criminal_ip_whois_{k}"), val_str);
                }
            }
        }
        entity.add_evidence(ev);
        let mut result = ModuleResult::new();
        result.push(entity);
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
