use std::collections::HashMap;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::{fetch_json_or_404, urlencode};

const KEY_ENV: &str = "HUNTSMAN_SHODAN_KEY";

#[derive(Deserialize)]
struct HostResp {
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    ports: Vec<u32>,
    #[serde(default)]
    vulns: Vec<String>,
    #[serde(default)]
    last_update: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    country_name: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    os: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

pub struct Shodan;

#[async_trait]
impl Module for Shodan {
    fn name(&self) -> &'static str {
        "shodan"
    }
    fn description(&self) -> &'static str {
        "Internet-wide service scan data for IP addresses"
    }
    fn priority(&self) -> u8 {
        105
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;
        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }
        let url = format!(
            "https://api.shodan.io/shodan/host/{}?key={}",
            urlencode(ip),
            urlencode(key),
        );
        let Some(body): Option<HostResp> = fetch_json_or_404(&ctx.http, "shodan", &url).await?
        else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        let mut entity = target.to_entity(0.90, &ctx.scan_id);
        entity.tag("shodan");
        entity.tag_if(!body.vulns.is_empty(), "vulnerable");
        if let Some(c) = body.country_code.as_deref() {
            entity.tag(format!("country:{}", c.to_uppercase()));
        }

        let ev = Evidence::new("shodan", format!("Shodan host record for {ip}"))
            .with_opt_attr("org", body.org.as_deref())
            .with_opt_attr("isp", body.isp.as_deref())
            .with_opt_attr("asn", body.asn.as_deref())
            .with_opt_attr("country", body.country_name.as_deref())
            .with_opt_attr("country_code", body.country_code.as_deref())
            .with_opt_attr("os", body.os.as_deref())
            .with_opt_attr("last_update", body.last_update.as_deref());
        let mut ev = ev;
        if !body.ports.is_empty() {
            let mut ports = body.ports;
            ports.sort_unstable();
            ev = ev
                .with_attr("port_count", ports.len().to_string())
                .with_attr(
                    "open_ports",
                    ports
                        .iter()
                        .take(20)
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                );
        }
        if !body.vulns.is_empty() {
            ev = ev
                .with_attr("vuln_count", body.vulns.len().to_string())
                .with_attr(
                    "top_vulns",
                    body.vulns
                        .iter()
                        .take(10)
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                );
        }
        for (k, v) in &body.extra {
            let val_str = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            ev = ev.with_attr(format!("shodan_{k}"), val_str);
        }
        entity.add_evidence(ev);
        result.push(entity);

        for host in body.hostnames {
            if host.is_empty() {
                continue;
            }
            let mut d = Entity::new(EntityKind::Domain, &host, 0.85, &ctx.scan_id);
            d.tag("shodan");
            d.tag(tags::PTR);
            d.add_evidence(
                Evidence::new("shodan", format!("Hostname known for {ip}")).with_attr("ip", ip),
            );
            result.push(d);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_ip() {
        let m = Shodan;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
    }
    #[test]
    fn cost_is_paid() {
        assert!(matches!(Shodan.cost(), ModuleCost::Paid));
    }
}
