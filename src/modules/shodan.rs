//! Shodan host record — paid premium internet-scan database.
//!
//! Endpoint: `GET https://api.shodan.io/shodan/host/{ip}?key={KEY}`
//! Auth:     query-string `key=…` (Shodan API quirk).
//!
//! Returns the running services, open ports, CPEs, known CVEs, hostnames,
//! ASN/ISP/org, OS, and last-update timestamp for an IP. We summarise:
//! open-port list (capped at 20), vuln count + top-10 CVE IDs, org/isp/asn/
//! country, OS, last-update. Each PTR hostname becomes a `Domain` entity.

use async_trait::async_trait;
use serde::Deserialize;

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
}

pub struct Shodan;

#[async_trait]
impl Module for Shodan {
    fn name(&self) -> &'static str {
        "shodan"
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
        if !body.vulns.is_empty() {
            entity.tag("vulnerable");
        }
        if let Some(c) = body.country_code.as_deref() {
            entity.tag(format!("country:{}", c.to_uppercase()));
        }

        let mut ev = Evidence::new("shodan", format!("Shodan host record for {ip}"));
        if let Some(o) = body.org.as_deref() {
            ev = ev.with_attr("org", o);
        }
        if let Some(i) = body.isp.as_deref() {
            ev = ev.with_attr("isp", i);
        }
        if let Some(a) = body.asn.as_deref() {
            ev = ev.with_attr("asn", a);
        }
        if let Some(c) = body.country_name.as_deref() {
            ev = ev.with_attr("country", c);
        }
        if let Some(o) = body.os.as_deref() {
            ev = ev.with_attr("os", o);
        }
        if let Some(t) = body.last_update.as_deref() {
            ev = ev.with_attr("last_update", t);
        }
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
        entity.add_evidence(ev);
        result.push(entity);

        // Each PTR hostname becomes a Domain entity so downstream
        // domain modules pick it up during expansion.
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
