use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{error_snippet, urlencode};

#[derive(Deserialize)]
struct InternetDbResp {
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    cpes: Vec<String>,
    #[serde(default)]
    vulns: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
}

pub struct ShodanInternetDb;

#[async_trait]
impl Module for ShodanInternetDb {
    fn name(&self) -> &'static str {
        "shodan_internetdb"
    }

    fn description(&self) -> &'static str {
        "Shodan InternetDB: open ports, CVEs, CPEs for IP addresses (free, no key)"
    }

    fn priority(&self) -> u8 {
        108
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }

        let resp = ctx
            .http
            .get(format!("https://internetdb.shodan.io/{}", urlencode(ip)))
            .header("Accept", "application/json")
            .timeout(std::time::Duration::from_millis(self.max_timeout_ms()))
            .send()
            .await
            .map_err(|e| Error::module("shodan_internetdb", e.to_string()))?;

        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            return Err(Error::module(
                "shodan_internetdb",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let body: InternetDbResp = resp
            .json()
            .await
            .map_err(|e| Error::module("shodan_internetdb", e.to_string()))?;

        if body.ports.is_empty()
            && body.vulns.is_empty()
            && body.hostnames.is_empty()
            && body.cpes.is_empty()
            && body.tags.is_empty()
        {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.92, &ctx.scan_id);
        entity.tag("shodan-internetdb");
        entity.tag_if(!body.vulns.is_empty(), "vulnerable");
        const MAX_PORTS: usize = 20;
        let mut ports_sorted: Vec<u16> = body.ports.clone();
        ports_sorted.sort_unstable();
        ports_sorted.dedup();
        let ports_csv = ports_sorted
            .iter()
            .take(MAX_PORTS)
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let mut ev = Evidence::new(
            "shodan_internetdb",
            format!(
                "Shodan InternetDB: {} port(s), {} CVE(s), {} hostname(s)",
                body.ports.len(),
                body.vulns.len(),
                body.hostnames.len()
            ),
        )
        .with_attr("ports", ports_csv)
        .with_attr("port_count", body.ports.len().to_string());

        if !body.vulns.is_empty() {
            let v: Vec<&str> = body.vulns.iter().take(16).map(|s| s.as_str()).collect();
            ev = ev
                .with_attr("vulns", v.join(","))
                .with_attr("vuln_count", body.vulns.len().to_string());
        }
        if !body.cpes.is_empty() {
            let c: Vec<&str> = body.cpes.iter().take(8).map(|s| s.as_str()).collect();
            ev = ev.with_attr("cpes", c.join(","));
        }
        if !body.tags.is_empty() {
            ev = ev.with_attr("tags", body.tags.join(","));
            for t in &body.tags {
                entity.tag(format!("shodan:{t}"));
            }
        }
        ev = ev.with_opt_attr("ip", body.ip.as_deref());
        entity.add_evidence(ev);
        result.push(entity);

        const MAX_HOSTS: usize = 16;
        for host in body.hostnames.iter().take(MAX_HOSTS) {
            let host = host.trim().trim_end_matches('.');
            if host.is_empty() {
                continue;
            }
            if host.parse::<std::net::IpAddr>().is_ok() {
                continue;
            }
            if !host.contains('.') || host.contains(char::is_whitespace) {
                continue;
            }
            let mut d = Entity::new(EntityKind::Domain, host, 0.80, &ctx.scan_id);
            d.tag("shodan-internetdb");
            d.tag("ptr");
            d.add_evidence(
                Evidence::new(
                    "shodan_internetdb",
                    format!("Hostname associated with {ip} per Shodan InternetDB"),
                )
                .with_attr("ip", ip),
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
        let m = ShodanInternetDb;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }
}
