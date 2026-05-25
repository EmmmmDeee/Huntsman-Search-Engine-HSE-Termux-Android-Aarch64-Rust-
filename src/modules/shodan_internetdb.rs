//! Shodan InternetDB — free, no-key port + vulnerability lookup.
//!
//! Endpoint: `GET https://internetdb.shodan.io/{ip}`
//!
//! Unlike the paid Shodan host API, InternetDB is a free, anonymous,
//! rate-limited (1 req/s per IP) snapshot of Shodan's most recent scan
//! data. It returns open ports, observed CPEs, listed CVEs, hostnames
//! and tags for any public IPv4 — making it the single highest-signal
//! free OSINT source we currently consume. No credentials, no header
//! auth.
//!
//! 404 means "not in Shodan's index" — clean no-results, not an error.

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

    fn priority(&self) -> u8 {
        // Same band as urlhaus — runs early so vulnerability/port
        // signals are available to correlations.
        108
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(ip) = target.trimmed() else {
            return Ok(ModuleResult::new());
        };
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }

        // ctx.http carries a 3 s default timeout (MODULE_TIMEOUT_MS);
        // override per-request to match the module's declared budget.
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
            // Not in Shodan's index — clean no-result.
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

        // CPE-only and tag-only hits are still useful (passive software
        // fingerprint, `compromised`/`honeypot` classifier output) — only
        // bail when every populated field is empty.
        if body.ports.is_empty()
            && body.vulns.is_empty()
            && body.hostnames.is_empty()
            && body.cpes.is_empty()
            && body.tags.is_empty()
        {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        // Enrich the originating IP with port/vuln summary.
        let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.92, &ctx.scan_id);
        entity.tag("shodan-internetdb");
        if !body.vulns.is_empty() {
            entity.tag("vulnerable");
        }
        // Sort + dedupe + cap so the evidence row is deterministic and
        // bounded for high-port-count hosts (the `port_count` attr
        // below preserves the total).
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
            // Cap the CVE list at the first 16 so the evidence row stays scannable.
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
            // Upstream-controlled vocabulary — namespace so Shodan strings
            // like `tor`/`proxy`/`vpn`/`compromised` can't impersonate the
            // first-party correlator tags emitted by tor_exit_check /
            // criminal_ip / ipqs / urlhaus.
            for t in &body.tags {
                entity.tag(format!("shodan:{t}"));
            }
        }
        if let Some(canonical_ip) = body.ip.as_deref() {
            ev = ev.with_attr("ip", canonical_ip);
        }
        entity.add_evidence(ev);
        result.push(entity);

        // Emit one Domain entity per observed PTR / SAN hostname.
        // Cap at the first 16 to bound the entity fan-out for CDN-fronted
        // IPs which can return hundreds of PTRs.
        const MAX_HOSTS: usize = 16;
        for host in body.hostnames.iter().take(MAX_HOSTS) {
            let host = host.trim().trim_end_matches('.');
            if host.is_empty() {
                continue;
            }
            // InternetDB occasionally returns IP literals when the PTR
            // points back to itself; reject so we don't seed an IP into
            // the Domain namespace.
            if host.parse::<std::net::IpAddr>().is_ok() {
                continue;
            }
            // Domain shape sanity — must contain at least one dot and
            // no whitespace (defensive against malformed upstream data).
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
