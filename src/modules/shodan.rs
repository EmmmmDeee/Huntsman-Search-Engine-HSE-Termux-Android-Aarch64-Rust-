//! Shodan — combined free InternetDB + paid host-API module.
//!
//! **Free path (always):**
//! `GET https://internetdb.shodan.io/{ip}` — open ports, CVEs, CPEs,
//! hostnames, tags for any public IPv4. No credentials needed.
//!
//! **Paid path (when `HUNTSMAN_SHODAN_KEY` is set):**
//! `GET https://api.shodan.io/shodan/host/{ip}?key={KEY}` — detailed
//! service-scan data, org/ISP/ASN/OS, and PTR hostnames.
//!
//! Both paths run for every IP address target; entities are merged.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::{error_snippet, urlencode};

const KEY_ENV: &str = "HUNTSMAN_SHODAN_KEY";

// ── Paid API response ────────────────────────────────────────────────

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

// ── Free InternetDB response ─────────────────────────────────────────

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

// ── Module impl ──────────────────────────────────────────────────────

const SRC: &str = "shodan";

pub struct Shodan;

#[async_trait]
impl Module for Shodan {
    fn name(&self) -> &'static str {
        "shodan"
    }
    fn description(&self) -> &'static str {
        "Shodan host intelligence — free InternetDB plus paid API when keyed"
    }
    fn priority(&self) -> u8 {
        105
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
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

        let mut result = ModuleResult::new();

        // ── 1. Free InternetDB (always) ──────────────────────────────
        self.query_internetdb(ip, ctx, &mut result).await;

        // ── 2. Paid host API (when key is present) ───────────────────
        if let Some(key) = ctx.key_opt(KEY_ENV) {
            self.query_paid(ip, key, ctx, &mut result).await?;
        }

        Ok(result)
    }
}

impl Shodan {
    /// Query the free InternetDB endpoint. Errors are swallowed so the
    /// paid path can still proceed.
    async fn query_internetdb(&self, ip: &str, ctx: &ModuleContext, result: &mut ModuleResult) {
        let resp = match ctx
            .http
            .get(format!("https://internetdb.shodan.io/{}", urlencode(ip)))
            .header("Accept", "application/json")
            .timeout(std::time::Duration::from_millis(self.max_timeout_ms()))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return,
        };

        let status = resp.status();
        if status.as_u16() == 404 || !status.is_success() {
            return;
        }

        let body: InternetDbResp = match resp.json().await {
            Ok(b) => b,
            Err(_) => return,
        };

        if body.ports.is_empty()
            && body.vulns.is_empty()
            && body.hostnames.is_empty()
            && body.cpes.is_empty()
            && body.tags.is_empty()
        {
            return;
        }

        // Enrich the originating IP with port/vuln summary.
        let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.92, &ctx.scan_id);
        entity.tag("shodan-internetdb");
        if !body.vulns.is_empty() {
            entity.tag("vulnerable");
        }

        const MAX_PORTS: usize = 50;
        let mut ports_sorted: Vec<u16> = body.ports.clone();
        ports_sorted.sort_unstable();
        ports_sorted.dedup();
        let ports_csv = ports_sorted
            .iter()
            .take(MAX_PORTS)
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let mut ev = Evidence::new(
            SRC,
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
            let v: Vec<&str> = body
                .vulns
                .iter()
                .take(30)
                .map(std::string::String::as_str)
                .collect();
            ev = ev
                .with_attr("vulns", v.join(","))
                .with_attr("vuln_count", body.vulns.len().to_string());
        }
        if !body.cpes.is_empty() {
            let c: Vec<&str> = body
                .cpes
                .iter()
                .take(20)
                .map(std::string::String::as_str)
                .collect();
            ev = ev.with_attr("cpes", c.join(","));
        }
        if !body.tags.is_empty() {
            ev = ev.with_attr("tags", body.tags.join(","));
            for t in &body.tags {
                entity.tag(format!("shodan:{t}"));
            }
        }
        if let Some(canonical_ip) = body.ip.as_deref() {
            ev = ev.with_attr("ip", canonical_ip);
        }
        entity.add_evidence(ev);
        result.push(entity);

        // Emit Domain entities for observed PTR / SAN hostnames.
        const MAX_HOSTS: usize = 30;
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
                    SRC,
                    format!("Hostname associated with {ip} per Shodan InternetDB"),
                )
                .with_attr("ip", ip),
            );
            result.push(d);
        }
    }

    /// Query the paid Shodan host API.
    async fn query_paid(
        &self,
        ip: &str,
        key: &str,
        ctx: &ModuleContext,
        result: &mut ModuleResult,
    ) -> Result<()> {
        let url = format!(
            "https://api.shodan.io/shodan/host/{}?key={}",
            urlencode(ip),
            urlencode(key),
        );
        let resp = ctx
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;
        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(());
        }
        if !status.is_success() {
            let code = status.as_u16();
            if code == 429 || code == 401 || code == 403 {
                ctx.report_key_exhausted(SRC, key, code);
            }
            return Err(Error::module(
                SRC,
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }
        let body: HostResp = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let mut entity = target_entity(ip, &ctx.scan_id);
        entity.tag("shodan");
        if !body.vulns.is_empty() {
            entity.tag("vulnerable");
        }
        if let Some(c) = body.country_code.as_deref() {
            entity.tag(format!("country:{}", c.to_uppercase()));
        }

        let mut ev = Evidence::new(SRC, format!("Shodan host record for {ip}"));
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
        if let Some(c) = body.country_code.as_deref() {
            ev = ev.with_attr("country_code", c);
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

        // Each PTR hostname becomes a Domain entity.
        for host in body.hostnames {
            if host.is_empty() {
                continue;
            }
            let mut d = Entity::new(EntityKind::Domain, &host, 0.85, &ctx.scan_id);
            d.tag("shodan");
            d.tag(tags::PTR);
            d.add_evidence(
                Evidence::new(SRC, format!("Hostname known for {ip}")).with_attr("ip", ip),
            );
            result.push(d);
        }

        if let Some(org) = &body.org
            && !org.is_empty()
        {
            let mut oe = Entity::new(EntityKind::Organisation, org, 0.70, &ctx.scan_id);
            oe.tag("shodan");
            oe.add_evidence(Evidence::new(SRC, format!("Organisation for {ip}")));
            result.push(oe);
        }
        if let Some(asn) = &body.asn
            && !asn.is_empty()
        {
            let mut ae = Entity::new(EntityKind::Asn, asn, 0.80, &ctx.scan_id);
            ae.tag("shodan");
            ae.add_evidence(Evidence::new(SRC, format!("ASN for {ip}")));
            result.push(ae);
        }
        if let Some(country) = &body.country_name
            && !country.is_empty()
        {
            let mut addr = Entity::new(EntityKind::Address, country, 0.55, &ctx.scan_id);
            addr.tag("shodan");
            addr.tag("geoint");
            addr.add_evidence(Evidence::new(SRC, format!("Country for {ip}")));
            result.push(addr);
        }

        Ok(())
    }
}

/// Helper to build an IP entity from a raw IP string.
fn target_entity(ip: &str, scan_id: &str) -> Entity {
    Entity::new(EntityKind::IpAddress, ip, 0.90, scan_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Tests carried from paid-only shodan.rs ───────────────────────

    #[test]
    fn accepts_only_ip() {
        let m = Shodan;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
    }

    #[test]
    fn cost_is_free() {
        assert!(matches!(Shodan.cost(), ModuleCost::Free));
    }

    // ── Tests carried from shodan_internetdb.rs ──────────────────────

    #[test]
    fn accepts_only_ip_not_domain() {
        let m = Shodan;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    // ── Merged-module tests ──────────────────────────────────────────

    #[test]
    fn priority_is_105() {
        assert_eq!(Shodan.priority(), 105);
    }

    #[test]
    fn timeout_is_10s() {
        assert_eq!(Shodan.max_timeout_ms(), 10_000);
    }

    #[test]
    fn name_is_shodan() {
        assert_eq!(Shodan.name(), "shodan");
    }

    #[test]
    fn description_mentions_free_and_paid() {
        let desc = Shodan.description();
        assert!(desc.contains("free") || desc.contains("Free") || desc.contains("InternetDB"));
        assert!(desc.contains("paid") || desc.contains("Paid") || desc.contains("keyed"));
    }
}
