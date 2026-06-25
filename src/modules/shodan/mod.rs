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

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::urlencode;

pub(super) const KEY_ENV: &str = "HUNTSMAN_SHODAN_KEY";

// ── Paid API response ────────────────────────────────────────────────

#[derive(Deserialize)]
pub(super) struct HostResp {
    #[serde(default)]
    pub(super) hostnames: Vec<String>,
    #[serde(default)]
    pub(super) ports: Vec<u32>,
    #[serde(default)]
    pub(super) vulns: Vec<String>,
    #[serde(default)]
    pub(super) last_update: Option<String>,
    #[serde(default)]
    pub(super) org: Option<String>,
    #[serde(default)]
    pub(super) isp: Option<String>,
    #[serde(default)]
    pub(super) asn: Option<String>,
    #[serde(default)]
    pub(super) country_name: Option<String>,
    #[serde(default)]
    pub(super) country_code: Option<String>,
    #[serde(default)]
    pub(super) os: Option<String>,
}

// ── Free InternetDB response ─────────────────────────────────────────

#[derive(Deserialize)]
pub(super) struct InternetDbResp {
    #[serde(default)]
    pub(super) ip: Option<String>,
    #[serde(default)]
    pub(super) ports: Vec<u16>,
    #[serde(default)]
    pub(super) hostnames: Vec<String>,
    #[serde(default)]
    pub(super) cpes: Vec<String>,
    #[serde(default)]
    pub(super) vulns: Vec<String>,
    #[serde(default)]
    pub(super) tags: Vec<String>,
}

// ── Module impl ──────────────────────────────────────────────────────

pub(super) const SRC: &str = "shodan";

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
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }
    fn attack_techniques(&self) -> &'static [&'static str] {
        // Shodan IS a scan database (T1596.005) and gathers IP address info
        // (T1590.005) — both covered by the Infrastructure default. But it
        // also maps hosts to their country-level Address (T1591.001 Physical
        // Locations) and identifies the ASN operator as an Organisation
        // (T1591.002 Business Relationships) — both absent from the default.
        &["T1590.005", "T1591.001", "T1591.002", "T1596.005"]
    }
    fn produces(&self) -> &'static [EntityKind] {
        // Free + paid Shodan paths emit IP host context: domains (PTR/SAN
        // hostnames), ASN labels, plus the dominant ISP/org as Organisation
        // and the host's country as Address. Neither endpoint returns a URL
        // field, so Url is not listed.
        const KINDS: &[EntityKind] = &[
            EntityKind::Domain,
            EntityKind::Asn,
            EntityKind::Organisation,
            EntityKind::Address,
            EntityKind::IpAddress,
        ];
        KINDS
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

        if let Some(key) = ctx.key_opt(KEY_ENV) {
            // Paid API returns a strict superset (org, ISP, ASN, OS,
            // country + everything InternetDB has). Skip free path.
            self.query_paid(ip, key, ctx, &mut result).await?;
        } else {
            self.query_internetdb(ip, ctx, &mut result).await;
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
            Err(e) => {
                tracing::debug!(target: "huntsman::shodan", ip, error = %e, "internetdb fetch failed");
                return;
            }
        };

        let status = resp.status();
        if status.as_u16() == 404 || !status.is_success() {
            tracing::debug!(
                target: "huntsman::shodan",
                ip,
                status = status.as_u16(),
                "internetdb returned no usable data (404 / non-success)"
            );
            return;
        }

        let body: InternetDbResp = match crate::util::http::json_scanned(resp, SRC).await {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(target: "huntsman::shodan", ip, error = %e, "internetdb parse failed");
                return;
            }
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
            body.tags
                .iter()
                .for_each(|t| entity.tag(format!("shodan:{t}")));
        }
        if let Some(canonical_ip) = body.ip.as_deref() {
            ev = ev.with_attr("ip", canonical_ip);
        }
        entity.add_evidence(ev);
        result.push(entity);

        // Emit Domain entities for observed PTR / SAN hostnames.
        const MAX_HOSTS: usize = 30;
        result.extend(
            body.hostnames
                .iter()
                .take(MAX_HOSTS)
                .map(|host| host.trim().trim_end_matches('.'))
                .filter(|host| {
                    !host.is_empty()
                        && host.parse::<std::net::IpAddr>().is_err()
                        && host.contains('.')
                        && !host.contains(char::is_whitespace)
                })
                .map(|host| {
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
                    d
                }),
        );
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
        let resp = ctx.http.get(&url).send_tagged(SRC).await?;
        // 404 → host not in Shodan (clean miss); 401/403/429 → note_keyed_error + Err;
        // other non-2xx → Err via http_status_error.
        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(());
        };
        let body: HostResp = crate::util::http::json_decode(SRC, resp).await?;

        let mut entity = target_entity(ip, &ctx.scan_id);
        entity.tag("shodan");
        if !body.vulns.is_empty() {
            entity.tag("vulnerable");
        }
        if let Some(c) = body.country_code.as_deref() {
            entity.tag(format!("country:{}", c.to_uppercase()));
        }

        let mut ev = [
            ("org", body.org.as_deref()),
            ("isp", body.isp.as_deref()),
            ("asn", body.asn.as_deref()),
            ("country", body.country_name.as_deref()),
            ("country_code", body.country_code.as_deref()),
            ("os", body.os.as_deref()),
            ("last_update", body.last_update.as_deref()),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|v| (key, v)))
        .fold(
            Evidence::new(SRC, format!("Shodan host record for {ip}")),
            |ev, (key, v)| ev.with_attr(key, v),
        );
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
        result.extend(
            body.hostnames
                .into_iter()
                .filter(|host| !host.is_empty())
                .map(|host| {
                    let mut d = Entity::new(EntityKind::Domain, &host, 0.85, &ctx.scan_id);
                    d.tag("shodan");
                    d.tag(tags::PTR);
                    d.add_evidence(
                        Evidence::new(SRC, format!("Hostname known for {ip}")).with_attr("ip", ip),
                    );
                    d
                }),
        );

        let org_lc = body
            .org
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        if let Some(org) = &body.org
            && !org.is_empty()
        {
            let mut oe = Entity::new(EntityKind::Organisation, org, 0.70, &ctx.scan_id);
            oe.tag("shodan");
            oe.add_evidence(Evidence::new(SRC, format!("Organisation for {ip}")));
            result.push(oe);
        }
        // ISP is a distinct OSINT pivot when it differs from org (e.g. org="AWS
        // EC2", isp="Amazon.com" — the provider layer above the customer org).
        if let Some(isp) = &body.isp {
            let isp = isp.trim();
            let isp_lc = isp.to_ascii_lowercase();
            if !isp.is_empty() && org_lc.as_deref() != Some(isp_lc.as_str()) {
                let mut ie = Entity::new(EntityKind::Organisation, isp, 0.65, &ctx.scan_id);
                ie.tag("shodan");
                ie.tag("isp");
                ie.add_evidence(Evidence::new(SRC, format!("ISP for {ip}")));
                result.push(ie);
            }
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
pub(super) fn target_entity(ip: &str, scan_id: &str) -> Entity {
    Entity::new(EntityKind::IpAddress, ip, 0.90, scan_id)
}
