//! DNS-over-HTTPS resolution via Cloudflare + Google public resolvers.
//!
//! Endpoints (free, no key, unlimited):
//!   GET https://cloudflare-dns.com/dns-query?name={domain}&type={type}
//!   GET https://dns.google/resolve?name={domain}&type={type}
//!
//! Queries A, AAAA, MX, TXT, NS, CNAME records. Extracts IPs from A/AAAA,
//! mail servers from MX, nameservers from NS, SPF/DKIM/DMARC from TXT.

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "doh_resolver";

#[derive(Deserialize)]
struct DohResp {
    #[serde(default, rename = "Answer")]
    answer: Vec<DohRecord>,
    #[serde(default, rename = "Status")]
    status: i32,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct DohRecord {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    rtype: u16,
    #[serde(default)]
    data: String,
}

pub struct DohResolver;

#[async_trait]
impl Module for DohResolver {
    fn name(&self) -> &'static str {
        "doh_resolver"
    }
    fn description(&self) -> &'static str {
        "DNS-over-HTTPS via Cloudflare + Google (A/MX/TXT/NS — free, unlimited)"
    }
    fn priority(&self) -> u8 {
        34
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Url)
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::Domain];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let domain = match target.kind {
            TargetKind::Url => match crate::util::url_util::host_from_url(&target.value) {
                Some(h) => h,
                None => return Ok(ModuleResult::new()),
            },
            _ => target.value.trim().to_string(),
        };
        let domain = domain.as_str();
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        let mut seen: HashSet<String> = HashSet::new();

        for rtype in &["A", "AAAA", "MX", "TXT", "NS", "CNAME"] {
            if ctx.cancel.is_cancelled() {
                break;
            }
            let records = query_doh(domain, rtype, &ctx.http).await;
            for rec in &records {
                match *rtype {
                    "A" | "AAAA" => {
                        let ip = rec.data.trim().trim_matches('"');
                        if !ip.is_empty() && seen.insert(format!("ip:{ip}")) {
                            let mut e = Entity::new(EntityKind::IpAddress, ip, 0.80, &ctx.scan_id);
                            e.tag("dns");
                            e.tag(if *rtype == "A" { "ipv4" } else { "ipv6" });
                            e.add_evidence(
                                Evidence::new(SRC, format!("{rtype} record for {domain}"))
                                    .with_attr("record_type", *rtype),
                            );
                            result.push(e);
                        }
                    }
                    "MX" => {
                        let mx = rec
                            .data
                            .split_whitespace()
                            .last()
                            .unwrap_or("")
                            .trim_end_matches('.');
                        if !mx.is_empty() && mx.contains('.') && seen.insert(format!("mx:{mx}")) {
                            let mut e = Entity::new(EntityKind::Domain, mx, 0.75, &ctx.scan_id);
                            e.tag("dns");
                            e.tag("mx");
                            e.add_evidence(
                                Evidence::new(SRC, format!("MX record for {domain}"))
                                    .with_attr("mx_host", mx),
                            );
                            result.push(e);
                        }
                    }
                    "NS" => {
                        let ns = rec.data.trim().trim_end_matches('.');
                        if !ns.is_empty() && ns.contains('.') && seen.insert(format!("ns:{ns}")) {
                            let mut e = Entity::new(EntityKind::Domain, ns, 0.70, &ctx.scan_id);
                            e.tag("dns");
                            e.tag("nameserver");
                            e.add_evidence(Evidence::new(SRC, format!("NS record for {domain}")));
                            result.push(e);
                        }
                    }
                    "TXT" => {
                        let txt = rec.data.trim().trim_matches('"');
                        if txt.starts_with("v=spf1") {
                            for part in txt.split_whitespace() {
                                if let Some(ip) = part.strip_prefix("ip4:") {
                                    let ip = ip.split('/').next().unwrap_or(ip);
                                    if seen.insert(format!("spf:{ip}")) {
                                        let mut e = Entity::new(
                                            EntityKind::IpAddress,
                                            ip,
                                            0.75,
                                            &ctx.scan_id,
                                        );
                                        e.tag("dns");
                                        e.tag("spf");
                                        e.add_evidence(Evidence::new(
                                            SRC,
                                            format!("SPF include for {domain}"),
                                        ));
                                        result.push(e);
                                    }
                                }
                                if let Some(inc) = part.strip_prefix("include:")
                                    && seen.insert(format!("spfinc:{inc}"))
                                {
                                    let mut e =
                                        Entity::new(EntityKind::Domain, inc, 0.65, &ctx.scan_id);
                                    e.tag("dns");
                                    e.tag("spf-include");
                                    e.add_evidence(Evidence::new(
                                        SRC,
                                        format!("SPF include for {domain}"),
                                    ));
                                    result.push(e);
                                }
                            }
                        }
                    }
                    "CNAME" => {
                        let cname = rec.data.trim().trim_end_matches('.');
                        if !cname.is_empty()
                            && cname.contains('.')
                            && seen.insert(format!("cn:{cname}"))
                        {
                            let mut e = Entity::new(EntityKind::Domain, cname, 0.80, &ctx.scan_id);
                            e.tag("dns");
                            e.tag("cname");
                            e.add_evidence(Evidence::new(SRC, format!("CNAME for {domain}")));
                            result.push(e);
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(result)
    }
}

async fn query_doh(domain: &str, rtype: &str, http: &reqwest::Client) -> Vec<DohRecord> {
    let cf_url = format!("https://cloudflare-dns.com/dns-query?name={domain}&type={rtype}");
    let resp = http
        .get(&cf_url)
        .header("Accept", "application/dns-json")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await;
    if let Ok(r) = resp
        && let Ok(data) = r.json::<DohResp>().await
        && data.status == 0
    {
        return data.answer;
    }
    let google_url = format!("https://dns.google/resolve?name={domain}&type={rtype}");
    let resp = http
        .get(&google_url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await;
    if let Ok(r) = resp
        && let Ok(data) = r.json::<DohResp>().await
        && data.status == 0
    {
        return data.answer;
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_domain_only() {
        assert!(DohResolver.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(!DohResolver.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    }

    #[test]
    fn cost_is_free() {
        assert!(matches!(
            DohResolver.cost(),
            crate::core::module::ModuleCost::Free
        ));
    }

    #[test]
    fn doh_resp_deser() {
        let json =
            r#"{"Status":0,"Answer":[{"name":"example.com.","type":1,"data":"93.184.216.34"}]}"#;
        let resp: DohResp = serde_json::from_str(json).unwrap();
        assert_eq!(resp.answer.len(), 1);
        assert_eq!(resp.answer[0].data, "93.184.216.34");
    }
}
