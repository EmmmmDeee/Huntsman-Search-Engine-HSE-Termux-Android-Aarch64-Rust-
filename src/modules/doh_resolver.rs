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
struct DohRecord {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    rtype: u16,
    #[serde(default)]
    data: String,
}

/// Human-readable name for a DNS record-type code (the numeric `type` the
/// resolver returns on each answer record).
fn rtype_name(rtype: u16) -> &'static str {
    match rtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        _ => "?",
    }
}

/// Map one DoH answer record to its `(dedup_key, Entity)` findings, dispatched on
/// the record's **actual** type. **Pure** (no IO) so the per-type classification
/// is unit-tested. Keying off `rec.rtype` (recovered from a previously-dead
/// field) rather than the *queried* type fixes a real bug: an `A`/`AAAA` query
/// whose answer carries an intermediate CNAME used to mint that CNAME's hostname
/// as a bogus `IpAddress`; it is now correctly emitted as a `Domain`. The record
/// `name` is surfaced as provenance (it diverges from the query along a CNAME
/// chain).
fn record_to_findings(rec: &DohRecord, domain: &str, scan_id: &str) -> Vec<(String, Entity)> {
    let name = rec.name.trim();
    let prov = |ev: Evidence| -> Evidence {
        if name.is_empty() {
            ev
        } else {
            ev.with_attr("record_name", name)
        }
    };
    let mut out: Vec<(String, Entity)> = Vec::new();

    match rec.rtype {
        // A / AAAA → IP address.
        1 | 28 => {
            let ip = rec.data.trim().trim_matches('"');
            if !ip.is_empty() {
                let label = rtype_name(rec.rtype);
                let mut e = Entity::new(EntityKind::IpAddress, ip, 0.80, scan_id);
                e.tag("dns");
                e.tag(if rec.rtype == 1 { "ipv4" } else { "ipv6" });
                e.add_evidence(prov(
                    Evidence::new(SRC, format!("{label} record for {domain}"))
                        .with_attr("record_type", label),
                ));
                out.push((format!("ip:{ip}"), e));
            }
        }
        // MX → mail-server domain.
        15 => {
            let mx = rec
                .data
                .split_whitespace()
                .last()
                .unwrap_or("")
                .trim_end_matches('.');
            if !mx.is_empty() && mx.contains('.') {
                let mut e = Entity::new(EntityKind::Domain, mx, 0.75, scan_id);
                e.tag("dns");
                e.tag("mx");
                e.add_evidence(prov(
                    Evidence::new(SRC, format!("MX record for {domain}")).with_attr("mx_host", mx),
                ));
                out.push((format!("mx:{mx}"), e));
            }
        }
        // NS → nameserver domain.
        2 => {
            let ns = rec.data.trim().trim_end_matches('.');
            if !ns.is_empty() && ns.contains('.') {
                let mut e = Entity::new(EntityKind::Domain, ns, 0.70, scan_id);
                e.tag("dns");
                e.tag("nameserver");
                e.add_evidence(prov(Evidence::new(SRC, format!("NS record for {domain}"))));
                out.push((format!("ns:{ns}"), e));
            }
        }
        // TXT → SPF ip4: hosts + include: domains.
        16 => {
            let txt = rec.data.trim().trim_matches('"');
            if txt.starts_with("v=spf1") {
                for part in txt.split_whitespace() {
                    if let Some(ip) = part.strip_prefix("ip4:") {
                        let ip = ip.split('/').next().unwrap_or(ip);
                        if !ip.is_empty() {
                            let mut e = Entity::new(EntityKind::IpAddress, ip, 0.75, scan_id);
                            e.tag("dns");
                            e.tag("spf");
                            e.add_evidence(prov(Evidence::new(
                                SRC,
                                format!("SPF include for {domain}"),
                            )));
                            out.push((format!("spf:{ip}"), e));
                        }
                    }
                    if let Some(inc) = part.strip_prefix("include:")
                        && !inc.is_empty()
                    {
                        let mut e = Entity::new(EntityKind::Domain, inc, 0.65, scan_id);
                        e.tag("dns");
                        e.tag("spf-include");
                        e.add_evidence(prov(Evidence::new(
                            SRC,
                            format!("SPF include for {domain}"),
                        )));
                        out.push((format!("spfinc:{inc}"), e));
                    }
                }
            }
        }
        // CNAME → canonical-name domain.
        5 => {
            let cname = rec.data.trim().trim_end_matches('.');
            if !cname.is_empty() && cname.contains('.') {
                let mut e = Entity::new(EntityKind::Domain, cname, 0.80, scan_id);
                e.tag("dns");
                e.tag("cname");
                e.add_evidence(prov(Evidence::new(SRC, format!("CNAME for {domain}"))));
                out.push((format!("cn:{cname}"), e));
            }
        }
        _ => {}
    }

    out
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
                // Dispatch on each answer record's ACTUAL type, not the queried
                // one — an A/AAAA answer can carry an intermediate CNAME record.
                for (key, entity) in record_to_findings(rec, domain, &ctx.scan_id) {
                    if seen.insert(key) {
                        result.push(entity);
                    }
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

    fn rec(name: &str, rtype: u16, data: &str) -> DohRecord {
        DohRecord {
            name: name.into(),
            rtype,
            data: data.into(),
        }
    }

    fn only(rec: &DohRecord, domain: &str) -> (String, Entity) {
        let mut f = record_to_findings(rec, domain, "s");
        assert_eq!(f.len(), 1, "expected exactly one finding");
        f.pop().unwrap()
    }

    #[test]
    fn rtype_name_maps_known_codes() {
        assert_eq!(rtype_name(1), "A");
        assert_eq!(rtype_name(28), "AAAA");
        assert_eq!(rtype_name(5), "CNAME");
        assert_eq!(rtype_name(15), "MX");
        assert_eq!(rtype_name(999), "?");
    }

    #[test]
    fn a_record_yields_ipv4_with_provenance() {
        let (key, e) = only(&rec("example.com.", 1, "93.184.216.34"), "example.com");
        assert_eq!(key, "ip:93.184.216.34");
        assert_eq!(e.kind, EntityKind::IpAddress);
        assert!(e.has_tag("ipv4") && e.has_tag("dns") && !e.has_tag("ipv6"));
        let a = &e.evidence[0].attributes;
        assert_eq!(a.get("record_type").map(String::as_str), Some("A"));
        assert_eq!(
            a.get("record_name").map(String::as_str),
            Some("example.com.")
        );
    }

    #[test]
    fn aaaa_record_yields_ipv6() {
        let (_, e) = only(
            &rec("x.com.", 28, "2606:2800:220:1:248:1893:25c8:1946"),
            "x.com",
        );
        assert_eq!(e.kind, EntityKind::IpAddress);
        assert!(e.has_tag("ipv6") && !e.has_tag("ipv4"));
    }

    #[test]
    fn cname_in_an_a_answer_is_a_domain_not_a_bogus_ip() {
        // Regression: the old code processed every answer record AS the queried
        // type, so a CNAME record returned alongside an A query became a bogus
        // IpAddress entity holding a hostname. Dispatching on rec.rtype fixes it.
        let (key, e) = only(
            &rec("www.example.com.", 5, "cdn.example.net."),
            "www.example.com",
        );
        assert_eq!(
            e.kind,
            EntityKind::Domain,
            "CNAME must not become an IpAddress"
        );
        assert_eq!(e.value, "cdn.example.net");
        assert!(e.has_tag("cname"));
        assert!(key.starts_with("cn:"));
    }

    #[test]
    fn mx_record_extracts_host_from_priority_pair() {
        let (key, e) = only(&rec("x.com.", 15, "10 mail.x.com."), "x.com");
        assert_eq!(key, "mx:mail.x.com");
        assert_eq!(e.kind, EntityKind::Domain);
        assert!(e.has_tag("mx"));
        assert_eq!(
            e.evidence[0].attributes.get("mx_host").map(String::as_str),
            Some("mail.x.com")
        );
    }

    #[test]
    fn txt_spf_yields_ip_and_include_findings() {
        let f = record_to_findings(
            &rec(
                "x.com.",
                16,
                "\"v=spf1 ip4:198.51.100.7 include:_spf.google.com ~all\"",
            ),
            "x.com",
            "s",
        );
        let ip = f
            .iter()
            .find(|(_, e)| e.kind == EntityKind::IpAddress)
            .unwrap();
        assert_eq!(ip.1.value, "198.51.100.7");
        assert!(ip.1.has_tag("spf"));
        let inc = f
            .iter()
            .find(|(_, e)| e.kind == EntityKind::Domain)
            .unwrap();
        assert_eq!(inc.1.value, "_spf.google.com");
        assert!(inc.1.has_tag("spf-include"));
    }
}
