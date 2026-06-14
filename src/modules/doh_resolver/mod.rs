//! DNS-over-HTTPS resolution via Cloudflare + Google public resolvers.
//!
//! Endpoints (free, no key, unlimited):
//!   `GET https://cloudflare-dns.com/dns-query?name={domain}&type={type}`
//!   `GET https://dns.google/resolve?name={domain}&type={type}`
//!
//! Queries A, AAAA, MX, TXT, NS, CNAME records. Extracts IPs from A/AAAA,
//! mail servers from MX, nameservers from NS, SPF/DKIM/DMARC from TXT.

use async_trait::async_trait;
use futures::future::join_all;
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

/// The record types we query, in order.
const RECORD_TYPES: &[&str] = &["A", "AAAA", "MX", "TXT", "NS", "CNAME"];

/// Reconstruct a TXT record's logical value from the DoH JSON presentation form.
/// **Pure.** A TXT record is one or more character-strings; the resolvers return
/// a multi-string record as space-separated double-quoted chunks
/// (`"v=spf1 ip4:… " "include:… -all"`) and a single string bare. Per RFC 1035
/// §3.3.14 the strings concatenate with **no** separator, so a long (chunked)
/// SPF/DKIM record reads correctly instead of keeping the stray `" "` chunk
/// boundaries that `trim_matches('"')` left behind. Bare data passes through;
/// `\"`/`\\` escapes inside a chunk are decoded.
fn unquote_txt(data: &str) -> String {
    if !data.starts_with('"') {
        return data.to_string();
    }
    let bytes = data.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut in_quotes = false;
    while i < bytes.len() {
        let c = bytes[i];
        if !in_quotes {
            in_quotes = c == b'"'; // opening quote; inter-chunk spaces ignored
            i += 1;
        } else if c == b'\\' && i + 1 < bytes.len() {
            out.push(bytes[i + 1]); // `\"` / `\\` → literal
            i += 2;
        } else if c == b'"' {
            in_quotes = false; // closing quote
            i += 1;
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Resolve a target to the domain to query. **Pure**: a `Url` is reduced to its
/// host; any other kind is trimmed. Returns `None` when nothing queryable remains.
fn target_domain(kind: TargetKind, value: &str) -> Option<String> {
    let domain = match kind {
        TargetKind::Url => crate::util::url_util::host_from_url(value)?,
        _ => value.trim().to_string(),
    };
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

/// Map one record type's answers to entities. **Pure** (no network/IO): parses
/// each record per its type — A/AAAA → `IpAddress`, MX/NS/CNAME → `Domain`, and
/// SPF `TXT` → the `ip4:`/`ip6:`/`include:` members — deduplicating across the whole
/// resolution via the shared `seen` set (keyed by a type prefix so an IP from an
/// A record and an SPF `ip4:` of the same value are distinct). Skips blank /
/// dotless hosts. `rtype` outside [`RECORD_TYPES`] yields nothing.
fn records_for_type(
    rtype: &str,
    records: &[DohRecord],
    domain: &str,
    seen: &mut HashSet<String>,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    for rec in records {
        match rtype {
            "A" | "AAAA" => {
                let ip = rec.data.trim().trim_matches('"');
                if !ip.is_empty() && seen.insert(format!("ip:{ip}")) {
                    let mut e = Entity::new(EntityKind::IpAddress, ip, 0.80, scan_id);
                    e.tag("dns");
                    e.tag(if rtype == "A" { "ipv4" } else { "ipv6" });
                    e.add_evidence(
                        Evidence::new(SRC, format!("{rtype} record for {domain}"))
                            .with_attr("record_type", rtype),
                    );
                    out.push(e);
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
                    let mut e = Entity::new(EntityKind::Domain, mx, 0.75, scan_id);
                    e.tag("dns");
                    e.tag("mx");
                    e.add_evidence(
                        Evidence::new(SRC, format!("MX record for {domain}"))
                            .with_attr("mx_host", mx),
                    );
                    out.push(e);
                }
            }
            "NS" => {
                let ns = rec.data.trim().trim_end_matches('.');
                if !ns.is_empty() && ns.contains('.') && seen.insert(format!("ns:{ns}")) {
                    let mut e = Entity::new(EntityKind::Domain, ns, 0.70, scan_id);
                    e.tag("dns");
                    e.tag("nameserver");
                    e.add_evidence(Evidence::new(SRC, format!("NS record for {domain}")));
                    out.push(e);
                }
            }
            "TXT" => {
                let txt = unquote_txt(rec.data.trim());
                if crate::util::spf::is_spf(&txt) {
                    for member in crate::util::spf::members(&txt) {
                        match member {
                            crate::util::spf::Member::Ip(ip) => {
                                if seen.insert(format!("spf:{ip}")) {
                                    let mut e =
                                        Entity::new(EntityKind::IpAddress, ip, 0.75, scan_id);
                                    e.tag("dns");
                                    e.tag("spf");
                                    e.add_evidence(Evidence::new(
                                        SRC,
                                        format!("SPF authorised sender for {domain}"),
                                    ));
                                    out.push(e);
                                }
                            }
                            crate::util::spf::Member::Include(inc) => {
                                if seen.insert(format!("spfinc:{inc}")) {
                                    let mut e = Entity::new(EntityKind::Domain, inc, 0.65, scan_id);
                                    e.tag("dns");
                                    e.tag("spf-include");
                                    e.add_evidence(Evidence::new(
                                        SRC,
                                        format!("SPF include for {domain}"),
                                    ));
                                    out.push(e);
                                }
                            }
                            crate::util::spf::Member::Redirect(red) => {
                                if seen.insert(format!("spfinc:{red}")) {
                                    let mut e = Entity::new(EntityKind::Domain, red, 0.65, scan_id);
                                    e.tag("dns");
                                    e.tag("spf-redirect");
                                    e.add_evidence(Evidence::new(
                                        SRC,
                                        format!("SPF redirect for {domain}"),
                                    ));
                                    out.push(e);
                                }
                            }
                        }
                    }
                }
            }
            "CNAME" => {
                let cname = rec.data.trim().trim_end_matches('.');
                if !cname.is_empty() && cname.contains('.') && seen.insert(format!("cn:{cname}")) {
                    let mut e = Entity::new(EntityKind::Domain, cname, 0.80, scan_id);
                    e.tag("dns");
                    e.tag("cname");
                    e.add_evidence(Evidence::new(SRC, format!("CNAME for {domain}")));
                    out.push(e);
                }
            }
            _ => {}
        }
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

    fn attack_techniques(&self) -> &'static [&'static str] {
        // DNS-over-HTTPS resolution — ATT&CK DNS (T1590.002).
        &["T1590.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::Domain];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(domain) = target_domain(target.kind, &target.value) else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        let mut seen: HashSet<String> = HashSet::new();

        let futures = RECORD_TYPES.iter().map(|rtype| {
            let domain = domain.as_str();
            let http = ctx.http.clone();
            async move { (*rtype, query_doh(domain, rtype, &http).await) }
        });
        let all_records = join_all(futures).await;
        for (rtype, records) in all_records {
            result.entities.extend(records_for_type(
                rtype,
                &records,
                &domain,
                &mut seen,
                &ctx.scan_id,
            ));
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
mod tests;
