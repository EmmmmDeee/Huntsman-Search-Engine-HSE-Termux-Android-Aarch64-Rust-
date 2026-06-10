//! DNS-over-HTTPS resolution via Cloudflare + Google public resolvers.
//!
//! Endpoints (free, no key, unlimited):
//!   `GET https://cloudflare-dns.com/dns-query?name={domain}&type={type}`
//!   `GET https://dns.google/resolve?name={domain}&type={type}`
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

        for rtype in RECORD_TYPES {
            if ctx.cancel.is_cancelled() {
                break;
            }
            let records = query_doh(&domain, rtype, &ctx.http).await;
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

    fn rec(data: &str) -> DohRecord {
        DohRecord {
            name: String::new(),
            rtype: 0,
            data: data.to_string(),
        }
    }

    fn run(rtype: &str, datas: &[&str]) -> Vec<Entity> {
        let records: Vec<DohRecord> = datas.iter().map(|d| rec(d)).collect();
        let mut seen = HashSet::new();
        records_for_type(rtype, &records, "example.com", &mut seen, "s")
    }

    #[test]
    fn target_domain_reduces_url_and_trims() {
        assert_eq!(
            target_domain(TargetKind::Domain, "  Example.com "),
            Some("Example.com".into())
        );
        assert_eq!(
            target_domain(TargetKind::Url, "https://host.example.com/a?b=1"),
            Some("host.example.com".into())
        );
        assert_eq!(target_domain(TargetKind::Domain, "   "), None);
    }

    #[test]
    fn a_and_aaaa_become_tagged_ip_entities() {
        let a = run("A", &["93.184.216.34"]);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].kind, EntityKind::IpAddress);
        assert!(a[0].has_tag("dns") && a[0].has_tag("ipv4"));
        assert_eq!(
            a[0].evidence[0]
                .attributes
                .get("record_type")
                .map(String::as_str),
            Some("A")
        );

        let aaaa = run("AAAA", &["2606:2800:220:1:248:1893:25c8:1946"]);
        assert!(aaaa[0].has_tag("ipv6"));
    }

    #[test]
    fn mx_takes_last_field_and_requires_a_dot() {
        // Priority + host; only the host is kept, trailing dot stripped.
        let mx = run("MX", &["10 mail.example.com."]);
        assert_eq!(mx.len(), 1);
        assert_eq!(mx[0].kind, EntityKind::Domain);
        assert_eq!(mx[0].value, "mail.example.com");
        assert!(mx[0].has_tag("mx"));
        // A dotless MX host (e.g. "0 .") is rejected.
        assert!(run("MX", &["0 ."]).is_empty());
    }

    #[test]
    fn spf_txt_extracts_ip4_ip6_and_includes_others_ignored() {
        let out = run(
            "TXT",
            &[
                "v=spf1 ip4:198.51.100.0/24 ip6:2001:db8::/32 include:_spf.google.com -all",
                "some-unrelated-txt-record",
            ],
        );
        // IPv4 + IPv6 (both CIDR-stripped) + one include domain; non-SPF ignored.
        assert_eq!(out.len(), 3);
        let ips: Vec<&str> = out
            .iter()
            .filter(|e| e.kind == EntityKind::IpAddress)
            .map(|e| e.value.as_str())
            .collect();
        assert!(ips.contains(&"198.51.100.0"));
        // IPv6 member surfaced with its internal colons intact (CIDR removed).
        assert!(ips.contains(&"2001:db8::"));
        let first_ip = out
            .iter()
            .find(|e| e.kind == EntityKind::IpAddress)
            .unwrap();
        assert!(first_ip.has_tag("spf"));
        let inc = out.iter().find(|e| e.kind == EntityKind::Domain).unwrap();
        assert_eq!(inc.value, "_spf.google.com");
        assert!(inc.has_tag("spf-include"));
    }

    #[test]
    fn unquote_txt_reconstructs_single_and_chunked_records() {
        // Bare (unquoted) single string — passthrough.
        assert_eq!(unquote_txt("v=spf1 -all"), "v=spf1 -all");
        // Single quoted string.
        assert_eq!(unquote_txt(r#""v=spf1 -all""#), "v=spf1 -all");
        // Two chunks: concatenated with NO separator (the space lives inside
        // chunk 1, at the operator's split point) — the stray `" "` is gone.
        assert_eq!(
            unquote_txt(r#""v=spf1 ip4:198.51.100.0/24 " "include:_spf.example.com -all""#),
            "v=spf1 ip4:198.51.100.0/24 include:_spf.example.com -all"
        );
        // A token split mid-word across the chunk boundary rejoins cleanly.
        assert_eq!(unquote_txt(r#""inclu" "de:x.com""#), "include:x.com");
        // Escaped quote inside a chunk is decoded to a literal.
        assert_eq!(unquote_txt(r#""a\"b""#), "a\"b");
    }

    #[test]
    fn chunked_spf_record_parses_into_members() {
        // The whole point: a long SPF record split across two DoH chunks must
        // still yield its ip4 + include members (it would not with the old
        // trim_matches: the boundary tokens were mangled).
        let out = run(
            "TXT",
            &[r#""v=spf1 ip4:203.0.113.7 " "include:_spf.example.org -all""#],
        );
        assert!(
            out.iter()
                .any(|e| e.kind == EntityKind::IpAddress && e.value == "203.0.113.7")
        );
        assert!(
            out.iter()
                .any(|e| e.kind == EntityKind::Domain && e.value == "_spf.example.org")
        );
    }

    #[test]
    fn spf_redirect_surfaces_target_as_domain() {
        let out = run("TXT", &["v=spf1 redirect=_spf.example.net"]);
        let red = out.iter().find(|e| e.kind == EntityKind::Domain).unwrap();
        assert_eq!(red.value, "_spf.example.net");
        assert!(red.has_tag("spf-redirect"));
    }

    #[test]
    fn spf_skips_empty_ip4_and_dotless_or_empty_include() {
        // Bare `ip4:`, `ip4:/24`, dotless `include:`, and empty `include:` must
        // not produce blank/garbage entities.
        let out = run(
            "TXT",
            &["v=spf1 ip4: ip4:/24 include: include:localhost -all"],
        );
        assert!(out.is_empty());
    }

    #[test]
    fn dedup_is_cross_type_and_prefixed() {
        // Same value as both an A record and an SPF ip4 → distinct (prefixed keys),
        // but a repeated A record within the run is deduped.
        let mut seen = HashSet::new();
        let a = records_for_type(
            "A",
            &[rec("1.2.3.4"), rec("1.2.3.4")],
            "example.com",
            &mut seen,
            "s",
        );
        assert_eq!(a.len(), 1); // intra-run dedup
        let spf = records_for_type(
            "TXT",
            &[rec("v=spf1 ip4:1.2.3.4 -all")],
            "example.com",
            &mut seen,
            "s",
        );
        // Different key prefix (spf: vs ip:) → still surfaced.
        assert_eq!(spf.len(), 1);
        assert!(spf[0].has_tag("spf"));
    }

    #[test]
    fn ns_and_cname_strip_trailing_dot_and_need_a_dot() {
        assert_eq!(run("NS", &["ns1.example.com."])[0].value, "ns1.example.com");
        assert_eq!(
            run("CNAME", &["target.cdn.net."])[0].value,
            "target.cdn.net"
        );
        assert!(run("CNAME", &["localhost"]).is_empty());
    }
}
