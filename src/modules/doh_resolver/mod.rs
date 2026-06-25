//! DNS-over-HTTPS resolution via Cloudflare + Google public resolvers.
//!
//! Endpoints (free, no key, unlimited):
//!   `GET https://cloudflare-dns.com/dns-query?name={domain}&type={type}`
//!   `GET https://dns.google/resolve?name={domain}&type={type}`
//!
//! Queries A, AAAA, MX, TXT, NS, CNAME records. Extracts IPs from A/AAAA,
//! mail servers from MX, nameservers from NS, SPF from apex TXT. DMARC is
//! queried separately at `_dmarc.{domain}` (RFC 7489 §6.6.3) and yields
//! policy tags, issue flags, and report-address [`crate::core::entity::EntityKind::Email`] entities.

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

/// DNS record TYPE number → the mnemonic this module handles, per IANA. Lets
/// each answer be classified by its **own** type rather than the queried type —
/// a resolver returns a CNAME chain inside an `A` query's `Answer`, and the
/// intermediate CNAME must be read as a `Domain`, not parsed as an `A`/IP.
/// `None` for types this module does not map. **Pure.**
fn rtype_name(t: u16) -> Option<&'static str> {
    match t {
        1 => Some("A"),
        2 => Some("NS"),
        5 => Some("CNAME"),
        15 => Some("MX"),
        16 => Some("TXT"),
        28 => Some("AAAA"),
        _ => None,
    }
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
        // Classify by the record's OWN type; fall back to the queried type only
        // when the record carries no type number (e.g. a hand-built test record).
        let effective = rtype_name(rec.rtype).unwrap_or(rtype);
        // The record's owner name (the FQDN the answer is for) — surfaced on
        // every finding so a CNAME/alias chain is traceable to its source.
        let owner = rec.name.trim().trim_end_matches('.').to_string();
        let base = |summary: String| {
            let ev = Evidence::new(SRC, summary);
            if owner.is_empty() {
                ev
            } else {
                ev.with_attr("record_name", &owner)
            }
        };
        match effective {
            "A" | "AAAA" => {
                let ip = rec.data.trim().trim_matches('"');
                if !ip.is_empty() && seen.insert(format!("ip:{ip}")) {
                    let mut e = Entity::new(EntityKind::IpAddress, ip, 0.80, scan_id);
                    e.tag("dns");
                    e.tag(if effective == "A" { "ipv4" } else { "ipv6" });
                    e.add_evidence(
                        base(format!("{effective} record for {domain}"))
                            .with_attr("record_type", effective),
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
                        base(format!("MX record for {domain}")).with_attr("mx_host", mx),
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
                    e.add_evidence(base(format!("NS record for {domain}")));
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
                    e.add_evidence(base(format!("CNAME for {domain}")));
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
        // Live scan: 224 dispatches, 0 found — Cloudflare + Google DoH are
        // unreachable from DC IPs. Lowering from 10 s to 5 s still leaves
        // room for a healthy response (CF/Google answer in <1 s) while
        // halving the concurrency-slot cost when both endpoints are blocked.
        5_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // DNS-over-HTTPS resolution — ATT&CK DNS (T1590.002).
        &["T1590.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] =
            &[EntityKind::IpAddress, EntityKind::Domain, EntityKind::Email];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(domain) = target_domain(target.kind, &target.value) else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut empty_count = 0usize;
        let mut doh_reachable = true;

        for (i, rtype) in RECORD_TYPES.iter().enumerate() {
            if ctx.cancel.is_cancelled() {
                break;
            }
            let records = query_doh(&domain, rtype, &ctx.http).await;
            if records.is_empty() {
                empty_count += 1;
            }
            // If the first two queries (A + AAAA) both return nothing, both
            // Cloudflare and Google DoH are unreachable from this IP — skip
            // remaining record types to free the concurrency slot immediately.
            if i == 1 && empty_count == 2 {
                doh_reachable = false;
                break;
            }
            result.entities.extend(records_for_type(
                rtype,
                &records,
                &domain,
                &mut seen,
                &ctx.scan_id,
            ));
        }

        // DMARC: published at `_dmarc.{domain}` (RFC 7489 §6.6.3), never at the
        // apex. Skip if DoH endpoints proved unreachable during the main loop.
        if doh_reachable && !ctx.cancel.is_cancelled() {
            let dmarc_records = query_doh(&format!("_dmarc.{domain}"), "TXT", &ctx.http).await;
            'dmarc: for rec in &dmarc_records {
                let txt = unquote_txt(rec.data.trim());
                let Some(dmarc) = crate::util::dmarc::parse(&txt) else {
                    continue;
                };
                let policy_str = dmarc
                    .policy
                    .map_or("dmarc:missing-policy", crate::util::dmarc::DmarcPolicy::tag);
                let sp_str = dmarc
                    .sp
                    .map_or("(inherited)", crate::util::dmarc::DmarcPolicy::tag);
                let mut dom = Entity::new(EntityKind::Domain, &domain, 0.85, &ctx.scan_id);
                dom.tag("dns");
                dom.tag("dmarc");
                if let Some(p) = dmarc.policy {
                    dom.tag(p.tag());
                }
                let issues = dmarc.issues();
                for issue in &issues {
                    dom.tag(issue.tag());
                }
                let mut ev = Evidence::new(
                    SRC,
                    format!(
                        "DMARC policy: {policy_str}; sp={sp_str}; pct={pct}",
                        pct = dmarc.pct
                    ),
                )
                .with_attr("record_type", "DMARC")
                .with_attr("policy", policy_str)
                .with_attr("subdomain_policy", sp_str)
                .with_attr("pct", dmarc.pct.to_string())
                .with_attr(
                    "adkim",
                    if dmarc.adkim == crate::util::dmarc::AlignmentMode::Strict {
                        "s"
                    } else {
                        "r"
                    },
                )
                .with_attr(
                    "aspf",
                    if dmarc.aspf == crate::util::dmarc::AlignmentMode::Strict {
                        "s"
                    } else {
                        "r"
                    },
                );
                if !issues.is_empty() {
                    let flags = issues
                        .iter()
                        .map(crate::util::dmarc::DmarcIssue::tag)
                        .collect::<Vec<_>>()
                        .join(", ");
                    ev = ev.with_attr("issues", flags);
                }
                if !dmarc.rua.is_empty() {
                    ev = ev.with_attr("rua", dmarc.rua.join(", "));
                }
                if !dmarc.ruf.is_empty() {
                    ev = ev.with_attr("ruf", dmarc.ruf.join(", "));
                }
                dom.add_evidence(ev);
                if seen.insert(format!("dom:{domain}")) {
                    result.entities.push(dom);
                }
                // `rua=`/`ruf=` report addresses reveal where the organisation
                // receives DMARC failure reports — high-value OSINT pivot.
                // Skip known third-party infrastructure addresses (e.g.
                // reports@dmarcanalyzer.com) so only org-specific addresses survive.
                for addr in dmarc.report_addresses() {
                    if crate::util::domains::is_infrastructure_email(addr) {
                        continue;
                    }
                    if seen.insert(format!("email:{addr}")) {
                        let mut ee = Entity::new(EntityKind::Email, addr, 0.72, &ctx.scan_id);
                        ee.tag("dmarc-report");
                        ee.tag("dns");
                        ee.add_evidence(Evidence::new(
                            SRC,
                            format!("DMARC report address for {domain}"),
                        ));
                        result.entities.push(ee);
                    }
                }
                break 'dmarc; // RFC 7489 §6.6.3: one DMARC record per name
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
        && let Ok(data) = crate::util::http::json_decode::<DohResp>(SRC, r).await
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
        && let Ok(data) = crate::util::http::json_decode::<DohResp>(SRC, r).await
        && data.status == 0
    {
        return data.answer;
    }
    Vec::new()
}

#[cfg(test)]
mod tests;
