//! DNS-over-HTTPS resolution via Cloudflare + Google public resolvers.
//!
//! Endpoints (free, no key, unlimited):
//!   `GET https://cloudflare-dns.com/dns-query?name={domain}&type={type}`
//!   `GET https://dns.google/resolve?name={domain}&type={type}`
//!
//! Queries A, AAAA, MX, TXT, NS, CNAME, SOA records. Extracts IPs from A/AAAA,
//! mail servers from MX, nameservers from NS, SPF/DKIM from TXT, zone admin email
//! and primary NS from SOA, and DMARC reporting addresses from a dedicated
//! `_dmarc.{domain}` TXT query (RFC 7489 §6.6.3).

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
        6 => Some("SOA"),
        15 => Some("MX"),
        16 => Some("TXT"),
        28 => Some("AAAA"),
        _ => None,
    }
}

/// The record types we query at the apex domain, in order.
const RECORD_TYPES: &[&str] = &["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"];

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
                            // a: and mx: mechanism targets are domain pivots but
                            // doh_resolver doesn't resolve them independently — the
                            // spf module already handles them via its own DNS pass.
                            crate::util::spf::Member::A(_) | crate::util::spf::Member::Mx(_) => {}
                        }
                    }
                } else if txt.to_ascii_lowercase().starts_with("v=dmarc1") {
                    // DMARC record: extract rua/ruf reporting mailto: URIs.
                    // These reveal the organization's DMARC monitoring addresses —
                    // often a third-party service or internal security team inbox.
                    for field in ["rua=", "ruf="] {
                        if let Some(val_start) = txt.to_ascii_lowercase().find(field) {
                            let after = &txt[val_start + field.len()..];
                            // DMARC tag-value pairs are `;`-delimited (RFC 7489 §6.3):
                            // clip the URI list before the next tag, then split on `,`.
                            let value_part = after.split(';').next().unwrap_or(after).trim();
                            for uri in value_part.split(',').map(str::trim) {
                                // Strip trailing `;` or whitespace.
                                let uri = uri.trim_end_matches(';').trim();
                                if let Some(addr) = uri.strip_prefix("mailto:") {
                                    let addr = addr.trim();
                                    // May have `!size` suffix: `dmarc@example.com!10m`.
                                    let addr = addr.split('!').next().unwrap_or(addr).trim();
                                    if addr.contains('@') && seen.insert(format!("dmarc:{addr}")) {
                                        let mut e =
                                            Entity::new(EntityKind::Email, addr, 0.60, scan_id);
                                        e.tag("dns");
                                        e.tag("dmarc-reporting");
                                        e.add_evidence(
                                            Evidence::new(
                                                SRC,
                                                format!(
                                                    "DMARC {} reporting address for {domain}",
                                                    &field[..3]
                                                ),
                                            )
                                            .with_attr("dmarc_field", &field[..3])
                                            .with_attr("domain", domain),
                                        );
                                        out.push(e);
                                    }
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
            "SOA" => {
                // SOA RDATA: `<mname> <rname> <serial> <refresh> <retry> <expire> <minimum>`
                // `rname` is the zone admin's email with `@` encoded as `.`.
                // Per RFC 1035 §3.3.13 the first unescaped `.` in the local-part
                // marks the boundary: `hostmaster.example.com.` → `hostmaster@example.com`.
                // We extract the email and the primary nameserver (mname).
                let parts: Vec<&str> = rec.data.split_whitespace().collect();
                if parts.len() >= 2 {
                    // Primary nameserver.
                    let mname = parts[0].trim_end_matches('.');
                    if mname.contains('.') && seen.insert(format!("soa-ns:{mname}")) {
                        let mut e = Entity::new(EntityKind::Domain, mname, 0.72, scan_id);
                        e.tag("dns");
                        e.tag("soa");
                        e.tag("nameserver");
                        e.add_evidence(
                            base(format!("SOA primary nameserver for {domain}"))
                                .with_attr("record_type", "SOA")
                                .with_attr("role", "mname"),
                        );
                        out.push(e);
                    }
                    // Zone admin email from RNAME.
                    let rname = parts[1].trim_end_matches('.');
                    if let Some(email) = soa_rname_to_email(rname)
                        && email.contains('@')
                        && seen.insert(format!("soa-email:{}", email.to_ascii_lowercase()))
                    {
                        let mut e = Entity::new(EntityKind::Email, &email, 0.62, scan_id);
                        e.tag("dns");
                        e.tag("soa");
                        e.tag("zone-admin");
                        e.add_evidence(
                            base(format!("SOA zone admin email for {domain}"))
                                .with_attr("record_type", "SOA")
                                .with_attr("rname_raw", rname),
                        );
                        out.push(e);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Convert an SOA RNAME field to an email address. Per RFC 1035 §3.3.13 the
/// RNAME is a domain-name where the first unescaped `.` represents `@`.
/// `hostmaster.example.com` → `hostmaster@example.com`.
/// `john\.doe.example.com` → `john.doe@example.com` (escaped dot in local-part).
/// Returns `None` when the result contains no `@` (single-label or malformed).
fn soa_rname_to_email(rname: &str) -> Option<String> {
    let mut local = String::new();
    let mut bytes = rname.as_bytes().iter().copied().peekable();
    loop {
        match bytes.next()? {
            b'\\' => {
                // Escaped byte: include the literal next byte in the local-part.
                if let Some(next) = bytes.next() {
                    local.push(next as char);
                } else {
                    break;
                }
            }
            b'.' => break, // First unescaped dot → the `@` boundary.
            c => local.push(c as char),
        }
    }
    if local.is_empty() {
        return None;
    }
    let rest: String = bytes.map(|b| b as char).collect();
    let domain = rest.trim_end_matches('.');
    if domain.is_empty() || !domain.contains('.') {
        return None;
    }
    Some(format!("{local}@{domain}"))
}

pub struct DohResolver;

#[async_trait]
impl Module for DohResolver {
    fn name(&self) -> &'static str {
        "doh_resolver"
    }
    fn description(&self) -> &'static str {
        "DNS-over-HTTPS via Cloudflare + Google (A/AAAA/MX/TXT/NS/CNAME/SOA + DMARC — free)"
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

        // DMARC lives at `_dmarc.{domain}` (RFC 7489 §6.6.3), not at the apex.
        // Query it separately so the parser sees the correct subdomain context.
        if !ctx.cancel.is_cancelled() {
            let dmarc_domain = format!("_dmarc.{domain}");
            let dmarc_records = query_doh(&dmarc_domain, "TXT", &ctx.http).await;
            result.entities.extend(records_for_type(
                "TXT",
                &dmarc_records,
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
