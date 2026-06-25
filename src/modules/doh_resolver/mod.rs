//! DNS-over-HTTPS resolution via Cloudflare + Google public resolvers.
//!
//! Endpoints (free, no key, unlimited):
//!   `GET https://cloudflare-dns.com/dns-query?name={domain}&type={type}`
//!   `GET https://dns.google/resolve?name={domain}&type={type}`
//!
//! **Domain targets** — queries A, AAAA, MX, TXT, NS, CNAME, SOA, CAA concurrently
//! via [`tokio::task::JoinSet`] plus a dedicated `_dmarc.{domain}` TXT subquery.
//! Extracts: IPs (A/AAAA/SPF), mail servers (MX), nameservers (NS), CNAME aliases,
//! SPF members (ip4/ip6/include/redirect), DMARC report addresses (rua/ruf),
//! primary NS + zone-contact email (SOA), certificate-authority issuers (CAA).
//!
//! **IP address targets** — queries PTR (reverse DNS) and returns the hostnames
//! as [`EntityKind::Domain`] entities.

use async_trait::async_trait;
use serde::Deserialize;
use std::{collections::HashSet, net::IpAddr};

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
        12 => Some("PTR"),
        15 => Some("MX"),
        16 => Some("TXT"),
        28 => Some("AAAA"),
        257 => Some("CAA"),
        _ => None,
    }
}

/// Record types queried for domain targets. All fire concurrently.
const RECORD_TYPES: &[&str] = &["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"];

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

/// Convert an IP address string to its reverse-DNS query name. **Pure.**
/// IPv4: `1.2.3.4` → `4.3.2.1.in-addr.arpa`
/// IPv6: `2001:db8::1` → `1.0.0.0…0.8.b.d.0.1.0.0.2.ip6.arpa`
pub(crate) fn ip_to_reverse_dns(ip: &str) -> Option<String> {
    match ip.trim().parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]))
        }
        IpAddr::V6(v6) => {
            let nibbles: Vec<char> = v6
                .octets()
                .iter()
                .rev()
                .flat_map(|b| [b & 0xf, b >> 4])
                .map(|n| char::from_digit(u32::from(n), 16).unwrap_or('0'))
                .collect();
            let dotted = nibbles
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(".");
            Some(format!("{dotted}.ip6.arpa"))
        }
    }
}

/// Parse SOA RDATA into `(mname, rname-as-email)`. **Pure.**
/// SOA format: `mname rname serial refresh retry expire minimum`
/// The rname encodes an email address: the first `.` is the `@` separator
/// (e.g. `hostmaster.example.com.` → `hostmaster@example.com`).
pub(crate) fn parse_soa_fields(data: &str) -> Option<(String, String)> {
    let mut parts = data.split_whitespace();
    let mname = parts.next()?.trim_end_matches('.').to_string();
    let rname_raw = parts.next()?.trim_end_matches('.');
    // DNS master files escape dots in the local-part with backslash
    // (e.g. `john\.doe.example.com` → `john.doe@example.com`).
    // Find the first *unescaped* dot to split local-part from domain.
    let mut dot_pos = None;
    let mut escaped = false;
    for (idx, c) in rname_raw.char_indices() {
        if c == '\\' {
            escaped = !escaped;
        } else if c == '.' && !escaped {
            dot_pos = Some(idx);
            break;
        } else {
            escaped = false;
        }
    }
    let pos = dot_pos?;
    let local = rname_raw[..pos].replace("\\.", ".");
    let dom = &rname_raw[pos + 1..];
    if !dom.contains('.') {
        return None; // too short to be a real domain
    }
    Some((mname, format!("{local}@{dom}")))
}

/// Decode a CAA record presented in RFC 3597 "Unknown" hex format.
///
/// Cloudflare DoH returns CAA RDATA as `\# <byte-count> <hex-bytes...>` rather
/// than the canonical `flags tag "value"` text form. This converts it to the
/// canonical form so `parse_caa_issuer` can handle both sources uniformly.
fn decode_caa_hex_rdata(data: &str) -> Option<String> {
    let rest = data.trim_start().strip_prefix("\\#")?.trim_start();
    let mut tokens = rest.split_whitespace();
    tokens.next()?; // byte-count; consume and discard
    let bytes: Vec<u8> = tokens
        .map(|h| u8::from_str_radix(h, 16).ok())
        .collect::<Option<Vec<_>>>()?;
    let tag_len = *bytes.get(1)? as usize;
    if bytes.len() < 2 + tag_len {
        return None;
    }
    let tag = std::str::from_utf8(&bytes[2..2 + tag_len]).ok()?;
    let value = std::str::from_utf8(&bytes[2 + tag_len..]).ok()?;
    Some(format!("{} {} \"{}\"", bytes[0], tag, value))
}

/// Parse CAA RDATA and return the CA domain for `issue`/`issuewild` tags. **Pure.**
/// CAA format: `flags tag "value"` (value may be bare or quoted).
/// Also handles RFC 3597 hex-encoded RDATA returned by Cloudflare DoH.
/// Returns `None` for `iodef` tags and for prohibit-all (`";"`) values.
pub(crate) fn parse_caa_issuer(data: &str) -> Option<String> {
    let canonical = if data.trim_start().starts_with("\\#") {
        decode_caa_hex_rdata(data)?
    } else {
        data.to_string()
    };
    let mut parts = canonical.splitn(3, |c: char| c.is_whitespace());
    let _flags = parts.next()?;
    let tag = parts.next()?.trim();
    if !matches!(tag, "issue" | "issuewild") {
        return None;
    }
    let value = parts.next()?.trim().trim_matches('"');
    if value.is_empty() || value == ";" {
        return None; // prohibit-all marker
    }
    // Strip CAA parameters after `;` (e.g. `letsencrypt.org;validationmethods=dns-01`).
    let domain = value.split(';').next()?.trim();
    if domain.is_empty() || !domain.contains('.') {
        return None;
    }
    Some(domain.to_string())
}

/// Extract `rua=` and `ruf=` `mailto:` addresses from a DMARC TXT record. **Pure.**
pub(crate) fn dmarc_rua_emails(txt: &str) -> Vec<String> {
    let mut emails = Vec::new();
    for part in txt.split(';') {
        let part = part.trim();
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        if !matches!(key.trim(), "rua" | "ruf") {
            continue;
        }
        for uri in value.split(',') {
            if let Some(addr) = uri.trim().strip_prefix("mailto:")
                && addr.contains('@')
            {
                emails.push(addr.to_string());
            }
        }
    }
    emails
}

/// Map one record type's answers to entities. **Pure** (no network/IO): parses
/// each record per its type — A/AAAA → `IpAddress`, MX/NS/CNAME/PTR/SOA-mname/CAA
/// → `Domain`, SOA-rname + DMARC rua/ruf → `Email`, SPF `TXT` → ip4/ip6/include
/// members — deduplicating across the whole resolution via the shared `seen` set
/// (keyed by a type prefix so an IP from an A record and an SPF `ip4:` of the same
/// value are distinct). Skips blank / dotless hosts. `rtype` outside handled types
/// yields nothing.
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
            "SOA" => {
                if let Some((mname, rname_email)) = parse_soa_fields(&rec.data) {
                    if !mname.is_empty()
                        && mname.contains('.')
                        && seen.insert(format!("soa-ns:{mname}"))
                    {
                        let mut e = Entity::new(EntityKind::Domain, &mname, 0.75, scan_id);
                        e.tag("dns");
                        e.tag("ns-primary");
                        e.add_evidence(base(format!("SOA primary NS for {domain}")));
                        out.push(e);
                    }
                    if rname_email.contains('@') && seen.insert(format!("soa-email:{rname_email}"))
                    {
                        let mut e = Entity::new(EntityKind::Email, &rname_email, 0.60, scan_id);
                        e.tag("dns");
                        e.tag("soa-contact");
                        e.add_evidence(base(format!("SOA zone contact for {domain}")));
                        out.push(e);
                    }
                }
            }
            "CAA" => {
                if let Some(issuer) = parse_caa_issuer(&rec.data)
                    && seen.insert(format!("caa:{issuer}"))
                {
                    let mut e = Entity::new(EntityKind::Domain, &issuer, 0.70, scan_id);
                    e.tag("dns");
                    e.tag("caa-issuer");
                    e.add_evidence(base(format!("CAA authorised CA for {domain}")));
                    out.push(e);
                }
            }
            "PTR" => {
                let ptr = rec.data.trim().trim_end_matches('.');
                if !ptr.is_empty() && ptr.contains('.') && seen.insert(format!("ptr:{ptr}")) {
                    let mut e = Entity::new(EntityKind::Domain, ptr, 0.75, scan_id);
                    e.tag("dns");
                    e.tag("ptr");
                    e.add_evidence(base(format!("PTR record for {domain}")));
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
                            crate::util::spf::Member::A(a_dom) => {
                                if seen.insert(format!("spfa:{a_dom}")) {
                                    let mut e =
                                        Entity::new(EntityKind::Domain, a_dom, 0.65, scan_id);
                                    e.tag("dns");
                                    e.tag("spf-a");
                                    e.add_evidence(Evidence::new(
                                        SRC,
                                        format!("SPF a: mechanism for {domain}"),
                                    ));
                                    out.push(e);
                                }
                            }
                            crate::util::spf::Member::Mx(mx_dom) => {
                                if seen.insert(format!("spfmx:{mx_dom}")) {
                                    let mut e =
                                        Entity::new(EntityKind::Domain, mx_dom, 0.65, scan_id);
                                    e.tag("dns");
                                    e.tag("spf-mx");
                                    e.add_evidence(Evidence::new(
                                        SRC,
                                        format!("SPF mx: mechanism for {domain}"),
                                    ));
                                    out.push(e);
                                }
                            }
                        }
                    }
                } else if txt.trim_start().starts_with("v=DMARC1") {
                    for email in dmarc_rua_emails(&txt) {
                        if seen.insert(format!("dmarc:{email}")) {
                            let mut e = Entity::new(EntityKind::Email, &email, 0.70, scan_id);
                            e.tag("dns");
                            e.tag("dmarc");
                            e.add_evidence(base(format!("DMARC report address for {domain}")));
                            out.push(e);
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
        "DNS-over-HTTPS via Cloudflare + Google — A/AAAA/MX/TXT/NS/CNAME/SOA/CAA + PTR for IPs (free, unlimited)"
    }
    fn priority(&self) -> u8 {
        34
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Domain | TargetKind::Url | TargetKind::IpAddress
        )
    }
    fn max_timeout_ms(&self) -> u64 {
        15_000
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
        let mut result = ModuleResult::new();
        let mut seen: HashSet<String> = HashSet::new();

        // IP address path: PTR (reverse DNS) only.
        if target.kind == TargetKind::IpAddress {
            let Some(ptr_name) = ip_to_reverse_dns(&target.value) else {
                return Ok(result);
            };
            let records = query_doh(&ptr_name, "PTR", &ctx.http).await;
            result.entities.extend(records_for_type(
                "PTR",
                &records,
                &target.value,
                &mut seen,
                &ctx.scan_id,
            ));
            return Ok(result);
        }

        // Domain / URL path: fire all record-type queries + DMARC subquery concurrently.
        let Some(domain) = target_domain(target.kind, &target.value) else {
            return Ok(result);
        };

        let mut set: tokio::task::JoinSet<(&'static str, Vec<DohRecord>)> =
            tokio::task::JoinSet::new();

        for rtype in RECORD_TYPES {
            let rtype: &'static str = rtype;
            let h = ctx.http.clone();
            let d = domain.clone();
            set.spawn(async move { (rtype, query_doh(&d, rtype, &h).await) });
        }

        // `_dmarc.{domain}` TXT subquery — report addresses not on the apex zone.
        {
            let h = ctx.http.clone();
            let dmarc_name = format!("_dmarc.{domain}");
            set.spawn(async move { ("TXT", query_doh(&dmarc_name, "TXT", &h).await) });
        }

        while let Some(join_result) = set.join_next().await {
            if ctx.cancel.is_cancelled() {
                set.abort_all();
                break;
            }
            if let Ok((rtype, records)) = join_result {
                result.entities.extend(records_for_type(
                    rtype,
                    &records,
                    &domain,
                    &mut seen,
                    &ctx.scan_id,
                ));
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
