//! DNS-over-HTTPS resolution via Cloudflare + Google public resolvers.
//!
//! Endpoints (free, no key, unlimited):
//!   `GET https://cloudflare-dns.com/dns-query?name={domain}&type={type}`
//!   `GET https://dns.google/resolve?name={domain}&type={type}`
//!
//! Queries A, AAAA, MX, TXT, NS, CNAME, SOA, HTTPS, and CAA records. Extracts IPs
//! from A/AAAA, mail servers from MX, nameservers from NS, SPF/DKIM from TXT,
//! zone admin email and primary NS from SOA, DMARC reporting addresses from a
//! dedicated `_dmarc.{domain}` TXT query (RFC 7489 §6.6.3), the ipv4hint/ipv6hint
//! endpoint IPs from HTTPS/SVCB records (RFC 9460), and the authorised CAs +
//! `iodef` security-contact from CAA records (RFC 8659) — the latter routed
//! through the shared `dns_intel` iodef extractor — and the SMTP-TLS reporting
//! contact from a `_smtp._tls.{domain}` TLSRPT record (RFC 8460). HTTPS and CAA
//! are parsed from both the friendly presentation string and the raw RFC 3597
//! wire form the two resolvers respectively return.
//!
//! CAA matters most on Termux: the hickory `dns_intel` module owns CAA over
//! port-53, but that transport is frequently blocked on-device, so this DoH pass
//! is often the only path by which a domain's CA policy and published
//! security/abuse contact are enumerated.

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
        65 => Some("HTTPS"),
        257 => Some("CAA"),
        _ => None,
    }
}

/// The record types we query at the apex domain, in order. `HTTPS` (RFC 9460,
/// type 65) is queried last as a supplementary infrastructure pass; its
/// `ipv4hint`/`ipv6hint` addresses either mark an existing serving IP as an
/// HTTPS/SVCB endpoint (via a UID merge) or surface a net-new one — see the
/// `"HTTPS"` arm of [`records_for_type`].
const RECORD_TYPES: &[&str] = &["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "HTTPS"];

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

/// Extract the `ipv4hint` / `ipv6hint` addresses from an HTTPS/SVCB record
/// (RFC 9460) as returned in a DoH JSON `data` field. **Pure**, fully
/// bounds-checked — malformed input yields whatever parsed cleanly, never a
/// panic. Handles BOTH forms the two resolvers emit: dns.google's friendly
/// presentation string (`1 . alpn=h3,h2 ipv4hint=A,B ipv6hint=C,D`), and
/// cloudflare-dns's raw RFC 3597 generic form (`\# <len> <hex octets>`), which
/// carries the SvcParams as binary and must be decoded on the wire.
///
/// The hint addresses are the origin/edge IPs a client is told to connect to —
/// infrastructure that an A/AAAA lookup may not surface (e.g. an HTTP/3-only or
/// ECH-fronted endpoint), so a new one is a real pivot.
fn parse_svcb_hints(data: &str) -> Vec<String> {
    let data = data.trim();
    if let Some(hex_body) = data.strip_prefix(r"\#") {
        return svcb_hints_from_wire(hex_body);
    }
    // Friendly presentation form: whitespace-separated params, comma-lists.
    let mut out = Vec::new();
    for tok in data.split_whitespace() {
        if let Some(list) = tok
            .strip_prefix("ipv4hint=")
            .or_else(|| tok.strip_prefix("ipv6hint="))
        {
            out.extend(
                list.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            );
        }
    }
    out
}

/// Parse the binary SVCB RDATA behind an RFC 3597 `\#`-prefixed generic record
/// (the space-separated `<decimal length> <hex octets…>` body) and return the
/// `ipv4hint` (SvcParamKey 4) and `ipv6hint` (key 6) addresses. Every read is
/// length-checked, so a truncated or hostile record simply stops early. **Pure.**
fn svcb_hints_from_wire(hex_body: &str) -> Vec<String> {
    let mut toks = hex_body.split_whitespace();
    // First token is the RFC 3597 decimal rdata length; we bound on the actual
    // decoded bytes instead, so skip it. The rest are hex octets.
    toks.next();
    let mut bytes: Vec<u8> = Vec::new();
    for t in toks {
        match u8::from_str_radix(t, 16) {
            Ok(b) => bytes.push(b),
            Err(_) => return Vec::new(), // non-hex octet → malformed, bail
        }
    }

    let mut out = Vec::new();
    // SvcPriority (2 octets).
    let mut i = 2usize;
    if bytes.len() < i {
        return out;
    }
    // TargetName: length-prefixed labels terminated by a zero-length octet.
    while i < bytes.len() {
        let label_len = bytes[i] as usize;
        i += 1;
        if label_len == 0 {
            break; // root / end of name
        }
        i = i.saturating_add(label_len);
        if i > bytes.len() {
            return out;
        }
    }
    // SvcParams: repeated (key:2, len:2, value:len).
    while i + 4 <= bytes.len() {
        let key = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
        let vlen = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
        i += 4;
        if i + vlen > bytes.len() {
            break;
        }
        let value = &bytes[i..i + vlen];
        match key {
            4 => {
                for c in value.chunks_exact(4) {
                    out.push(std::net::Ipv4Addr::new(c[0], c[1], c[2], c[3]).to_string());
                }
            }
            6 => {
                for c in value.chunks_exact(16) {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(c);
                    out.push(std::net::Ipv6Addr::from(o).to_string());
                }
            }
            _ => {}
        }
        i += vlen;
    }
    out
}

/// Parse one CAA record's DoH `data` field into a `(tag, value)` pair with the
/// tag lowercased. Handles BOTH resolver forms — exactly like `parse_svcb_hints`
/// — because the two DoH endpoints disagree: dns.google returns the presentation
/// string `0 issue "letsencrypt.org"`, while cloudflare-dns returns the raw RFC
/// 3597 generic form `\# <declen> <hex octets>` whose CAA RDATA (RFC 8659 §4.1)
/// is `flags(1) taglen(1) tag(taglen) value(rest)`. Every read is length-checked,
/// so a truncated or non-CAA record yields `None` rather than panicking. **Pure.**
fn parse_caa_rdata(data: &str) -> Option<(String, String)> {
    let data = data.trim();
    if let Some(hex_body) = data.strip_prefix(r"\#") {
        // First token is the RFC 3597 decimal rdata length; bound on the decoded
        // bytes instead, so skip it. The rest are hex octets.
        let mut toks = hex_body.split_whitespace();
        toks.next();
        let mut bytes: Vec<u8> = Vec::new();
        for t in toks {
            bytes.push(u8::from_str_radix(t, 16).ok()?);
        }
        // flags(1) taglen(1) tag(taglen) value(rest)
        if bytes.len() < 2 {
            return None;
        }
        let taglen = bytes[1] as usize;
        let tag_end = 2usize.checked_add(taglen)?;
        if tag_end > bytes.len() {
            return None;
        }
        let tag = String::from_utf8_lossy(&bytes[2..tag_end]).to_ascii_lowercase();
        let value = String::from_utf8_lossy(&bytes[tag_end..])
            .trim()
            .to_string();
        if tag.is_empty() || value.is_empty() {
            return None;
        }
        return Some((tag, value));
    }
    // Presentation form: `<flags> <tag> "<value>"`.
    let mut parts = data.splitn(3, char::is_whitespace);
    let _flags = parts.next()?;
    let tag = parts.next()?.to_ascii_lowercase();
    let value = parts.next()?.trim().trim_matches('"').trim().to_string();
    if tag.is_empty() || value.is_empty() {
        return None;
    }
    Some((tag, value))
}

/// Build CAA entities from a DoH CAA answer set — transport parity with the
/// hickory `dns_intel` CAA path, which on Termux frequently never runs (its
/// UDP/TCP port-53 lookups are commonly blocked, leaving DoH as the sole
/// resolver). Aggregates the `issue`/`issuewild`/`iodef` values onto one
/// `caa`-tagged Domain entity, then routes each `iodef` value through the shared
/// `dns_intel::iodef_entities` extractor so a published cert-violation reporting
/// contact — a `mailto:` **security-contact Email** or an `http(s)://` reporting
/// **Domain** — surfaces as a pivotable entity instead of being dropped on
/// Termux. **Pure** (no network/IO).
fn caa_entities(records: &[DohRecord], domain: &str, scan_id: &str) -> Vec<Entity> {
    let mut issuers: Vec<String> = Vec::new();
    let mut wildcards: Vec<String> = Vec::new();
    let mut iodefs: Vec<String> = Vec::new();

    for rec in records {
        // parse_caa_rdata self-validates: a stray CNAME/other answer in the set
        // fails to parse and is skipped, so no record-type filter is needed.
        let Some((tag, value)) = parse_caa_rdata(&rec.data) else {
            continue;
        };
        match tag.as_str() {
            "issue" => issuers.push(value),
            "issuewild" => wildcards.push(value),
            "iodef" => iodefs.push(value),
            _ => {}
        }
    }

    if issuers.is_empty() && wildcards.is_empty() && iodefs.is_empty() {
        return Vec::new();
    }

    let mut entity = Entity::new(EntityKind::Domain, domain, 0.85, scan_id);
    entity.tag("dns");
    entity.tag("caa");
    let mut ev = Evidence::new(
        SRC,
        format!(
            "CAA policy published: {} issuer(s), {} wildcard issuer(s)",
            issuers.len(),
            wildcards.len()
        ),
    );
    if !issuers.is_empty() {
        ev = ev.with_attr("issue", issuers.join(","));
    }
    if !wildcards.is_empty() {
        ev = ev.with_attr("issuewild", wildcards.join(","));
    }
    if !iodefs.is_empty() {
        ev = ev.with_attr("iodef", iodefs.join(","));
    }
    entity.add_evidence(ev);

    let mut out = vec![entity];
    for value in &iodefs {
        out.extend(crate::modules::dns_intel::iodef_entities(
            value, domain, scan_id,
        ));
    }
    out
}

/// Build entities from a `_smtp._tls.{domain}` TLSRPT answer set (RFC 8460).
/// The `rua=` destinations are a published mail-security contact — parallel to
/// DMARC `rua`, and on Termux reachable only over this DoH transport when
/// port-53 is blocked. A `mailto:` destination becomes an `Email` tagged
/// `tlsrpt-report`; an `https:` collection endpoint becomes a `Domain` for its
/// host (a recursable lead). Role/provider-infrastructure mailboxes are gated
/// (`is_infrastructure_email`) so this DoH transport surfaces the SAME contact
/// set as the hickory `dns_intel` path — a provider desk like
/// `sts-reports@google.com` is not clustered as the subject. **Pure** (no
/// network/IO).
fn tlsrpt_entities(records: &[DohRecord], domain: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    for rec in records {
        let txt = unquote_txt(rec.data.trim());
        let Some(parsed) = crate::util::tlsrpt::parse(&txt) else {
            continue;
        };
        for addr in &parsed.emails {
            if crate::util::domains::is_infrastructure_email(addr) {
                continue;
            }
            let mut e = Entity::new(EntityKind::Email, addr, 0.68, scan_id);
            e.tag("dns");
            e.tag("tlsrpt-report");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("TLSRPT (SMTP-TLS) report address for {domain}"),
                )
                .with_attr("record_type", "TLSRPT")
                .with_attr("domain", domain),
            );
            out.push(e);
        }
        for url in &parsed.urls {
            if let Some(host) = crate::util::url_util::host_from_url(url)
                && host.contains('.')
                && host != domain
            {
                let mut d = Entity::new(EntityKind::Domain, &host, 0.58, scan_id);
                d.tag("dns");
                d.tag("tlsrpt-report");
                d.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("TLSRPT (SMTP-TLS) reporting endpoint host for {domain}"),
                    )
                    .with_attr("record_type", "TLSRPT")
                    .with_attr("rua", url.as_str()),
                );
                out.push(d);
            }
        }
        // A domain has at most one valid TLSRPT record; the first wins.
        break;
    }
    out
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
            "HTTPS" => {
                // RFC 9460 HTTPS record: harvest its ipv4hint/ipv6hint addresses.
                // A distinct `httpshint:` dedup key (NOT the A/AAAA `ip:` key) is
                // used deliberately: for a CDN-fronted domain a hint typically
                // REPEATS an A/AAAA IP, and emitting it here lets the engine merge
                // it (same UID) into that IP's entity — stamping it `https-hint`/
                // `svcb`, i.e. marking WHICH serving IPs speak the HTTPS/SVCB
                // record (HTTP/3-capable, ECH-fronted) rather than discarding the
                // fact. A hint that is NOT among the plain records is a genuinely
                // new endpoint IP the A/AAAA lookup missed. Both are wins.
                for ip in parse_svcb_hints(&rec.data) {
                    if !ip.is_empty() && seen.insert(format!("httpshint:{ip}")) {
                        let is_v6 = ip.contains(':');
                        let mut e = Entity::new(EntityKind::IpAddress, &ip, 0.75, scan_id);
                        e.tag("dns");
                        e.tag(if is_v6 { "ipv6" } else { "ipv4" });
                        e.tag("https-hint");
                        e.tag("svcb");
                        e.add_evidence(
                            base(format!("HTTPS/SVCB record hint for {domain}"))
                                .with_attr("record_type", "HTTPS")
                                .with_attr("svcparam", if is_v6 { "ipv6hint" } else { "ipv4hint" }),
                        );
                        out.push(e);
                    }
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
        "DNS-over-HTTPS resolution via Cloudflare + Google — sweeps A/AAAA/MX/TXT/NS/CNAME/SOA/HTTPS plus DMARC, CAA, and TLSRPT (free)"
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

        // CAA (RFC 8659, type 257) — a dedicated aggregating pass, not part of the
        // per-answer RECORD_TYPES loop, because CAA folds many answers into one
        // policy entity + routes each `iodef` value to a security-contact entity.
        // This is the Termux parity fix: on-device, hickory `dns_intel` (which
        // owns CAA over port-53) is routinely unreachable, so without this the
        // domain's authorised CAs and its published security/abuse contact are
        // lost on the exact platform HSE targets.
        if !ctx.cancel.is_cancelled() {
            let caa_records = query_doh(&domain, "CAA", &ctx.http).await;
            result
                .entities
                .extend(caa_entities(&caa_records, &domain, &ctx.scan_id));
        }

        // TLSRPT (RFC 8460) lives at `_smtp._tls.{domain}` as a TXT record, like
        // DMARC at `_dmarc.`. Its `rua=` names a published mail-security contact
        // (Email or https endpoint) — another pivot lost on Termux without a DoH
        // path, since the hickory transport that would resolve it is blocked.
        if !ctx.cancel.is_cancelled() {
            let tlsrpt_domain = format!("_smtp._tls.{domain}");
            let tlsrpt_records = query_doh(&tlsrpt_domain, "TXT", &ctx.http).await;
            result
                .entities
                .extend(tlsrpt_entities(&tlsrpt_records, &domain, &ctx.scan_id));
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
