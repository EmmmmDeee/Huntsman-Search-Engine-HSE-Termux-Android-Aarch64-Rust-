//! DNS resolver via Cloudflare. Pulls A / AAAA / MX / NS / SOA / TXT
//! in parallel and emits one entity per record type:
//!
//! * A     → IpAddress (per IPv4)
//! * AAAA  → IpAddress (per IPv6)
//! * MX    → Domain    (per mailserver, tagged `mx`)
//! * NS    → Domain    (per nameserver, tagged `ns`)
//! * SOA   → Domain    (one summary, with primary NS + admin email)
//! * TXT   → Domain    (enriched parent, evidence holds all TXT values)
//!
//! Lookups run concurrently via `tokio::join!` — the module wall-time
//! is roughly the slowest single lookup rather than the sum. Missing
//! record types are silently skipped (most domains don't publish all
//! six).
//!
//! Uses `hickory-resolver` 0.26 — see `RUSTSEC-2026-0119` for the
//! O(n²) name-compression fix that motivated the 0.24 → 0.26 bump.

use async_trait::async_trait;
use hickory_resolver::proto::rr::RData;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::dns::shared_resolver;

pub struct DnsResolver;

#[async_trait]
impl Module for DnsResolver {
    fn name(&self) -> &'static str {
        "dns_resolver"
    }

    fn priority(&self) -> u8 {
        30
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let resolver = shared_resolver();
        let domain = target.value.as_str();
        let mut result = ModuleResult::new();

        let (ips, mxs, nss, soa, txts) = tokio::join!(
            resolver.lookup_ip(domain),
            resolver.mx_lookup(domain),
            resolver.ns_lookup(domain),
            resolver.soa_lookup(domain),
            resolver.txt_lookup(domain),
        );

        // A + AAAA — iterate the underlying records so we can read TTL.
        if let Ok(lookup) = ips {
            for record in lookup.as_lookup().answers() {
                let (ip_str, record_type, ip_version) = match &record.data {
                    RData::A(a) => {
                        (a.0.to_string(), "A", "4")
                    }
                    RData::AAAA(aaaa) => {
                        (aaaa.0.to_string(), "AAAA", "6")
                    }
                    _ => continue,
                };
                let mut e = Entity::new(EntityKind::IpAddress, &ip_str, 0.95, &ctx.scan_id);
                e.tag(if record_type == "A" { "ipv4" } else { "ipv6" });
                e.add_evidence(
                    Evidence::new("dns_resolver", format!("{record_type} record for {domain}"))
                        .with_attr("record_type", record_type)
                        .with_attr("domain", domain)
                        .with_attr("ttl_secs", record.ttl.to_string())
                        .with_attr("ip_version", ip_version),
                );
                result.push(e);
            }
        }

        // MX records
        if let Ok(lookup) = mxs {
            for record in lookup.answers() {
                let RData::MX(mx) = &record.data else {
                    continue;
                };
                let host = mx.exchange.to_ascii();
                let host = host.trim_end_matches('.').to_string();
                if !host.is_empty() {
                    let mut e = Entity::new(EntityKind::Domain, &host, 0.85, &ctx.scan_id);
                    e.tag("mx");
                    e.add_evidence(
                        Evidence::new("dns_resolver", format!("MX record for {domain}"))
                            .with_attr("record_type", "MX")
                            .with_attr("priority", mx.preference.to_string())
                            .with_attr("parent_domain", domain)
                            .with_attr("ttl_secs", record.ttl.to_string()),
                    );
                    result.push(e);
                }
            }
        }

        // NS records — authoritative nameservers
        if let Ok(lookup) = nss {
            for record in lookup.answers() {
                let RData::NS(ns) = &record.data else {
                    continue;
                };
                let host = ns.0.to_ascii();
                let host = host.trim_end_matches('.').to_string();
                if !host.is_empty() {
                    let mut e = Entity::new(EntityKind::Domain, &host, 0.88, &ctx.scan_id);
                    e.tag("ns");
                    e.add_evidence(
                        Evidence::new("dns_resolver", format!("NS record for {domain}"))
                            .with_attr("record_type", "NS")
                            .with_attr("parent_domain", domain)
                            .with_attr("ttl_secs", record.ttl.to_string()),
                    );
                    result.push(e);
                }
            }
        }

        // SOA — Start-of-Authority. Surfaces the zone's primary NS and
        // the admin email (encoded as a hostname with `.` instead of `@`
        // in the local-part separator per RFC 1035 §3.3.13).
        if let Ok(lookup) = soa
            && let Some(dns_record) = lookup.answers().iter().find(|r| {
                matches!(&r.data, RData::SOA(_))
            })
        {
            let RData::SOA(ref soa_data) = dns_record.data else {
                unreachable!();
            };
            // SOA fields are public in hickory-proto 0.26 — direct access
            // rather than getters.
            let mname = soa_data.mname.to_ascii();
            let mname = mname.trim_end_matches('.');
            let rname_raw = soa_data.rname.to_ascii();
            let admin_email = soa_rname_to_email(rname_raw.trim_end_matches('.'));

            let mut e = Entity::new(EntityKind::Domain, domain, 0.92, &ctx.scan_id);
            e.tag("soa");
            let mut ev = Evidence::new("dns_resolver", format!("SOA record for {domain}"))
                .with_attr("record_type", "SOA")
                .with_attr("primary_ns", mname)
                .with_attr("serial", soa_data.serial.to_string())
                .with_attr("refresh_secs", soa_data.refresh.to_string())
                .with_attr("retry_secs", soa_data.retry.to_string())
                .with_attr("expire_secs", soa_data.expire.to_string())
                .with_attr("minimum_ttl_secs", soa_data.minimum.to_string())
                .with_attr("ttl_secs", dns_record.ttl.to_string());
            if !admin_email.is_empty() {
                ev = ev.with_attr("admin_email", &admin_email);
            }
            e.add_evidence(ev);
            result.push(e);

            // Also emit the admin contact as a discrete Email entity
            // when present — it's a real OSINT signal.
            if admin_email.contains('@') {
                let mut em = Entity::new(EntityKind::Email, &admin_email, 0.70, &ctx.scan_id);
                em.tag("dns-admin");
                em.add_evidence(
                    Evidence::new("dns_resolver", format!("Zone admin for {domain}"))
                        .with_attr("source", "SOA RNAME")
                        .with_attr("parent_domain", domain),
                );
                result.push(em);
            }
        }

        // TXT records → enrich parent
        if let Ok(lookup) = txts {
            let mut min_ttl: Option<u32> = None;
            let txts: Vec<String> = lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::TXT(txt) => {
                        min_ttl = Some(min_ttl.map_or(r.ttl, |prev| prev.min(r.ttl)));
                        Some(txt.to_string())
                    }
                    _ => None,
                })
                .collect();
            if !txts.is_empty() {
                let mut dom = Entity::new(EntityKind::Domain, domain, 0.90, &ctx.scan_id);
                // Common TXT-record signals worth surfacing as tags so
                // the SPA can highlight them.
                for t in &txts {
                    let b = t.as_bytes();
                    if b.len() >= 6 && b[..6].eq_ignore_ascii_case(b"v=spf1") {
                        dom.tag("spf");
                    } else if b.len() >= 7 && b[..7].eq_ignore_ascii_case(b"v=dkim1") {
                        dom.tag("dkim");
                    } else if b.len() >= 8 && b[..8].eq_ignore_ascii_case(b"v=dmarc1") {
                        dom.tag("dmarc");
                    } else if b.len() >= 24
                        && b[..24].eq_ignore_ascii_case(b"google-site-verification")
                    {
                        dom.tag("google-verified");
                    } else if b.len() >= 3 && b[..3].eq_ignore_ascii_case(b"ms=") {
                        dom.tag("ms-verified");
                    }
                }
                let mut txt_ev =
                    Evidence::new("dns_resolver", format!("{} TXT records", txts.len()))
                        .with_attr("txt_records", txts.join(" | "))
                        .with_attr("txt_count", txts.len().to_string());
                if let Some(ttl) = min_ttl {
                    txt_ev = txt_ev.with_attr("ttl_secs", ttl.to_string());
                }
                dom.add_evidence(txt_ev);
                result.push(dom);
            }
        }

        Ok(result)
    }
}

/// SOA RNAME field is encoded as `local-part.domain` (no `@` allowed in
/// DNS labels). Decode by replacing the first unescaped `.` with `@`.
/// Returns empty string when the input doesn't look like an email.
fn soa_rname_to_email(rname: &str) -> String {
    if rname.is_empty() || !rname.contains('.') {
        return String::new();
    }
    // Find the first non-escaped dot.
    let bytes = rname.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'.' {
            let (local, rest) = rname.split_at(i);
            // rest still starts with '.'; skip it.
            let domain = &rest[1..];
            if local.is_empty() || domain.is_empty() {
                return String::new();
            }
            return format!("{local}@{domain}");
        }
        i += 1;
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_domain_only() {
        let m = DnsResolver;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x")));
    }

    #[test]
    fn soa_rname_decodes() {
        assert_eq!(
            soa_rname_to_email("hostmaster.example.com"),
            "hostmaster@example.com"
        );
        assert_eq!(
            soa_rname_to_email("admin.sub.example.org"),
            "admin@sub.example.org"
        );
        assert_eq!(soa_rname_to_email(""), "");
        assert_eq!(soa_rname_to_email("notanemail"), "");
    }
}
