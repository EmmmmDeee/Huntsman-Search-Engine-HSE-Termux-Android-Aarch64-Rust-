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

        // A + AAAA (lookup_ip returns both v4 and v6)
        if let Ok(lookup) = ips {
            for ip in lookup.iter() {
                let record_type = if ip.is_ipv4() { "A" } else { "AAAA" };
                let mut e = Entity::new(EntityKind::IpAddress, ip.to_string(), 0.95, &ctx.scan_id);
                e.tag(if ip.is_ipv4() { "ipv4" } else { "ipv6" });
                e.add_evidence(
                    Evidence::new("dns_resolver", format!("{record_type} record for {domain}"))
                        .with_attr("record_type", record_type)
                        .with_attr("domain", domain),
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
                            .with_attr("parent_domain", domain),
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
                            .with_attr("parent_domain", domain),
                    );
                    result.push(e);
                }
            }
        }

        // SOA — Start-of-Authority. Surfaces the zone's primary NS and
        // the admin email (encoded as a hostname with `.` instead of `@`
        // in the local-part separator per RFC 1035 §3.3.13).
        if let Ok(lookup) = soa
            && let Some(record) = lookup.answers().iter().find_map(|r| match &r.data {
                RData::SOA(soa) => Some(soa),
                _ => None,
            })
        {
            // SOA fields are public in hickory-proto 0.26 — direct access
            // rather than getters.
            let mname = record.mname.to_ascii();
            let mname = mname.trim_end_matches('.');
            let rname_raw = record.rname.to_ascii();
            let admin_email = soa_rname_to_email(rname_raw.trim_end_matches('.'));

            let mut e = Entity::new(EntityKind::Domain, domain, 0.92, &ctx.scan_id);
            e.tag("soa");
            let mut ev = Evidence::new("dns_resolver", format!("SOA record for {domain}"))
                .with_attr("record_type", "SOA")
                .with_attr("primary_ns", mname)
                .with_attr("serial", record.serial.to_string())
                .with_attr("refresh_secs", record.refresh.to_string())
                .with_attr("retry_secs", record.retry.to_string())
                .with_attr("expire_secs", record.expire.to_string())
                .with_attr("minimum_ttl_secs", record.minimum.to_string());
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
            let txts: Vec<String> = lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::TXT(txt) => Some(txt.to_string()),
                    _ => None,
                })
                .collect();
            if !txts.is_empty() {
                let mut dom = Entity::new(EntityKind::Domain, domain, 0.90, &ctx.scan_id);
                // Common TXT-record signals worth surfacing as tags so
                // the SPA can highlight them.
                let lower: Vec<String> = txts.iter().map(|s| s.to_lowercase()).collect();
                if lower.iter().any(|t| t.starts_with("v=spf1")) {
                    dom.tag("spf");
                }
                if lower.iter().any(|t| t.starts_with("v=dkim1")) {
                    dom.tag("dkim");
                }
                if lower.iter().any(|t| t.starts_with("v=dmarc1")) {
                    dom.tag("dmarc");
                }
                if lower
                    .iter()
                    .any(|t| t.starts_with("google-site-verification"))
                {
                    dom.tag("google-verified");
                }
                if lower.iter().any(|t| t.starts_with("ms=")) {
                    dom.tag("ms-verified");
                }
                dom.add_evidence(
                    Evidence::new("dns_resolver", format!("{} TXT records", txts.len()))
                        .with_attr("txt_records", txts.join(" | "))
                        .with_attr("txt_count", txts.len().to_string()),
                );
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
