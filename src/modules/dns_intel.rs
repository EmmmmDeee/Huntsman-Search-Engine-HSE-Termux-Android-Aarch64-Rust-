//! Unified DNS intelligence module — merges five formerly-separate modules
//! into a single `DnsIntel` struct that dispatches on target kind:
//!
//! **Domain targets** (sequential):
//!   1. *Resolution* — A / AAAA / MX / NS / SOA / TXT lookups via `tokio::join!`.
//!   2. *Subdomain brute-force* — ~67-label common-name dictionary, bounded
//!      to 12 concurrent lookups.
//!   3. *CAA inspection* — RFC 8659 Certification Authority Authorization.
//!
//! **IpAddress targets** (sequential):
//!   1. *Reverse DNS* — PTR record lookup.
//!   2. *Blocklist (DNSBL)* — 8 well-known DNS-based blocklists.
//!
//! All lookups use `crate::util::dns::shared_resolver()` (Cloudflare).
//! No API keys, no HTTP, no rate limits.
//!
//! Evidence source for every finding: `"dns_intel"`.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_resolver::proto::rr::{RData, RecordType};
use tokio::sync::Semaphore;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::dns::shared_resolver;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Subdomain brute-force dictionary — covers ~99 % of the public-facing
/// subdomains operators actually want to discover. Ordered roughly by
/// frequency so cancellation during a partial run still surfaces the
/// highest-value names first.
const SUBDOMAINS: &[&str] = &[
    "www",
    "mail",
    "smtp",
    "imap",
    "pop",
    "pop3",
    "webmail",
    "ns",
    "ns1",
    "ns2",
    "ns3",
    "mx",
    "mx1",
    "ftp",
    "admin",
    "blog",
    "api",
    "dev",
    "staging",
    "stage",
    "test",
    "beta",
    "alpha",
    "qa",
    "secure",
    "vpn",
    "cdn",
    "static",
    "assets",
    "media",
    "img",
    "images",
    "docs",
    "support",
    "help",
    "status",
    "shop",
    "store",
    "portal",
    "app",
    "apps",
    "my",
    "login",
    "auth",
    "sso",
    "files",
    "upload",
    "download",
    "backup",
    "git",
    "gitlab",
    "github",
    "jira",
    "wiki",
    "forum",
    "community",
    "old",
    "new",
    "m",
    "mobile",
    "internal",
    "prod",
    "production",
    "cpanel",
    "autodiscover",
    "autoconfig",
    "webdisk",
];

const MAX_CONCURRENT_BRUTE: usize = 12;

/// DNS-based blocklists — zone + human label.
const BLOCKLISTS: &[(&str, &str)] = &[
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("bl.spamcop.net", "SpamCop"),
    ("dnsbl.sorbs.net", "SORBS"),
    ("b.barracudacentral.org", "Barracuda"),
    ("cbl.abuseat.org", "CBL"),
    ("dnsbl-1.uceprotect.net", "UCEPROTECT-1"),
    ("psbl.surriel.com", "PSBL"),
    ("all.s5h.net", "S5H"),
];

/// Evidence source label used for every finding in this module.
const SRC: &str = "dns_intel";

// ---------------------------------------------------------------------------
// Module struct + trait impl
// ---------------------------------------------------------------------------

pub struct DnsIntel;

#[async_trait]
impl Module for DnsIntel {
    fn name(&self) -> &'static str {
        "dns_intel"
    }

    fn description(&self) -> &'static str {
        "DNS intelligence: resolution, subdomain brute-force, blocklist, reverse DNS, and CAA"
    }

    fn priority(&self) -> u8 {
        30
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::IpAddress)
    }

    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        match target.kind {
            TargetKind::Domain => process_domain(target, ctx).await,
            TargetKind::IpAddress => process_ip(target, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Domain pipeline: resolver → brute → CAA
// ---------------------------------------------------------------------------

async fn process_domain(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let mut result = ModuleResult::new();

    // 1. Full DNS resolution (A/AAAA/MX/NS/SOA/TXT)
    let resolver_result = resolve_records(target, ctx).await?;
    result.extend(resolver_result);

    // 2. Subdomain brute-force
    let brute_result = brute_subdomains(target, ctx).await?;
    result.extend(brute_result);

    // 3. CAA record inspection
    let caa_result = lookup_caa(target, ctx).await?;
    result.extend(caa_result);

    Ok(result)
}

/// A / AAAA / MX / NS / SOA / TXT — run concurrently via `tokio::join!`.
async fn resolve_records(target: &Target, ctx: &ModuleContext) -> Result<Vec<Entity>> {
    let resolver = shared_resolver();
    let domain = target.value.as_str();
    let mut entities: Vec<Entity> = Vec::new();

    let (ips, mxs, nss, soa, txts) = tokio::join!(
        resolver.lookup_ip(domain),
        resolver.mx_lookup(domain),
        resolver.ns_lookup(domain),
        resolver.soa_lookup(domain),
        resolver.txt_lookup(domain),
    );

    // A + AAAA
    if let Ok(lookup) = ips {
        for record in lookup.as_lookup().answers() {
            let (ip_str, record_type, ip_version) = match &record.data {
                RData::A(a) => (a.0.to_string(), "A", "4"),
                RData::AAAA(aaaa) => (aaaa.0.to_string(), "AAAA", "6"),
                _ => continue,
            };
            let mut e = Entity::new(EntityKind::IpAddress, &ip_str, 0.95, &ctx.scan_id);
            e.tag(if record_type == "A" { "ipv4" } else { "ipv6" });
            e.add_evidence(
                Evidence::new(SRC, format!("{record_type} record for {domain}"))
                    .with_attr("record_type", record_type)
                    .with_attr("domain", domain)
                    .with_attr("ttl_secs", record.ttl.to_string())
                    .with_attr("ip_version", ip_version),
            );
            entities.push(e);
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
                    Evidence::new(SRC, format!("MX record for {domain}"))
                        .with_attr("record_type", "MX")
                        .with_attr("priority", mx.preference.to_string())
                        .with_attr("parent_domain", domain)
                        .with_attr("ttl_secs", record.ttl.to_string()),
                );
                entities.push(e);
            }
        }
    }

    // NS records
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
                    Evidence::new(SRC, format!("NS record for {domain}"))
                        .with_attr("record_type", "NS")
                        .with_attr("parent_domain", domain)
                        .with_attr("ttl_secs", record.ttl.to_string()),
                );
                entities.push(e);
            }
        }
    }

    // SOA
    if let Ok(lookup) = soa
        && let Some(dns_record) = lookup
            .answers()
            .iter()
            .find(|r| matches!(&r.data, RData::SOA(_)))
    {
        let RData::SOA(ref soa_data) = dns_record.data else {
            unreachable!();
        };
        let mname = soa_data.mname.to_ascii();
        let mname = mname.trim_end_matches('.');
        let rname_raw = soa_data.rname.to_ascii();
        let admin_email = soa_rname_to_email(rname_raw.trim_end_matches('.'));

        let mut e = Entity::new(EntityKind::Domain, domain, 0.92, &ctx.scan_id);
        e.tag("soa");
        let mut ev = Evidence::new(SRC, format!("SOA record for {domain}"))
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
        entities.push(e);

        // Emit the admin contact as a discrete Email entity when present.
        if admin_email.contains('@') {
            let mut em = Entity::new(EntityKind::Email, &admin_email, 0.70, &ctx.scan_id);
            em.tag("dns-admin");
            em.add_evidence(
                Evidence::new(SRC, format!("Zone admin for {domain}"))
                    .with_attr("source", "SOA RNAME")
                    .with_attr("parent_domain", domain),
            );
            entities.push(em);
        }
    }

    // TXT records
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
            for t in &txts {
                let t = t.trim_matches('"');
                let b = t.as_bytes();
                if b.len() >= 6 && b[..6].eq_ignore_ascii_case(b"v=spf1") {
                    dom.tag("spf");
                } else if b.len() >= 7 && b[..7].eq_ignore_ascii_case(b"v=dkim1") {
                    dom.tag("dkim");
                } else if b.len() >= 8 && b[..8].eq_ignore_ascii_case(b"v=dmarc1") {
                    dom.tag("dmarc");
                } else if b.len() >= 24 && b[..24].eq_ignore_ascii_case(b"google-site-verification")
                {
                    dom.tag("google-verified");
                } else if b.len() >= 3 && b[..3].eq_ignore_ascii_case(b"ms=") {
                    dom.tag("ms-verified");
                }
            }
            let mut txt_ev = Evidence::new(SRC, format!("{} TXT records", txts.len()))
                .with_attr("txt_records", txts.join(" | "))
                .with_attr("txt_count", txts.len().to_string());
            if let Some(ttl) = min_ttl {
                txt_ev = txt_ev.with_attr("ttl_secs", ttl.to_string());
            }
            dom.add_evidence(txt_ev);
            entities.push(dom);
        }
    }

    Ok(entities)
}

/// Subdomain brute-force via the common-name dictionary.
async fn brute_subdomains(target: &Target, ctx: &ModuleContext) -> Result<Vec<Entity>> {
    let parent = target.value.trim().trim_end_matches('.').to_lowercase();
    if parent.is_empty() || parent.contains('/') || parent.contains(' ') {
        return Ok(Vec::new());
    }

    let resolver = shared_resolver();
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_BRUTE));
    let mut set = tokio::task::JoinSet::new();

    for sub in SUBDOMAINS {
        // Skip if the sub-label is already the leftmost label of the input.
        if parent.starts_with(sub) && parent.as_bytes().get(sub.len()) == Some(&b'.') {
            continue;
        }
        let mut host = String::with_capacity(sub.len() + 1 + parent.len());
        host.push_str(sub);
        host.push('.');
        host.push_str(&parent);
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            match resolver.lookup_ip(host.as_str()).await {
                Ok(lookup) => {
                    let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
                    let count = ips.len();
                    let joined = ips.join(", ");
                    Some((host, joined, count))
                }
                Err(_) => None,
            }
        });
    }

    let mut entities: Vec<Entity> = Vec::new();
    while let Some(join_result) = set.join_next().await {
        let Ok(Some((host, ips_joined, count))) = join_result else {
            continue;
        };
        let mut e = Entity::new(EntityKind::Domain, &host, 0.85, &ctx.scan_id);
        e.tag("subdomain");
        e.tag("dns-brute");
        e.add_evidence(
            Evidence::new(
                SRC,
                format!("Subdomain {host} resolves to one or more A/AAAA records"),
            )
            .with_attr("parent_domain", &parent)
            .with_attr("method", "common-name-dictionary")
            .with_attr("dictionary_size", SUBDOMAINS.len().to_string())
            .with_attr("resolved_ips", &ips_joined)
            .with_attr("ip_count", count.to_string()),
        );
        entities.push(e);
    }
    Ok(entities)
}

/// CAA record inspection (RFC 8659).
async fn lookup_caa(target: &Target, ctx: &ModuleContext) -> Result<Vec<Entity>> {
    let domain = target.value.trim();
    if domain.is_empty() {
        return Ok(Vec::new());
    }
    let resolver = shared_resolver();

    let lookup = match resolver.lookup(domain, RecordType::CAA).await {
        Ok(l) => l,
        Err(_) => return Ok(Vec::new()),
    };

    let mut issuers: Vec<String> = Vec::new();
    let mut wildcards: Vec<String> = Vec::new();
    let mut iodefs: Vec<String> = Vec::new();

    for record in lookup.answers() {
        let RData::CAA(caa) = &record.data else {
            continue;
        };
        let value = String::from_utf8_lossy(&caa.value).into_owned();
        match caa.tag.to_ascii_lowercase().as_str() {
            "issue" => issuers.push(value),
            "issuewild" => wildcards.push(value),
            "iodef" => iodefs.push(value),
            _ => {}
        }
    }

    if issuers.is_empty() && wildcards.is_empty() && iodefs.is_empty() {
        return Ok(Vec::new());
    }

    let mut entity = Entity::new(EntityKind::Domain, domain, 0.85, &ctx.scan_id);
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

    Ok(vec![entity])
}

// ---------------------------------------------------------------------------
// IP pipeline: reverse DNS → blocklist
// ---------------------------------------------------------------------------

async fn process_ip(target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
    let mut result = ModuleResult::new();

    // 1. Reverse DNS (PTR)
    let ptr_result = reverse_lookup(target, ctx).await?;
    result.extend(ptr_result);

    // 2. DNSBL check
    let bl_result = blocklist_check(target, ctx).await?;
    result.extend(bl_result);

    Ok(result)
}

/// PTR record lookup for IP → hostname mapping.
async fn reverse_lookup(target: &Target, ctx: &ModuleContext) -> Result<Vec<Entity>> {
    let ip: IpAddr = match target.value.parse() {
        Ok(ip) => ip,
        Err(_) => return Ok(Vec::new()),
    };

    let resolver = shared_resolver();
    let lookup = match resolver.reverse_lookup(ip).await {
        Ok(l) => l,
        Err(_) => return Ok(Vec::new()),
    };

    let mut entities: Vec<Entity> = Vec::new();
    for record in lookup.answers() {
        let RData::PTR(ptr) = &record.data else {
            continue;
        };
        let host_raw = ptr.0.to_ascii();
        let host = host_raw.trim_end_matches('.');
        if host.is_empty() {
            continue;
        }
        let mut e = Entity::new(EntityKind::Domain, host, 0.85, &ctx.scan_id);
        e.tag(crate::core::tags::PTR);
        e.add_evidence(
            Evidence::new(SRC, format!("PTR record for {ip}"))
                .with_attr("record_type", "PTR")
                .with_attr("ip", target.value.as_str())
                .with_attr("ttl_secs", record.ttl.to_string()),
        );
        entities.push(e);
    }
    Ok(entities)
}

/// DNSBL reputation check against 8 blocklists.
async fn blocklist_check(target: &Target, ctx: &ModuleContext) -> Result<Vec<Entity>> {
    let ip = target.value.trim();
    if ip.is_empty() {
        return Ok(Vec::new());
    }

    let reversed = match reverse_ip(ip) {
        Some(r) => r,
        None => return Ok(Vec::new()),
    };

    let resolver = shared_resolver();
    let mut listed_on: Vec<&str> = Vec::new();
    let mut checked = 0u32;

    for (zone, label) in BLOCKLISTS {
        if ctx.cancel.is_cancelled() {
            break;
        }
        let query = format!("{reversed}.{zone}");
        if resolver.lookup_ip(query.as_str()).await.is_ok() {
            listed_on.push(label);
        }
        checked += 1;
    }

    let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.90, &ctx.scan_id);
    entity.tag("dnsbl-checked");

    if listed_on.is_empty() {
        entity.add_evidence(
            Evidence::new(SRC, format!("{ip} clean on {checked} blocklists"))
                .with_attr("listed_count", "0")
                .with_attr("checked_count", checked.to_string())
                .with_attr("status", "clean"),
        );
    } else {
        entity.tag("blocklisted");
        if listed_on.len() >= 3 {
            entity.tag("high-risk");
        }
        listed_on.sort_unstable();
        entity.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "{ip} listed on {} of {} blocklists",
                    listed_on.len(),
                    checked
                ),
            )
            .with_attr("listed_count", listed_on.len().to_string())
            .with_attr("checked_count", checked.to_string())
            .with_attr("listed_on", listed_on.join(", "))
            .with_attr("status", "listed"),
        );
    }

    Ok(vec![entity])
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Reverse the octets of an IPv4 address for DNSBL queries.
/// Returns `None` for IPv6 (unsupported by most blocklists) and invalid input.
fn reverse_ip(ip: &str) -> Option<String> {
    let parsed: std::net::IpAddr = ip.parse().ok()?;
    match parsed {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            Some(format!(
                "{}.{}.{}.{}",
                octets[3], octets[2], octets[1], octets[0]
            ))
        }
        std::net::IpAddr::V6(_) => None,
    }
}

/// SOA RNAME field is encoded as `local-part.domain` (no `@` allowed in
/// DNS labels). Decode by replacing the first unescaped `.` with `@`.
/// Returns empty string when the input doesn't look like an email.
fn soa_rname_to_email(rname: &str) -> String {
    if rname.is_empty() || !rname.contains('.') {
        return String::new();
    }
    let bytes = rname.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'.' {
            let (local, rest) = rname.split_at(i);
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

// ---------------------------------------------------------------------------
// Tests — merged from all five original modules
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- DnsIntel accepts --------------------------------------------------

    #[test]
    fn accepts_domain() {
        let m = DnsIntel;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    }

    #[test]
    fn accepts_ip() {
        let m = DnsIntel;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn rejects_email() {
        let m = DnsIntel;
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y")));
    }

    // -- from dns_resolver -------------------------------------------------

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

    // -- from dns_brute ----------------------------------------------------

    #[test]
    fn dictionary_is_unique_and_lowercase() {
        let mut sorted: Vec<&&str> = SUBDOMAINS.iter().collect();
        sorted.sort();
        let mut deduped = sorted.clone();
        deduped.dedup();
        assert_eq!(sorted.len(), deduped.len(), "dictionary has duplicates");
        for s in SUBDOMAINS {
            assert!(
                s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "non-lowercase entry: {s}"
            );
            assert!(
                !s.is_empty() && !s.contains('.'),
                "subdomains must be single label without dots: {s}"
            );
        }
    }

    // -- from dns_blocklist ------------------------------------------------

    #[test]
    fn reverse_ipv4() {
        assert_eq!(reverse_ip("1.2.3.4"), Some("4.3.2.1".into()));
        assert_eq!(reverse_ip("192.168.1.100"), Some("100.1.168.192".into()));
    }

    #[test]
    fn reverse_ipv6_unsupported() {
        assert_eq!(reverse_ip("::1"), None);
        assert_eq!(reverse_ip("2001:db8::1"), None);
    }

    #[test]
    fn reverse_invalid_returns_none() {
        assert_eq!(reverse_ip("not-an-ip"), None);
        assert_eq!(reverse_ip(""), None);
    }

    // -- module metadata ---------------------------------------------------

    #[test]
    fn metadata() {
        let m = DnsIntel;
        assert_eq!(m.name(), "dns_intel");
        assert_eq!(m.priority(), 30);
        assert_eq!(m.max_timeout_ms(), 15_000);
    }
}
