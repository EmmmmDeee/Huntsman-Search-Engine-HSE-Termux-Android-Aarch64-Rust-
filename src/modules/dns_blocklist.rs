//! DNS blocklist (DNSBL) checker — free, zero API keys, pure DNS.
//!
//! Checks an IP against well-known DNS-based blocklists by performing
//! A-record lookups on `<reversed-ip>.<dnsbl-zone>`. A positive result
//! (any A record returned) means the IP is listed. Each blocklist
//! lookup is an independent DNS query — no HTTP, no rate limits, no
//! authentication.
//!
//! Blocklist sources:
//!   - zen.spamhaus.org    — spam/botnet/exploit (most authoritative)
//!   - bl.spamcop.net      — spam sources reported by users
//!   - dnsbl.sorbs.net     — open relays, proxies, spam
//!   - b.barracudacentral  — barracuda's spam/threat list
//!   - cbl.abuseat.org     — composite blocklist (bots/trojans)
//!   - dnsbl-1.uceprotect  — single-IP listings
//!   - psbl.surriel.com    — passive spam blocklist
//!   - all.s5h.net         — aggregated blocklist
//!
//! Entity production:
//!   - IpAddress entity tagged `blocklisted` with listing count and
//!     specific lists in evidence. Feeds AU-008 correlator rule for
//!     cross-referencing with domain hosting.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::dns::shared_resolver;

pub struct DnsBlocklist;

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

#[async_trait]
impl Module for DnsBlocklist {
    fn name(&self) -> &'static str {
        "dns_blocklist"
    }

    fn description(&self) -> &'static str {
        "DNSBL reputation check against 8 blocklists"
    }

    fn priority(&self) -> u8 {
        29
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }

        let reversed = match reverse_ip(ip) {
            Some(r) => r,
            None => return Ok(ModuleResult::new()),
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

        let mut result = ModuleResult::new();

        let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.90, &ctx.scan_id);
        entity.tag("dnsbl-checked");

        if listed_on.is_empty() {
            entity.add_evidence(
                Evidence::new("dns_blocklist", format!("{ip} clean on {checked} blocklists"))
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
                    "dns_blocklist",
                    format!("{ip} listed on {} of {} blocklists", listed_on.len(), checked),
                )
                .with_attr("listed_count", listed_on.len().to_string())
                .with_attr("checked_count", checked.to_string())
                .with_attr("listed_on", listed_on.join(", "))
                .with_attr("status", "listed"),
            );
        }

        result.push(entity);
        Ok(result)
    }
}

fn reverse_ip(ip: &str) -> Option<String> {
    let parsed: std::net::IpAddr = ip.parse().ok()?;
    match parsed {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            Some(format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0]))
        }
        std::net::IpAddr::V6(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ip_only() {
        let m = DnsBlocklist;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y")));
    }

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
}
