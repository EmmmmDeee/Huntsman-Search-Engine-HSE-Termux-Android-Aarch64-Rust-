//! HackerTarget — free DNS/subdomain/reverse-IP lookups.
//!
//! Endpoints (all free, no key):
//!   `GET https://api.hackertarget.com/hostsearch/?q={domain}`
//!   `GET https://api.hackertarget.com/reverseiplookup/?q={ip}`
//!   `GET https://api.hackertarget.com/reversedns/?q={ip}`
//!
//! Rate limit: 100 queries/day without key. Returns plain-text CSV.

use async_trait::async_trait;
use std::collections::HashSet;

use crate::core::{confidence, 
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::urlencode;

const SRC: &str = "hackertarget";
const BASE: &str = "https://api.hackertarget.com";

pub struct HackerTarget;

/// Map a `hostsearch` CSV body (`host,ip` per line) to its entities. **Pure**
/// (no network), so the line→entity mapping is unit-testable directly.
///
/// Each unique host (containing a dot) yields a `Domain` entity — confidence
/// confidence::VERY_HIGH and a `subdomain` tag when it is `domain` or a subdomain of it, else
/// confidence::MEDIUM — carrying its resolved IP as evidence. Each unique routable IP (has a
/// dot, not `0.`-prefixed) yields an `IpAddress` entity. Hosts and IPs are
/// de-duplicated within the body (IPs under an `ip:` key so a host and an IP
/// string never collide). A blank resolved IP adds no `resolved_ip` attribute.
fn build_hostsearch_entities(body: &str, domain: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for line in body.lines() {
        let parts: Vec<&str> = line.splitn(2, ',').collect();
        if parts.len() < 2 {
            continue;
        }
        let host = parts[0].trim().to_lowercase();
        let ip = parts[1].trim();

        if !host.is_empty() && host.contains('.') && seen.insert(host.clone()) {
            let is_sub = crate::util::domains::is_or_subdomain_of(&host, domain);
            let conf = if is_sub { confidence::VERY_HIGH } else { confidence::MEDIUM };
            let mut e = Entity::new(EntityKind::Domain, &host, conf, scan_id);
            e.tag("hackertarget");
            if is_sub {
                e.tag(tags::SUBDOMAIN);
            }
            let mut ev = Evidence::new(SRC, format!("Host search: {host} → {ip}"));
            if !ip.is_empty() {
                ev = ev.with_attr("resolved_ip", ip);
            }
            e.add_evidence(ev);
            out.push(e);
        }

        if !ip.is_empty()
            && ip.contains('.')
            && !ip.starts_with("0.")
            && seen.insert(format!("ip:{ip}"))
        {
            let mut e = Entity::new(EntityKind::IpAddress, ip, confidence::HIGH, scan_id);
            e.tag("hackertarget");
            e.add_evidence(Evidence::new(SRC, format!("Resolved from {host}")));
            out.push(e);
        }
    }

    out
}

/// Map a `reverseiplookup` body (one domain per line) to `Domain` entities.
/// **Pure** (no network). Each unique domain (containing a dot, not equal to the
/// queried `ip`) yields a `Domain` tagged `hackertarget` + `reverse-ip`.
fn build_reverse_ip_entities(body: &str, ip: &str, scan_id: &str) -> Vec<Entity> {
    let mut seen: HashSet<String> = HashSet::new();
    body.lines()
        .filter_map(|line| {
            let domain = line.trim().to_lowercase();
            if domain.is_empty()
                || !domain.contains('.')
                || domain == ip
                || !seen.insert(domain.clone())
            {
                return None;
            }
            let mut e = Entity::new(EntityKind::Domain, &domain, confidence::HIGH, scan_id);
            e.tag("hackertarget");
            e.tag("reverse-ip");
            e.add_evidence(Evidence::new(SRC, format!("Reverse IP lookup for {ip}")));
            Some(e)
        })
        .collect()
}

/// Map a `reversedns` body (the PTR host per line) to `Domain` entities.
/// **Pure** (no network). Each non-blank dotted host (trailing dot stripped)
/// yields a `Domain` tagged `hackertarget` + `ptr`.
fn build_reverse_dns_entities(body: &str, ip: &str, scan_id: &str) -> Vec<Entity> {
    body.lines()
        .filter_map(|line| {
            let domain = line.trim().trim_end_matches('.').to_lowercase();
            (!domain.is_empty() && domain.contains('.')).then(|| {
                let mut e = Entity::new(EntityKind::Domain, &domain, confidence::HIGH_PLUS, scan_id);
                e.tag("hackertarget");
                e.tag(tags::PTR);
                e.add_evidence(Evidence::new(SRC, format!("Reverse DNS for {ip}")));
                e
            })
        })
        .collect()
}

#[async_trait]
impl Module for HackerTarget {
    fn name(&self) -> &'static str {
        "hackertarget"
    }

    fn description(&self) -> &'static str {
        "hackertarget.com recon (free) — enumerates subdomains and pivots reverse-IP and reverse-DNS"
    }

    fn priority(&self) -> u8 {
        24
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Domain | TargetKind::IpAddress | TargetKind::Url
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // DNS lookups + passive-DNS — ATT&CK DNS (T1590.002) and DNS/Passive DNS (T1596.001).
        &["T1590.002", "T1596.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain, EntityKind::IpAddress];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let val = match target.kind {
            TargetKind::Url => match crate::util::url_util::host_from_url(&target.value) {
                Some(h) => h,
                None => return Ok(ModuleResult::new()),
            },
            _ => target.value.trim().to_string(),
        };
        if val.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();

        match target.kind {
            TargetKind::Domain | TargetKind::Url => {
                self.hostsearch(&val, ctx, &mut result).await?;
            }
            TargetKind::IpAddress => {
                self.reverse_ip(&val, ctx, &mut result).await?;
                if !ctx.cancel.is_cancelled() {
                    self.reverse_dns(&val, ctx, &mut result).await?;
                }
            }
            _ => {}
        }

        Ok(result)
    }
}

impl HackerTarget {
    async fn fetch_text(&self, url: &str, ctx: &ModuleContext) -> Result<String> {
        let resp = ctx
            .http
            .get(url)
            .timeout(std::time::Duration::from_millis(self.max_timeout_ms()))
            .send_tagged(SRC)
            .await?;

        if !resp.status().is_success() {
            return Err(Error::module(SRC, format!("HTTP {}", resp.status())));
        }

        let body = crate::util::http::read_text(SRC, resp).await?;

        if body.starts_with("error ") || body.contains("API count exceeded") {
            return Err(Error::module(SRC, body.trim().to_string()));
        }

        Ok(body)
    }

    async fn hostsearch(
        &self,
        domain: &str,
        ctx: &ModuleContext,
        result: &mut ModuleResult,
    ) -> Result<()> {
        let url = format!("{BASE}/hostsearch/?q={}", urlencode(domain));
        let body = self.fetch_text(&url, ctx).await?;
        result.extend(build_hostsearch_entities(&body, domain, &ctx.scan_id));
        Ok(())
    }

    async fn reverse_ip(
        &self,
        ip: &str,
        ctx: &ModuleContext,
        result: &mut ModuleResult,
    ) -> Result<()> {
        let url = format!("{BASE}/reverseiplookup/?q={}", urlencode(ip));
        let body = self.fetch_text(&url, ctx).await?;
        result.extend(build_reverse_ip_entities(&body, ip, &ctx.scan_id));
        Ok(())
    }

    async fn reverse_dns(
        &self,
        ip: &str,
        ctx: &ModuleContext,
        result: &mut ModuleResult,
    ) -> Result<()> {
        let url = format!("{BASE}/reversedns/?q={}", urlencode(ip));
        let body = self.fetch_text(&url, ctx).await?;
        result.extend(build_reverse_dns_entities(&body, ip, &ctx.scan_id));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
