//! HackerTarget — free DNS/subdomain/reverse-IP lookups.
//!
//! Endpoints (all free, no key):
//!   GET https://api.hackertarget.com/hostsearch/?q={domain}
//!   GET https://api.hackertarget.com/reverseiplookup/?q={ip}
//!   GET https://api.hackertarget.com/reversedns/?q={ip}
//!
//! Rate limit: 100 queries/day without key. Returns plain-text CSV.

use async_trait::async_trait;
use std::collections::HashSet;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::urlencode;

const SRC: &str = "hackertarget";
const BASE: &str = "https://api.hackertarget.com";

pub struct HackerTarget;

#[async_trait]
impl Module for HackerTarget {
    fn name(&self) -> &'static str {
        "hackertarget"
    }

    fn description(&self) -> &'static str {
        "Free subdomain + reverse-IP + reverse-DNS via hackertarget.com"
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
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        if !resp.status().is_success() {
            return Err(Error::module(SRC, format!("HTTP {}", resp.status())));
        }

        let body = resp
            .text()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

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
        let mut seen: HashSet<String> = HashSet::new();

        for line in body.lines() {
            let parts: Vec<&str> = line.splitn(2, ',').collect();
            if parts.len() < 2 {
                continue;
            }
            let host = parts[0].trim().to_lowercase();
            let ip = parts[1].trim();

            if !host.is_empty() && host.contains('.') && seen.insert(host.clone()) {
                let is_sub = host.ends_with(&format!(".{domain}")) || host == domain;
                let conf = if is_sub { 0.75 } else { 0.50 };
                let mut e = Entity::new(EntityKind::Domain, &host, conf, &ctx.scan_id);
                e.tag("hackertarget");
                if is_sub {
                    e.tag(tags::SUBDOMAIN);
                }
                e.add_evidence(
                    Evidence::new(SRC, format!("Host search: {host} → {ip}"))
                        .with_attr("resolved_ip", ip),
                );
                result.push(e);
            }

            if !ip.is_empty()
                && ip.contains('.')
                && !ip.starts_with("0.")
                && seen.insert(format!("ip:{ip}"))
            {
                let mut e = Entity::new(EntityKind::IpAddress, ip, 0.65, &ctx.scan_id);
                e.tag("hackertarget");
                e.add_evidence(Evidence::new(SRC, format!("Resolved from {host}")));
                result.push(e);
            }
        }

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
        let mut seen: HashSet<String> = HashSet::new();

        for line in body.lines() {
            let domain = line.trim().to_lowercase();
            if domain.is_empty() || !domain.contains('.') || domain == ip {
                continue;
            }
            if seen.insert(domain.clone()) {
                let mut e = Entity::new(EntityKind::Domain, &domain, 0.65, &ctx.scan_id);
                e.tag("hackertarget");
                e.tag("reverse-ip");
                e.add_evidence(Evidence::new(SRC, format!("Reverse IP lookup for {ip}")));
                result.push(e);
            }
        }

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

        for line in body.lines() {
            let domain = line.trim().trim_end_matches('.').to_lowercase();
            if domain.is_empty() || !domain.contains('.') {
                continue;
            }
            let mut e = Entity::new(EntityKind::Domain, &domain, 0.70, &ctx.scan_id);
            e.tag("hackertarget");
            e.tag(tags::PTR);
            e.add_evidence(Evidence::new(SRC, format!("Reverse DNS for {ip}")));
            result.push(e);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_domain_and_ip() {
        let m = HackerTarget;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }

    #[test]
    fn cost_is_free() {
        assert!(matches!(
            HackerTarget.cost(),
            crate::core::module::ModuleCost::Free
        ));
    }

    #[test]
    fn description_non_empty() {
        assert!(!HackerTarget.description().is_empty());
    }
}
