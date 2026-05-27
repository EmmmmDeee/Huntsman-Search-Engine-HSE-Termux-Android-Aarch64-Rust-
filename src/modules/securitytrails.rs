//! SecurityTrails subdomain enumeration + reverse IP lookup. Key-gated; free tier 50 q/mo.
//!
//! Domain path: `GET https://api.securitytrails.com/v1/domain/{domain}/subdomains`
//! IP path:     `GET https://api.securitytrails.com/v1/ips/nearby/{ip}` (associated domains)
//! Auth:        `APIKEY` request header

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{error_snippet, handle_keyed_error};

const KEY_ENV: &str = "HUNTSMAN_SECTRAILS_KEY";
const SRC: &str = "securitytrails";

#[derive(Deserialize)]
struct SubdomainResp {
    #[serde(default)]
    subdomains: Vec<String>,
    #[serde(default)]
    subdomain_count: Option<u64>,
}

#[derive(Deserialize)]
struct AssociatedResp {
    #[serde(default)]
    records: Vec<AssociatedRecord>,
}

#[derive(Deserialize)]
struct AssociatedRecord {
    #[serde(default)]
    hostname: Option<String>,
}

pub struct SecurityTrails;

#[async_trait]
impl Module for SecurityTrails {
    fn name(&self) -> &'static str {
        "securitytrails"
    }
    fn description(&self) -> &'static str {
        "Subdomain enumeration and reverse IP lookup via SecurityTrails"
    }
    fn priority(&self) -> u8 {
        45
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::IpAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };

        match target.kind {
            TargetKind::Domain => self.subdomain_search(target, key, ctx).await,
            TargetKind::IpAddress => self.reverse_ip(target, key, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}

impl SecurityTrails {
    async fn subdomain_search(
        &self,
        target: &Target,
        key: &str,
        ctx: &ModuleContext,
    ) -> Result<ModuleResult> {
        let domain = target.value.trim().trim_end_matches('.').to_lowercase();
        if domain.is_empty() || domain.contains('/') {
            return Ok(ModuleResult::new());
        }
        let url = format!("https://api.securitytrails.com/v1/domain/{domain}/subdomains");
        let body: SubdomainResp = self.fetch_keyed(key, &url, ctx).await?;

        let total = body.subdomain_count.unwrap_or(body.subdomains.len() as u64);
        let total_str = total.to_string();
        let mut result = ModuleResult::with_capacity(body.subdomains.len());
        for sub in &body.subdomains {
            if sub.is_empty() {
                continue;
            }
            let host = format!("{sub}.{domain}");
            let mut e = Entity::new(EntityKind::Domain, &host, 0.88, &ctx.scan_id);
            e.tag("subdomain");
            e.tag("securitytrails");
            e.add_evidence(
                Evidence::new(SRC, format!("Subdomain of {domain} per SecurityTrails"))
                    .with_attr("parent_domain", &domain)
                    .with_attr("total_subdomains", &total_str),
            );
            result.push(e);
        }
        Ok(result)
    }

    async fn reverse_ip(
        &self,
        target: &Target,
        key: &str,
        ctx: &ModuleContext,
    ) -> Result<ModuleResult> {
        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }
        let url = format!(
            "https://api.securitytrails.com/v1/ips/nearby/{}",
            crate::util::http::urlencode(ip),
        );
        let body: AssociatedResp = self.fetch_keyed(key, &url, ctx).await?;

        let mut result = ModuleResult::new();
        for record in body.records.iter().take(30) {
            let Some(hostname) = record.hostname.as_deref() else {
                continue;
            };
            let hostname = hostname.trim().trim_end_matches('.');
            if hostname.is_empty()
                || hostname.parse::<std::net::IpAddr>().is_ok()
                || !hostname.contains('.')
            {
                continue;
            }
            let mut e = Entity::new(EntityKind::Domain, hostname, 0.82, &ctx.scan_id);
            e.tag("securitytrails");
            e.tag("reverse-ip");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Domain associated with {ip} per SecurityTrails"),
                )
                .with_attr("ip", ip),
            );
            result.push(e);
        }
        Ok(result)
    }

    async fn fetch_keyed<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
        url: &str,
        ctx: &ModuleContext,
    ) -> Result<T> {
        let mut retries = 2u8;
        loop {
            let resp = ctx
                .http
                .get(url)
                .header("APIKEY", key)
                .header("Accept", "application/json")
                .send()
                .await
                .map_err(|e| Error::module(SRC, e.to_string()))?;
            let status = resp.status();
            if status.as_u16() == 404 {
                return Err(Error::module(SRC, "404 Not Found"));
            }
            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, SRC, key, ctx).await {
                    continue;
                }
                return Err(Error::module(
                    SRC,
                    format!("HTTP {status}: {}", error_snippet(resp).await),
                ));
            }
            return resp
                .json()
                .await
                .map_err(|e| Error::module(SRC, e.to_string()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_domain_and_ip() {
        let m = SecurityTrails;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }
    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(SecurityTrails.cost(), ModuleCost::KeyGated));
    }
}
