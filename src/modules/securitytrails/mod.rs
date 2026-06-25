//! SecurityTrails subdomain enumeration + reverse IP lookup. Key-gated; free tier 50 q/mo.
//!
//! Domain path: `GET https://api.securitytrails.com/v1/domain/{domain}/subdomains`
//! IP path:     `GET https://api.securitytrails.com/v1/ips/list?ipAddresses={ip}` (associated domains)
//! Auth:        `APIKEY` request header
//!
//! Both response→entity mappings are pure ([`build_subdomain_entity`],
//! [`build_associated_entity`]) so they are unit-tested without a live key.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::handle_keyed_error;

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

/// Cap on associated-domain records turned into entities from one reverse-IP
/// lookup — a busy shared host can list thousands; 30 is enough to pivot on
/// without flooding expansion.
const MAX_REVERSE_RECORDS: usize = 30;

/// Build the `Domain` entity for one enumerated subdomain label under `domain`.
/// **Pure** (no network/IO). `total_str` is the parent's reported subdomain
/// count, carried as evidence context. Returns `None` for a blank label.
fn build_subdomain_entity(
    domain: &str,
    sub: &str,
    total_str: &str,
    scan_id: &str,
) -> Option<Entity> {
    let sub = sub.trim();
    if sub.is_empty() {
        return None;
    }
    let host = format!("{sub}.{domain}");
    let mut e = Entity::new(EntityKind::Domain, &host, 0.88, scan_id);
    e.tag("subdomain");
    e.tag("securitytrails");
    e.add_evidence(
        Evidence::new(SRC, format!("Subdomain of {domain} per SecurityTrails"))
            .with_attr("parent_domain", domain)
            .with_attr("total_subdomains", total_str),
    );
    Some(e)
}

/// Build the `Domain` entity for one reverse-IP associated record. **Pure** (no
/// network/IO): trims a trailing dot and rejects anything that is not a usable
/// hostname — blank, a bare IP literal (the PTR pointing back at the IP itself),
/// or a single label with no dot. Returns `None` for a rejected record.
fn build_associated_entity(ip: &str, hostname: Option<&str>, scan_id: &str) -> Option<Entity> {
    let hostname = hostname?.trim().trim_end_matches('.');
    if hostname.is_empty()
        || hostname.parse::<std::net::IpAddr>().is_ok()
        || !hostname.contains('.')
    {
        return None;
    }
    let mut e = Entity::new(EntityKind::Domain, hostname, 0.82, scan_id);
    e.tag("securitytrails");
    e.tag("reverse-ip");
    e.add_evidence(
        Evidence::new(
            SRC,
            format!("Domain associated with {ip} per SecurityTrails"),
        )
        .with_attr("ip", ip),
    );
    Some(e)
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

    fn cache_ttl_secs(&self) -> u64 {
        86_400
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::IpAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Historical/passive DNS database — ATT&CK DNS/Passive DNS (T1596.001).
        &["T1596.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
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
        result.extend(
            body.subdomains
                .iter()
                .filter_map(|sub| build_subdomain_entity(&domain, sub, &total_str, &ctx.scan_id)),
        );
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
            "https://api.securitytrails.com/v1/ips/list?ipAddresses={}",
            crate::util::http::urlencode(ip),
        );
        let body: AssociatedResp = match self.fetch_keyed(key, &url, ctx).await {
            Ok(b) => b,
            // fetch_keyed returns Err on 404 (no records for this IP);
            // treat as an empty result rather than a module-level error.
            Err(e) if e.to_string().contains("404") => return Ok(ModuleResult::new()),
            Err(e) => return Err(e),
        };

        let mut result = ModuleResult::new();
        result.extend(
            body.records
                .iter()
                .take(MAX_REVERSE_RECORDS)
                .filter_map(|record| {
                    build_associated_entity(ip, record.hostname.as_deref(), &ctx.scan_id)
                }),
        );
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
                .send_tagged(SRC)
                .await?;
            let status = resp.status();
            if status.as_u16() == 404 {
                return Err(Error::module(SRC, "404 Not Found"));
            }
            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, SRC, key, ctx).await {
                    continue;
                }
                return Err(crate::util::http::http_status_error(SRC, resp).await);
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
    include!("tests.rs");
}
