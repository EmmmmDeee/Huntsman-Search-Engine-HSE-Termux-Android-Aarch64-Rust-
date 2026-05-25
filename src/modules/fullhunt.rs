//! FullHunt — attack surface discovery. Key-gated (free tier available).
//!
//! Endpoint: `GET https://fullhunt.io/api/v1/domain/{domain}/subdomains`
//! Auth:     `X-API-KEY: {HUNTSMAN_FULLHUNT_KEY}` header.
//!
//! Returns subdomains, DNS records, open ports, and technologies for a
//! domain. Complements SecurityTrails and dns_brute with a different
//! vantage point (FullHunt's own internet-wide scanner data).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

const KEY_ENV: &str = "HUNTSMAN_FULLHUNT_KEY";

#[derive(Deserialize)]
#[allow(dead_code)]
struct Resp {
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    status: Option<i32>,
    #[serde(default)]
    domain: Option<String>,
}

pub struct FullHunt;

#[async_trait]
impl Module for FullHunt {
    fn name(&self) -> &'static str {
        "fullhunt"
    }
    fn priority(&self) -> u8 {
        78
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }
    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;
        let domain = target.value.trim().to_lowercase();
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://fullhunt.io/api/v1/domain/{}/subdomains",
            crate::util::http::urlencode(&domain)
        );
        let resp = ctx
            .http
            .get(&url)
            .header("X-API-KEY", key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("fullhunt", e.to_string()))?;

        let status = resp.status().as_u16();
        if status == 404 {
            return Ok(ModuleResult::new());
        }
        if !(200..=299).contains(&status) {
            return Err(Error::module(
                "fullhunt",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let body: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module("fullhunt", e.to_string()))?;

        if body.hosts.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        const MAX_SUBS: usize = 50;
        for host in body.hosts.iter().take(MAX_SUBS) {
            let host = host.trim().to_lowercase();
            if host.is_empty() || host == domain {
                continue;
            }
            let mut entity = Entity::new(EntityKind::Domain, &host, 0.82, &ctx.scan_id);
            entity.tag("fullhunt");
            entity.tag("subdomain");
            entity.add_evidence(
                Evidence::new("fullhunt", format!("Subdomain of {domain} via FullHunt"))
                    .with_attr("parent", &domain),
            );
            result.push(entity);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_domain() {
        assert!(FullHunt.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(!FullHunt.accepts(&Target::new(TargetKind::Email, "x@y")));
    }
    #[test]
    fn cost_key_gated() {
        assert!(matches!(FullHunt.cost(), ModuleCost::KeyGated));
    }
}
