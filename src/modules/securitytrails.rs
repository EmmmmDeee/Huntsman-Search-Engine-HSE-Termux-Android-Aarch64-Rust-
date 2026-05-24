//! SecurityTrails subdomain enumeration. Key-gated; free tier 50 q/mo.
//!
//! Endpoint: `GET https://api.securitytrails.com/v1/domain/{domain}/subdomains`
//! Auth:     `APIKEY` request header
//!
//! Returns sub-labels (without the parent suffix). We emit each as a
//! `Domain` entity tagged `subdomain` + `securitytrails`. SecurityTrails
//! also offers `/v1/history/...` endpoints that we don't yet wire — same
//! key, future module.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

const KEY_ENV: &str = "HUNTSMAN_SECTRAILS_KEY";

#[derive(Deserialize)]
struct Resp {
    #[serde(default)]
    subdomains: Vec<String>,
    #[serde(default)]
    subdomain_count: Option<u64>,
}

pub struct SecurityTrails;

#[async_trait]
impl Module for SecurityTrails {
    fn name(&self) -> &'static str {
        "securitytrails"
    }
    fn description(&self) -> &'static str {
        "Subdomain enumeration via SecurityTrails API"
    }
    fn priority(&self) -> u8 {
        45
    }

    fn description(&self) -> &'static str {
        "SecurityTrails subdomain enumeration via passive-DNS registry view. Key-gated, generous free tier."
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;
        let domain = target.value.trim().trim_end_matches('.').to_lowercase();
        if domain.is_empty() || domain.contains('/') {
            return Ok(ModuleResult::new());
        }
        let url = format!("https://api.securitytrails.com/v1/domain/{domain}/subdomains");
        let resp = ctx
            .http
            .get(&url)
            .header("APIKEY", key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("securitytrails", e.to_string()))?;
        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            return Err(Error::module(
                "securitytrails",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }
        let body: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module("securitytrails", e.to_string()))?;

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
                Evidence::new(
                    "securitytrails",
                    format!("Subdomain of {domain} per SecurityTrails"),
                )
                .with_attr("parent_domain", &domain)
                .with_attr("total_subdomains", &total_str),
            );
            result.push(e);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_domain() {
        let m = SecurityTrails;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }
    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(SecurityTrails.cost(), ModuleCost::KeyGated));
    }
}
