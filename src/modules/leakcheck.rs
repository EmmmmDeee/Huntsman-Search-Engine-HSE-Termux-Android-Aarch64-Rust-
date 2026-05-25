//! LeakCheck — breach database search. Key-gated (paid tiers).
//!
//! Endpoint: `GET https://leakcheck.io/api/v2/query/{email}`
//! Auth:     `X-API-Key: {HUNTSMAN_LEAKCHECK_KEY}` header.
//!
//! Returns breach sources where the email appears, with partial
//! password hashes and breach dates. Complements HIBP (which lists
//! breach names but not hash data) and HudsonRock (stealer-log focus).
//! Per project invariant, we surface source names and dates but never
//! store or display actual passwords or full hashes.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

const KEY_ENV: &str = "HUNTSMAN_LEAKCHECK_KEY";

#[derive(Deserialize)]
#[allow(dead_code)]
struct Resp {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    found: Option<u32>,
    #[serde(default)]
    result: Vec<LeakEntry>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct LeakEntry {
    #[serde(default)]
    source: Option<Source>,
    #[serde(default)]
    last_breach: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Source {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    date: Option<String>,
}

pub struct LeakCheck;

#[async_trait]
impl Module for LeakCheck {
    fn name(&self) -> &'static str {
        "leakcheck"
    }
    fn priority(&self) -> u8 {
        132
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;
        let email = target.value.trim().to_lowercase();
        if email.is_empty() || !email.contains('@') {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://leakcheck.io/api/v2/query/{}",
            crate::util::http::urlencode(&email)
        );
        let resp = ctx
            .http
            .get(&url)
            .header("X-API-Key", key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("leakcheck", e.to_string()))?;

        let status = resp.status().as_u16();
        if status == 404 {
            return Ok(ModuleResult::new());
        }
        if status == 401 {
            return Err(Error::module("leakcheck", "invalid API key"));
        }
        if status == 429 {
            return Err(Error::module("leakcheck", "rate limited"));
        }
        if !(200..=299).contains(&status) {
            return Err(Error::module(
                "leakcheck",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let body: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module("leakcheck", e.to_string()))?;

        let found = body.found.unwrap_or(0);
        if found == 0 || body.result.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut entity = Entity::new(EntityKind::Email, &email, 0.92, &ctx.scan_id);
        entity.tag("breach");
        entity.tag("leakcheck");
        entity.tag("credentials-leaked");

        let source_names: Vec<&str> = body
            .result
            .iter()
            .filter_map(|e| e.source.as_ref()?.name.as_deref())
            .take(20)
            .collect();
        let latest = body
            .result
            .iter()
            .filter_map(|e| e.last_breach.as_deref())
            .max();

        let ev = Evidence::new(
            "leakcheck",
            format!("LeakCheck: {email} found in {found} source(s)"),
        )
        .with_attr("found", found.to_string())
        .with_attr("sources", source_names.join(", "))
        .opt_attr("latest_breach", latest);

        entity.add_evidence(ev);
        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_email() {
        assert!(LeakCheck.accepts(&Target::new(TargetKind::Email, "x@y")));
        assert!(!LeakCheck.accepts(&Target::new(TargetKind::Domain, "y")));
    }
    #[test]
    fn cost_is_paid() {
        assert!(matches!(LeakCheck.cost(), ModuleCost::Paid));
    }
}
