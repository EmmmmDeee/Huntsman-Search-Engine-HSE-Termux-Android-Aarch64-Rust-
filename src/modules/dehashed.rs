//! DeHashed breach search. Paid; requires `HUNTSMAN_DEHASHED_USER`
//! (account email) + `HUNTSMAN_DEHASHED_KEY` (API key).
//!
//! Endpoint: `GET https://api.dehashed.com/search?query={selector}:{value}`
//! Auth:     HTTP Basic (`user:key`)
//!
//! Per the project's no-credentials-in-evidence invariant, we deliberately
//! do NOT deserialise password / hashed_password / passwords fields and
//! never surface them. Only aggregate metadata escapes: total entries,
//! top databases, indexed timestamp range.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{error_snippet, urlencode};

const USER_ENV: &str = "HUNTSMAN_DEHASHED_USER";
const KEY_ENV: &str = "HUNTSMAN_DEHASHED_KEY";

#[derive(Deserialize)]
struct DehashedResp {
    #[serde(default)]
    entries: Option<Vec<Entry>>,
    #[serde(default)]
    total: Option<u64>,
}

/// Aggregate-safe field set — `password`, `hashed_password`, etc. are
/// deliberately omitted so we can't even accidentally surface them.
#[derive(Deserialize)]
struct Entry {
    #[serde(default)]
    database_name: Option<String>,
    #[serde(default)]
    obtained_from: Option<String>,
}

pub struct DeHashed;

#[async_trait]
impl Module for DeHashed {
    fn name(&self) -> &'static str {
        "dehashed"
    }
    fn priority(&self) -> u8 {
        118
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email
                | TargetKind::Username
                | TargetKind::Phone
                | TargetKind::IpAddress
                | TargetKind::Domain
        )
    }
    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let user = ctx.key(USER_ENV)?;
        let key = ctx.key(KEY_ENV)?;
        let selector = match target.kind {
            TargetKind::Email => "email",
            TargetKind::Username => "username",
            TargetKind::Phone => "phone",
            TargetKind::IpAddress => "ip_address",
            TargetKind::Domain => "domain",
            _ => return Ok(ModuleResult::new()),
        };
        let value = target.value.trim();
        if value.is_empty() {
            return Ok(ModuleResult::new());
        }
        let q = format!("{selector}:{value}");
        let url = format!("https://api.dehashed.com/search?query={}", urlencode(&q));
        let resp = ctx
            .http
            .get(&url)
            .basic_auth(user, Some(key))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("dehashed", e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::module(
                "dehashed",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }
        let body: DehashedResp = resp
            .json()
            .await
            .map_err(|e| Error::module("dehashed", e.to_string()))?;

        let entries = body.entries.unwrap_or_default();
        let total = body.total.unwrap_or(entries.len() as u64);
        if entries.is_empty() && total == 0 {
            return Ok(ModuleResult::new());
        }

        let kind = match target.kind {
            TargetKind::Email => EntityKind::Email,
            TargetKind::Username => EntityKind::Username,
            TargetKind::Phone => EntityKind::Phone,
            TargetKind::IpAddress => EntityKind::IpAddress,
            TargetKind::Domain => EntityKind::Domain,
            other => {
                return Err(Error::module(
                    "dehashed",
                    format!("unexpected target kind: {other:?}"),
                ));
            }
        };
        let mut entity = Entity::new(kind, value, 0.88, &ctx.scan_id);
        entity.tag("breach");
        entity.tag("dehashed");

        // Top databases by frequency (capped at 5).
        let mut counts: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
        for e in &entries {
            if let Some(db) = e.database_name.as_deref().or(e.obtained_from.as_deref()) {
                *counts.entry(db.to_string()).or_insert(0) += 1;
            }
        }
        let mut ranked: Vec<(String, u32)> = counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let top = ranked
            .iter()
            .take(5)
            .map(|(db, n)| format!("{db}×{n}"))
            .collect::<Vec<_>>()
            .join(", ");

        let mut ev = Evidence::new(
            "dehashed",
            format!("DeHashed: {total} breach record(s) for {selector}={value}"),
        )
        .with_attr("hits", total.to_string())
        .with_attr("returned", entries.len().to_string())
        .with_attr("selector", selector);
        if !top.is_empty() {
            ev = ev.with_attr("top_databases", top);
        }
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
    fn accepts_five_kinds() {
        let m = DeHashed;
        for k in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::Phone,
            TargetKind::IpAddress,
            TargetKind::Domain,
        ] {
            assert!(m.accepts(&Target::new(k, "x")));
        }
        assert!(!m.accepts(&Target::new(TargetKind::FullName, "Jane Doe")));
    }
    #[test]
    fn cost_is_paid() {
        assert!(matches!(DeHashed.cost(), ModuleCost::Paid));
    }
}
