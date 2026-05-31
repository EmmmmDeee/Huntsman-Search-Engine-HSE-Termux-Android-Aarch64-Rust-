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
    entity::Evidence,
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::{error_snippet, handle_keyed_error, urlencode};

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
    #[serde(default)]
    created_at: Option<String>,
}

const SRC: &str = "dehashed";

pub struct DeHashed;

#[async_trait]
impl Module for DeHashed {
    fn name(&self) -> &'static str {
        "dehashed"
    }
    fn description(&self) -> &'static str {
        "Breach record search across leaked databases"
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
                | TargetKind::FullName
                | TargetKind::IpAddress
                | TargetKind::Domain
        )
    }
    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (user, key) = match (ctx.key_opt(USER_ENV), ctx.key_opt(KEY_ENV)) {
            (Some(u), Some(k)) => (u, k),
            _ => return Ok(ModuleResult::new()),
        };
        let selector = match target.kind {
            TargetKind::Email => "email",
            TargetKind::Username => "username",
            TargetKind::Phone => "phone",
            TargetKind::FullName => "name",
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
        let mut retries = 2u8;
        let body: DehashedResp = loop {
            let resp = ctx
                .http
                .get(&url)
                .basic_auth(user, Some(key))
                .header("Accept", "application/json")
                .send()
                .await
                .map_err(|e| Error::module(SRC, e.to_string()))?;
            let status = resp.status();
            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, SRC, key, ctx).await {
                    continue;
                }
                return Err(Error::module(
                    "dehashed",
                    format!("HTTP {status}: {}", error_snippet(resp).await),
                ));
            }
            break resp
                .json()
                .await
                .map_err(|e| Error::module(SRC, e.to_string()))?;
        };

        let entries = body.entries.unwrap_or_default();
        let total = body.total.unwrap_or(entries.len() as u64);
        if entries.is_empty() && total == 0 {
            return Ok(ModuleResult::new());
        }

        let mut entity = target.to_entity(0.88, &ctx.scan_id);
        entity.tag(tags::BREACH);
        entity.tag("dehashed");

        // Top databases by frequency (capped at 5).
        let top = crate::util::freq::top_n(
            entries
                .iter()
                .filter_map(|e| e.database_name.as_deref().or(e.obtained_from.as_deref())),
            5,
        );

        let mut ev = Evidence::new(
            SRC,
            format!("DeHashed: {total} breach record(s) for {selector}={value}"),
        )
        .with_attr("hits", total.to_string())
        .with_attr("returned", entries.len().to_string())
        .with_attr("selector", selector);
        if !top.is_empty() {
            ev = ev.with_attr("top_databases", top);
        }
        let earliest = entries.iter().filter_map(|e| e.created_at.as_deref()).min();
        let latest = entries.iter().filter_map(|e| e.created_at.as_deref()).max();
        if let Some(e) = earliest {
            ev = ev.with_attr("earliest_record", e);
        }
        if let Some(l) = latest {
            ev = ev.with_attr("latest_record", l);
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
    fn accepts_six_kinds() {
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
        assert!(m.accepts(&Target::new(TargetKind::FullName, "Jane Doe")));
    }
    #[test]
    fn cost_is_paid() {
        assert!(matches!(DeHashed.cost(), ModuleCost::Paid));
    }
}
