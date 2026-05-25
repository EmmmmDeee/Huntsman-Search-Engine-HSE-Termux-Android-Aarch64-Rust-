use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::Evidence,
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
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

/// Password fields deliberately omitted to prevent accidental credential exposure.
#[derive(Deserialize)]
struct Entry {
    #[serde(default)]
    database_name: Option<String>,
    #[serde(default)]
    obtained_from: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
}

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

        let mut entity = target.to_entity(0.88, &ctx.scan_id);
        entity.tag(tags::BREACH);
        entity.tag("dehashed");

        let top = crate::util::freq::top_n(
            entries
                .iter()
                .filter_map(|e| e.database_name.as_deref().or(e.obtained_from.as_deref())),
            5,
        );

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
        let earliest = entries.iter().filter_map(|e| e.created_at.as_deref()).min();
        let latest = entries.iter().filter_map(|e| e.created_at.as_deref()).max();
        ev = ev
            .with_opt_attr("earliest_record", earliest)
            .with_opt_attr("latest_record", latest);
        entity.add_evidence(ev);

        // OathNet stealer cross-reference — supplements DeHashed breach data
        let oathnet_key =
            crate::util::oathnet::resolve_key(ctx.key_opt(crate::util::oathnet::KEY_ENV));
        if !ctx.cancel.is_cancelled() {
            let oathnet_field = match target.kind {
                TargetKind::Email => "email",
                TargetKind::Username => "username",
                TargetKind::Phone => "phone",
                TargetKind::IpAddress => "ip",
                TargetKind::Domain => "domain",
                _ => "",
            };
            if !oathnet_field.is_empty() {
                if let Ok(stealer_items) = crate::util::oathnet::search(
                    oathnet_key,
                    crate::util::oathnet::paths::STEALER,
                    oathnet_field,
                    &target.value,
                    20,
                )
                .await
                {
                    if !stealer_items.is_empty() {
                        entity.tag(tags::STEALER_LOG);
                        entity.add_evidence(
                            crate::core::entity::Evidence::new(
                                "dehashed:oathnet",
                                format!(
                                    "OathNet: {} stealer log record(s)",
                                    stealer_items.len()
                                ),
                            )
                            .with_attr(
                                "stealer_hits",
                                stealer_items.len().to_string(),
                            ),
                        );
                    }
                }
            }
        }

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
