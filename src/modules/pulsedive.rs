//! Pulsedive — threat intelligence with breach context. Free tier available.
//!
//! Endpoint: `GET https://pulsedive.com/api/info.php?indicator={value}&key={key}`
//! Auth:     query-string `key={HUNTSMAN_PULSEDIVE_KEY}`.
//!
//! Returns risk score (none/low/medium/high/critical), associated threats,
//! feeds, and properties for IPs and domains. Complements greynoise
//! (scanner classification) and abuseipdb (abuse reports) with a
//! third independent threat-intel perspective.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

const KEY_ENV: &str = "HUNTSMAN_PULSEDIVE_KEY";

#[derive(Deserialize)]
#[allow(dead_code)]
struct Resp {
    #[serde(default)]
    indicator: Option<String>,
    #[serde(default)]
    risk: Option<String>,
    #[serde(default, rename = "riskfactors")]
    risk_factors: Vec<RiskFactor>,
    #[serde(default)]
    threats: Vec<Threat>,
    #[serde(default)]
    feeds: Vec<Feed>,
    #[serde(default)]
    properties: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RiskFactor {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    risk: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Threat {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    category: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Feed {
    #[serde(default)]
    name: Option<String>,
}

pub struct Pulsedive;

#[async_trait]
impl Module for Pulsedive {
    fn name(&self) -> &'static str {
        "pulsedive"
    }
    fn priority(&self) -> u8 {
        90
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress | TargetKind::Domain)
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;
        let Some(value) = target.trimmed() else {
            return Ok(ModuleResult::new());
        };

        let url = format!(
            "https://pulsedive.com/api/info.php?indicator={}&key={key}",
            crate::util::http::urlencode(value)
        );
        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("pulsedive", e.to_string()))?;

        let status = resp.status().as_u16();
        if status == 404 {
            return Ok(ModuleResult::new());
        }
        if !(200..=299).contains(&status) {
            return Err(Error::module(
                "pulsedive",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let body: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module("pulsedive", e.to_string()))?;

        let risk = body.risk.as_deref().unwrap_or("none");
        if risk == "none" && body.threats.is_empty() && body.feeds.is_empty() {
            return Ok(ModuleResult::new());
        }

        let kind = if matches!(target.kind, TargetKind::IpAddress) {
            EntityKind::IpAddress
        } else {
            EntityKind::Domain
        };
        let mut entity = Entity::new(kind, value, 0.83, &ctx.scan_id);
        entity.tag("pulsedive");
        entity.tag("threat-intel");

        match risk {
            "critical" | "high" => {
                entity.tag("high-risk");
                entity.tag("malicious");
            }
            "medium" => {
                entity.tag("elevated-risk");
            }
            _ => {}
        }

        let threat_names: Vec<&str> = body
            .threats
            .iter()
            .filter_map(|t| t.name.as_deref())
            .take(10)
            .collect();
        let feed_names: Vec<&str> = body
            .feeds
            .iter()
            .filter_map(|f| f.name.as_deref())
            .take(10)
            .collect();
        let risk_descs: Vec<&str> = body
            .risk_factors
            .iter()
            .filter_map(|r| r.description.as_deref())
            .take(5)
            .collect();

        let threats_str = threat_names.join(", ");
        let feeds_str = feed_names.join(", ");
        let risk_str = risk_descs.join("; ");

        let ev = Evidence::new("pulsedive", format!("Pulsedive: {value} risk={risk}"))
            .with_attr("risk", risk)
            .opt_attr(
                "threats",
                if threats_str.is_empty() {
                    None
                } else {
                    Some(threats_str.as_str())
                },
            )
            .opt_attr(
                "feeds",
                if feeds_str.is_empty() {
                    None
                } else {
                    Some(feeds_str.as_str())
                },
            )
            .opt_attr(
                "risk_factors",
                if risk_str.is_empty() {
                    None
                } else {
                    Some(risk_str.as_str())
                },
            );

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
    fn accepts_ip_and_domain() {
        assert!(Pulsedive.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(Pulsedive.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(!Pulsedive.accepts(&Target::new(TargetKind::Email, "x@y")));
    }
}
