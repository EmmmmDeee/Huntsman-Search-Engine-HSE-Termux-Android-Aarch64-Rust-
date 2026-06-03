//! VirusTotal — URL and domain reputation scanning via the VT v3 API.
//!
//! Queries the VirusTotal API for domain/URL/IP analysis results.
//! Tags entities with detection ratios and threat categories.
//! Requires HUNTSMAN_VIRUSTOTAL_KEY.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "virustotal";

pub struct VirusTotal;

#[async_trait]
impl Module for VirusTotal {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "VirusTotal domain/IP/URL reputation and detection ratios"
    }
    fn priority(&self) -> u8 {
        55
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::IpAddress)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Threat
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let url = match target.kind {
            TargetKind::Domain => format!(
                "https://www.virustotal.com/api/v3/domains/{}",
                crate::util::http::urlencode(&target.value)
            ),
            TargetKind::IpAddress => format!(
                "https://www.virustotal.com/api/v3/ip_addresses/{}",
                crate::util::http::urlencode(&target.value)
            ),
            _ => return Ok(result),
        };

        let Some(body) = crate::util::http::fetch_keyed_json::<VtResponse>(
            ctx,
            SRC,
            &url,
            "HUNTSMAN_VIRUSTOTAL_KEY",
            "x-apikey",
        )
        .await?
        else {
            return Ok(result);
        };

        let Some(attrs) = body.data.and_then(|d| d.attributes) else {
            return Ok(result);
        };

        let malicious = attrs
            .last_analysis_stats
            .as_ref()
            .map_or(0, |s| s.malicious);
        let total = attrs.last_analysis_stats.as_ref().map_or(0, |s| {
            s.malicious + s.undetected + s.harmless + s.suspicious
        });

        let confidence = if total > 0 {
            0.50 + (malicious as f64 / total as f64) * 0.45
        } else {
            0.50
        };

        let mut e = Entity::new(
            target.kind.to_entity_kind(),
            &target.value,
            confidence,
            &ctx.scan_id,
        );
        if malicious > 0 {
            e.tag("malicious");
            e.tag("threat-intel");
        }
        e.tag("virustotal");
        e.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "{}/{} engines flagged {} as malicious",
                    malicious, total, target.value
                ),
            )
            .with_attr("malicious", malicious.to_string())
            .with_attr("total_engines", total.to_string())
            .with_attr("reputation", attrs.reputation.unwrap_or(0).to_string()),
        );
        result.push(e);

        Ok(result)
    }
}

#[derive(Deserialize)]
struct VtResponse {
    data: Option<VtData>,
}

#[derive(Deserialize)]
struct VtData {
    attributes: Option<VtAttributes>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct VtAttributes {
    last_analysis_stats: Option<VtStats>,
    reputation: Option<i64>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct VtStats {
    #[serde(default)]
    malicious: u32,
    #[serde(default)]
    suspicious: u32,
    #[serde(default)]
    undetected: u32,
    #[serde(default)]
    harmless: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_vt_response() {
        let json = r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":3,"suspicious":1,"undetected":60,"harmless":10},"reputation":5}}}"#;
        let r: VtResponse = serde_json::from_str(json).unwrap();
        let attrs = r.data.unwrap().attributes.unwrap();
        assert_eq!(attrs.last_analysis_stats.unwrap().malicious, 3);
        assert_eq!(attrs.reputation, Some(5));
    }

    #[test]
    fn deserialize_empty_response() {
        let json = r#"{"data":null}"#;
        let r: VtResponse = serde_json::from_str(json).unwrap();
        assert!(r.data.is_none());
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = VirusTotal;
        assert_eq!(m.cost(), ModuleCost::KeyGated);
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }
}
