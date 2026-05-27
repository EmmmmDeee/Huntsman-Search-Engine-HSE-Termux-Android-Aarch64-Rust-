//! AbuseIPDB — IP address abuse/threat reputation scoring.
//!
//! Queries the AbuseIPDB v2 API for abuse confidence score, report
//! count, and usage type. Tags high-risk IPs. Requires HUNTSMAN_ABUSEIPDB_KEY.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "abuseipdb";

pub struct AbuseIpDb;

#[async_trait]
impl Module for AbuseIpDb {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "AbuseIPDB IP reputation — abuse confidence score and report history"
    }
    fn priority(&self) -> u8 {
        52
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90&verbose",
            crate::util::http::urlencode(&target.value)
        );

        let Some(body) = crate::util::http::fetch_keyed_json::<AbuseResponse>(
            ctx,
            SRC,
            &url,
            "HUNTSMAN_ABUSEIPDB_KEY",
            "Key",
        )
        .await?
        else {
            return Ok(result);
        };

        let Some(data) = body.data else {
            return Ok(result);
        };

        let abuse_score = data.abuse_confidence_score.unwrap_or(0);
        let confidence = 0.60 + (abuse_score as f64 / 100.0) * 0.35;

        let mut e = Entity::new(
            EntityKind::IpAddress,
            &target.value,
            confidence,
            &ctx.scan_id,
        );
        e.tag("threat-intel");
        if abuse_score >= 80 {
            e.tag("malicious");
            e.tag("high-risk");
        } else if abuse_score >= 40 {
            e.tag("suspicious");
        }
        if data.is_tor.unwrap_or(false) {
            e.tag("tor-exit");
        }

        let mut ev = Evidence::new(
            SRC,
            format!(
                "AbuseIPDB: {}% abuse confidence, {} reports",
                abuse_score,
                data.total_reports.unwrap_or(0)
            ),
        )
        .with_attr("abuse_score", abuse_score.to_string())
        .with_attr("total_reports", data.total_reports.unwrap_or(0).to_string());
        if let Some(ref isp) = data.isp {
            ev = ev.with_attr("isp", isp);
        }
        if let Some(ref usage) = data.usage_type {
            ev = ev.with_attr("usage_type", usage);
        }
        if let Some(ref cc) = data.country_code {
            ev = ev.with_attr("country_code", cc);
        }
        e.add_evidence(ev);
        result.push(e);

        Ok(result)
    }
}

#[derive(Deserialize)]
struct AbuseResponse {
    data: Option<AbuseData>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct AbuseData {
    #[serde(rename = "abuseConfidenceScore")]
    abuse_confidence_score: Option<u32>,
    #[serde(rename = "totalReports")]
    total_reports: Option<u32>,
    #[serde(rename = "isTor")]
    is_tor: Option<bool>,
    isp: Option<String>,
    #[serde(rename = "usageType")]
    usage_type: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_abuse_response() {
        let json = r#"{"data":{"abuseConfidenceScore":85,"totalReports":42,"isTor":false,"isp":"Cloudflare","usageType":"Content Delivery Network","countryCode":"US"}}"#;
        let r: AbuseResponse = serde_json::from_str(json).unwrap();
        let d = r.data.unwrap();
        assert_eq!(d.abuse_confidence_score, Some(85));
        assert_eq!(d.total_reports, Some(42));
        assert_eq!(d.country_code.as_deref(), Some("US"));
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = AbuseIpDb;
        assert_eq!(m.cost(), ModuleCost::KeyGated);
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    }
}
