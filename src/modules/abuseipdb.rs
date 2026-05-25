//! AbuseIPDB — IP abuse/reputation check. Key-gated (free: 1000/day).
//!
//! Endpoint: `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90`
//! Auth:     `Key: {HUNTSMAN_ABUSEIPDB_KEY}` header.
//!
//! Returns an abuse confidence score (0–100), report count, country code,
//! ISP/domain, usage type, and whether the IP is whitelisted. High-abuse
//! IPs get tagged for the correlator.
//!
//! Fills the SpiderFoot `sfp_abuseipdb` gap.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

const KEY_ENV: &str = "HUNTSMAN_ABUSEIPDB_KEY";

#[derive(Deserialize)]
struct Wrapper {
    #[serde(default)]
    data: Option<Data>,
}

#[derive(Deserialize)]
struct Data {
    #[serde(default, rename = "abuseConfidenceScore")]
    abuse_score: Option<i32>,
    #[serde(default, rename = "totalReports")]
    total_reports: Option<i32>,
    #[serde(default, rename = "countryCode")]
    country_code: Option<String>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default, rename = "usageType")]
    usage_type: Option<String>,
    #[serde(default, rename = "isWhitelisted")]
    is_whitelisted: Option<bool>,
    #[serde(default, rename = "isTor")]
    is_tor: Option<bool>,
    #[serde(default, rename = "lastReportedAt")]
    last_reported: Option<String>,
}

pub struct AbuseIpDb;

#[async_trait]
impl Module for AbuseIpDb {
    fn name(&self) -> &'static str {
        "abuseipdb"
    }
    fn priority(&self) -> u8 {
        95
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::IpAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;
        let ip = target.value.trim();
        if ip.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90",
            crate::util::http::urlencode(ip)
        );
        let resp = ctx
            .http
            .get(&url)
            .header("Key", key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("abuseipdb", e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::module(
                "abuseipdb",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let body: Wrapper = resp
            .json()
            .await
            .map_err(|e| Error::module("abuseipdb", e.to_string()))?;

        let Some(data) = body.data else {
            return Ok(ModuleResult::new());
        };

        let mut entity = Entity::new(EntityKind::IpAddress, ip, 0.87, &ctx.scan_id);
        entity.tag("abuseipdb");

        let score = data.abuse_score.unwrap_or(0);
        if score >= 80 {
            entity.tag("high-risk");
            entity.tag("recent-abuse");
        } else if score >= 25 {
            entity.tag("elevated-risk");
        }
        if data.is_tor == Some(true) {
            entity.tag("tor");
        }
        if data.is_whitelisted == Some(true) {
            entity.tag("whitelisted");
        }
        if let Some(cc) = data.country_code.as_deref() {
            entity.tag(format!("country:{}", cc.to_uppercase()));
        }

        let mut ev = Evidence::new("abuseipdb", format!("AbuseIPDB: {ip} score={score}"))
            .with_attr("abuse_score", score.to_string());

        if let Some(r) = data.total_reports {
            ev = ev.with_attr("total_reports", r.to_string());
        }
        if let Some(v) = data.country_code.as_deref() {
            ev = ev.with_attr("country", v);
        }
        if let Some(v) = data.isp.as_deref() {
            ev = ev.with_attr("isp", v);
        }
        if let Some(v) = data.domain.as_deref() {
            ev = ev.with_attr("domain", v);
        }
        if let Some(v) = data.usage_type.as_deref() {
            ev = ev.with_attr("usage_type", v);
        }
        if let Some(v) = data.last_reported.as_deref() {
            ev = ev.with_attr("last_reported", v);
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
    fn accepts_ip_only() {
        let m = AbuseIpDb;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y")));
    }
    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(AbuseIpDb.cost(), ModuleCost::KeyGated));
    }
}
