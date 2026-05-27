//! IPQualityScore (IPQS) reputation lookup. Key-gated; free tier available.
//!
//! Three endpoints sharing the same URL shape and key dispatch:
//!   * IP:    `GET /api/json/ip/{key}/{ip}`
//!   * Email: `GET /api/json/email/{key}/{email}`
//!   * Phone: `GET /api/json/phone/{key}/{phone}`
//!
//! Each returns a `fraud_score` (0–100) plus type-specific signals.
//! We tag risky outputs (`high-risk`, `proxy`, `vpn`, `tor`, `disposable`,
//! `recent_abuse`) and embed the raw score in evidence for triage.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::Evidence,
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{error_snippet, handle_keyed_error, urlencode};

const KEY_ENV: &str = "HUNTSMAN_IPQS_KEY";

#[derive(Deserialize)]
struct Common {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    fraud_score: Option<i32>,
    #[serde(default)]
    recent_abuse: Option<bool>,
    // IP-specific
    #[serde(default)]
    proxy: Option<bool>,
    #[serde(default)]
    vpn: Option<bool>,
    #[serde(default)]
    tor: Option<bool>,
    #[serde(default)]
    is_crawler: Option<bool>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    organization: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    asn: Option<i64>,
    // Email-specific
    #[serde(default)]
    valid: Option<bool>,
    #[serde(default)]
    disposable: Option<bool>,
    #[serde(default)]
    deliverability: Option<String>,
    #[serde(default)]
    smtp_score: Option<i32>,
    #[serde(default)]
    leaked: Option<bool>,
    #[serde(default)]
    first_seen: Option<FirstSeen>,
    // Phone-specific
    #[serde(default)]
    line_type: Option<String>,
    #[serde(default)]
    carrier: Option<String>,
    #[serde(default)]
    active: Option<bool>,
}

#[derive(Deserialize)]
struct FirstSeen {
    #[serde(default)]
    human: Option<String>,
}

pub struct IpQs;

#[async_trait]
impl Module for IpQs {
    fn name(&self) -> &'static str {
        "ipqs"
    }
    fn description(&self) -> &'static str {
        "IP, email, and phone quality scoring"
    }
    fn priority(&self) -> u8 {
        100
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::IpAddress | TargetKind::Email | TargetKind::Phone
        )
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) { Some(k) => k, None => return Ok(ModuleResult::new()) };
        let endpoint = match target.kind {
            TargetKind::IpAddress => "ip",
            TargetKind::Email => "email",
            TargetKind::Phone => "phone",
            _ => return Ok(ModuleResult::new()),
        };
        let value = target.value.trim();
        if value.is_empty() {
            return Ok(ModuleResult::new());
        }
        let url = format!(
            "https://www.ipqualityscore.com/api/json/{endpoint}/{}/{}",
            urlencode(key),
            urlencode(value),
        );
        let mut retries = 2u8;
        let body: Common = loop {
            let resp = ctx
                .http
                .get(&url)
                .send()
                .await
                .map_err(|e| Error::module("ipqs", e.to_string()))?;
            let status = resp.status();
            if status.as_u16() == 404 {
                return Ok(ModuleResult::new());
            }
            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, "ipqs", key, ctx).await {
                    continue;
                }
                return Err(Error::module(
                    "ipqs",
                    format!("HTTP {status}: {}", error_snippet(resp).await),
                ));
            }
            break resp
                .json()
                .await
                .map_err(|e| Error::module("ipqs", e.to_string()))?;
        };
        if body.success == Some(false) {
            return Ok(ModuleResult::new());
        }

        let mut entity = target.to_entity(0.85, &ctx.scan_id);
        entity.tag("ipqs");

        let score = body.fraud_score.unwrap_or(0);
        if score >= 85 {
            entity.tag("high-risk");
        } else if score >= 50 {
            entity.tag("elevated-risk");
        }
        if body.proxy == Some(true) {
            entity.tag("proxy");
        }
        if body.vpn == Some(true) {
            entity.tag("vpn");
        }
        if body.tor == Some(true) {
            entity.tag("tor");
        }
        if body.is_crawler == Some(true) {
            entity.tag("crawler");
        }
        if body.disposable == Some(true) {
            entity.tag("disposable");
        }
        if body.leaked == Some(true) {
            entity.tag("leaked");
        }
        if body.recent_abuse == Some(true) {
            entity.tag("recent-abuse");
        }
        if let Some(c) = body.country_code.as_deref() {
            entity.tag(format!("country:{}", c.to_uppercase()));
        }

        let mut ev = Evidence::new(
            "ipqs",
            format!("IPQS {endpoint} reputation for {value} (fraud_score={score})"),
        )
        .with_attr("endpoint", endpoint)
        .with_attr("fraud_score", score.to_string());
        if let Some(v) = body.isp.as_deref() {
            ev = ev.with_attr("isp", v);
        }
        if let Some(v) = body.organization.as_deref() {
            ev = ev.with_attr("organization", v);
        }
        if let Some(v) = body.asn {
            ev = ev.with_attr("asn", v.to_string());
        }
        if let Some(v) = body.country_code.as_deref() {
            ev = ev.with_attr("country", v);
        }
        if let Some(v) = body.deliverability.as_deref() {
            ev = ev.with_attr("deliverability", v);
        }
        if let Some(v) = body.smtp_score {
            ev = ev.with_attr("smtp_score", v.to_string());
        }
        if let Some(v) = body.line_type.as_deref() {
            ev = ev.with_attr("line_type", v);
        }
        if let Some(v) = body.carrier.as_deref() {
            ev = ev.with_attr("carrier", v);
        }
        if let Some(v) = body.valid {
            ev = ev.with_attr("valid", v.to_string());
        }
        if let Some(v) = body.active {
            ev = ev.with_attr("active", v.to_string());
        }
        if let Some(fs) = body.first_seen.as_ref()
            && let Some(h) = fs.human.as_deref()
        {
            ev = ev.with_attr("first_seen", h);
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
    fn accepts_three_kinds() {
        let m = IpQs;
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(m.accepts(&Target::new(TargetKind::Phone, "+1")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
    }
    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(IpQs.cost(), ModuleCost::KeyGated));
    }
}
