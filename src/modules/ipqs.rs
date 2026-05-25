use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::Evidence,
    error::Result,
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

const KEY_ENV: &str = "HUNTSMAN_IPQS_KEY";

#[derive(Deserialize)]
struct Common {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    fraud_score: Option<i32>,
    #[serde(default)]
    recent_abuse: Option<bool>,
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
        let key = ctx.key(KEY_ENV)?;
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
        let Some(body): Option<Common> = fetch_json_or_404(&ctx.http, "ipqs", &url).await? else {
            return Ok(ModuleResult::new());
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
        entity.tag_opt(body.proxy, "proxy");
        entity.tag_opt(body.vpn, "vpn");
        entity.tag_opt(body.tor, "tor");
        entity.tag_opt(body.is_crawler, "crawler");
        entity.tag_opt(body.disposable, "disposable");
        entity.tag_opt(body.leaked, "leaked");
        entity.tag_opt(body.recent_abuse, "recent-abuse");
        if let Some(c) = body.country_code.as_deref() {
            entity.tag(format!("country:{}", c.to_uppercase()));
        }

        entity.add_evidence(
            Evidence::new(
                "ipqs",
                format!("IPQS {endpoint} reputation for {value} (fraud_score={score})"),
            )
            .with_attr("endpoint", endpoint)
            .with_attr("fraud_score", score.to_string())
            .with_opt_attr("isp", body.isp.as_deref())
            .with_opt_attr("organization", body.organization.as_deref())
            .with_opt_attr("asn", body.asn.map(|v| v.to_string()))
            .with_opt_attr("country", body.country_code.as_deref())
            .with_opt_attr("deliverability", body.deliverability.as_deref())
            .with_opt_attr("smtp_score", body.smtp_score.map(|v| v.to_string()))
            .with_opt_attr("line_type", body.line_type.as_deref())
            .with_opt_attr("carrier", body.carrier.as_deref())
            .with_opt_attr("valid", body.valid.map(|v| v.to_string()))
            .with_opt_attr("active", body.active.map(|v| v.to_string()))
            .with_opt_attr(
                "first_seen",
                body.first_seen.as_ref().and_then(|fs| fs.human.clone()),
            ),
        );
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
