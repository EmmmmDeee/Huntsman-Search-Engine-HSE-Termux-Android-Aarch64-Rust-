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
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
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

const SRC: &str = "ipqs";

/// `fraud_score` at/above this is treated as actively malicious (`high-risk`).
const HIGH_RISK_SCORE: i32 = 85;
/// `fraud_score` at/above this (but below [`HIGH_RISK_SCORE`]) is `elevated-risk`.
const ELEVATED_RISK_SCORE: i32 = 50;

/// Map an IPQS reputation response onto the target's entity. **Pure** (no
/// network/IO): translates the `fraud_score` into a single risk tag
/// (`high-risk` ≥ [`HIGH_RISK_SCORE`], else `elevated-risk` ≥
/// [`ELEVATED_RISK_SCORE`]), raises the boolean signal tags
/// (proxy/vpn/tor/crawler/disposable/leaked/recent-abuse) only when the API said
/// `true`, and emits a `country:<CC>` tag, then records every present
/// type-specific field as evidence. `endpoint` is the IPQS sub-API (`ip` /
/// `email` / `phone`) the response came from.
fn build_reputation_entity(
    kind: EntityKind,
    endpoint: &str,
    value: &str,
    body: &Common,
    scan_id: &str,
) -> Entity {
    let mut entity = Entity::new(kind, value, 0.85, scan_id);
    entity.tag("ipqs");

    let score = body.fraud_score.unwrap_or(0);
    if score >= HIGH_RISK_SCORE {
        entity.tag("high-risk");
    } else if score >= ELEVATED_RISK_SCORE {
        entity.tag("elevated-risk");
    }
    // Boolean signal tags — raised only on an explicit `true`.
    for (flag, tag) in [
        (body.proxy, "proxy"),
        (body.vpn, "vpn"),
        (body.tor, "tor"),
        (body.is_crawler, "crawler"),
        (body.disposable, crate::core::tags::DISPOSABLE),
        (body.leaked, "leaked"),
        (body.recent_abuse, "recent-abuse"),
    ] {
        if flag == Some(true) {
            entity.tag(tag);
        }
    }
    if let Some(c) = body.country_code.as_deref() {
        entity.tag(format!("country:{}", c.to_uppercase()));
    }

    let mut ev = Evidence::new(
        SRC,
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
    entity
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

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn produces(&self) -> &'static [crate::core::entity::EntityKind] {
        use crate::core::entity::EntityKind;
        const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::Email, EntityKind::Phone];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };
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
                .map_err(|e| Error::module(SRC, e.to_string()))?;
            let status = resp.status();
            if status.as_u16() == 404 {
                return Ok(ModuleResult::new());
            }
            if !status.is_success() {
                let code = status.as_u16();
                if handle_keyed_error(code, resp.headers(), &mut retries, SRC, key, ctx).await {
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
                .map_err(|e| Error::module(SRC, e.to_string()))?;
        };
        if body.success == Some(false) {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        result.push(build_reputation_entity(
            target.kind.to_entity_kind(),
            endpoint,
            value,
            &body,
            &ctx.scan_id,
        ));
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

    fn parse(json: &str) -> Common {
        serde_json::from_str(json).unwrap()
    }

    fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
        e.evidence[0].attributes.get(k).map(String::as_str)
    }

    #[test]
    fn high_fraud_ip_tags_high_risk_and_network_signals() {
        let b = parse(
            r#"{"success":true,"fraud_score":92,"proxy":true,"vpn":true,"tor":false,
                "recent_abuse":true,"isp":"Acme","asn":64500,"country_code":"ru"}"#,
        );
        let e = build_reputation_entity(EntityKind::IpAddress, "ip", "1.2.3.4", &b, "s");
        assert_eq!(e.kind, EntityKind::IpAddress);
        assert!(e.has_tag("ipqs") && e.has_tag("high-risk"));
        assert!(!e.has_tag("elevated-risk")); // mutually exclusive band
        assert!(e.has_tag("proxy") && e.has_tag("vpn") && e.has_tag("recent-abuse"));
        assert!(!e.has_tag("tor")); // explicit false → no tag
        assert!(e.has_tag("country:RU")); // upper-cased
        assert_eq!(attr(&e, "fraud_score"), Some("92"));
        assert_eq!(attr(&e, "endpoint"), Some("ip"));
        assert_eq!(attr(&e, "asn"), Some("64500"));
        assert_eq!(attr(&e, "isp"), Some("Acme"));
    }

    #[test]
    fn risk_band_is_threshold_exact() {
        let elevated = build_reputation_entity(
            EntityKind::IpAddress,
            "ip",
            "x",
            &parse(&format!(r#"{{"fraud_score":{ELEVATED_RISK_SCORE}}}"#)),
            "s",
        );
        assert!(elevated.has_tag("elevated-risk") && !elevated.has_tag("high-risk"));

        let clean = build_reputation_entity(
            EntityKind::IpAddress,
            "ip",
            "x",
            &parse(&format!(r#"{{"fraud_score":{}}}"#, ELEVATED_RISK_SCORE - 1)),
            "s",
        );
        assert!(!clean.has_tag("elevated-risk") && !clean.has_tag("high-risk"));

        let high = build_reputation_entity(
            EntityKind::IpAddress,
            "ip",
            "x",
            &parse(&format!(r#"{{"fraud_score":{HIGH_RISK_SCORE}}}"#)),
            "s",
        );
        assert!(high.has_tag("high-risk") && !high.has_tag("elevated-risk"));
    }

    #[test]
    fn email_endpoint_surfaces_email_fields_and_tags() {
        let b = parse(
            r#"{"success":true,"fraud_score":10,"disposable":true,"leaked":true,
                "valid":true,"deliverability":"high","smtp_score":3,
                "first_seen":{"human":"2 years ago"}}"#,
        );
        let e = build_reputation_entity(EntityKind::Email, "email", "a@b.com", &b, "s");
        assert_eq!(e.kind, EntityKind::Email);
        assert!(e.has_tag("disposable") && e.has_tag("leaked"));
        assert!(!e.has_tag("high-risk") && !e.has_tag("elevated-risk")); // low score
        assert_eq!(attr(&e, "deliverability"), Some("high"));
        assert_eq!(attr(&e, "smtp_score"), Some("3"));
        assert_eq!(attr(&e, "valid"), Some("true"));
        assert_eq!(attr(&e, "first_seen"), Some("2 years ago"));
    }

    #[test]
    fn missing_fraud_score_defaults_to_clean_and_omits_optionals() {
        let e = build_reputation_entity(
            EntityKind::Phone,
            "phone",
            "+15555550100",
            &parse(r#"{"success":true,"line_type":"Wireless","carrier":"Telco","active":true}"#),
            "s",
        );
        assert_eq!(attr(&e, "fraud_score"), Some("0")); // unwrap_or(0)
        assert!(!e.has_tag("high-risk") && !e.has_tag("elevated-risk"));
        assert_eq!(attr(&e, "line_type"), Some("Wireless"));
        assert_eq!(attr(&e, "carrier"), Some("Telco"));
        assert_eq!(attr(&e, "active"), Some("true"));
        // IP-only fields absent on a phone response → omitted.
        assert_eq!(attr(&e, "isp"), None);
        assert_eq!(attr(&e, "first_seen"), None);
    }
}
