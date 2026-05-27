//! SEON email and phone enrichment — cross-platform presence detection.
//!
//! **Email path:**
//! `POST https://api.seon.io/SeonRestService/email-api/v3`
//! Resolves email domain registration and checks presence across 250+ platforms.
//!
//! **Phone path:**
//! `POST https://api.seon.io/SeonRestService/phone-api/v2`
//! Resolves carrier details, HLR network lookup, and cross-platform presence.
//!
//! Auth: `X-API-KEY` header. Key-gated (`HUNTSMAN_SEON_KEY`).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

const KEY_ENV: &str = "HUNTSMAN_SEON_KEY";
const SRC: &str = "seon";

pub struct Seon;

#[derive(Deserialize)]
struct SeonEmailResp {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    data: Option<SeonEmailData>,
}

#[derive(Deserialize)]
struct SeonEmailData {
    #[serde(default)]
    score: Option<f64>,
    #[serde(default)]
    deliverable: Option<bool>,
    #[serde(default)]
    domain_details: Option<DomainDetails>,
    #[serde(default)]
    account_details: Option<AccountDetails>,
}

#[derive(Deserialize)]
struct DomainDetails {
    #[serde(default)]
    domain: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    registered: Option<bool>,
    #[serde(default)]
    disposable: Option<bool>,
    #[serde(default)]
    free: Option<bool>,
    #[allow(dead_code)]
    #[serde(default)]
    custom: Option<bool>,
}

#[derive(Deserialize)]
struct AccountDetails {
    #[serde(default)]
    facebook: Option<AccountPresence>,
    #[serde(default)]
    twitter: Option<AccountPresence>,
    #[serde(default)]
    linkedin: Option<AccountPresence>,
    #[serde(default)]
    instagram: Option<AccountPresence>,
    #[serde(default)]
    github: Option<AccountPresence>,
    #[serde(default)]
    google: Option<AccountPresence>,
    #[serde(default)]
    apple: Option<AccountPresence>,
    #[serde(default)]
    microsoft: Option<AccountPresence>,
    #[serde(default)]
    spotify: Option<AccountPresence>,
    #[serde(default)]
    skype: Option<AccountPresence>,
}

#[derive(Deserialize)]
struct AccountPresence {
    #[serde(default)]
    registered: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    url: Option<String>,
}

#[derive(Deserialize)]
struct SeonPhoneResp {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    data: Option<SeonPhoneData>,
}

#[derive(Deserialize)]
struct SeonPhoneData {
    #[serde(default)]
    score: Option<f64>,
    #[serde(default)]
    valid: Option<bool>,
    #[serde(default)]
    carrier: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default, rename = "type")]
    line_type: Option<String>,
    #[serde(default)]
    account_details: Option<PhoneAccountDetails>,
}

#[derive(Deserialize)]
struct PhoneAccountDetails {
    #[serde(default)]
    whatsapp: Option<AccountPresence>,
    #[serde(default)]
    viber: Option<AccountPresence>,
    #[serde(default)]
    telegram: Option<AccountPresence>,
}

#[async_trait]
impl Module for Seon {
    fn name(&self) -> &'static str {
        "seon"
    }
    fn description(&self) -> &'static str {
        "SEON email/phone enrichment — cross-platform presence across 250+ services"
    }
    fn priority(&self) -> u8 {
        95
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email | TargetKind::Phone)
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };

        match target.kind {
            TargetKind::Email => self.email_lookup(target, key, ctx).await,
            TargetKind::Phone => self.phone_lookup(target, key, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}

impl Seon {
    async fn email_lookup(
        &self,
        target: &Target,
        key: &str,
        ctx: &ModuleContext,
    ) -> Result<ModuleResult> {
        let email = target.value.trim();
        if !email.contains('@') {
            return Ok(ModuleResult::new());
        }

        let resp = ctx
            .http
            .post("https://api.seon.io/SeonRestService/email-api/v3")
            .header("X-API-KEY", key)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "email": email }))
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let code = status.as_u16();
            if code == 429 || code == 401 || code == 403 {
                ctx.report_key_exhausted(SRC, key, code);
            }
            return Err(Error::module(
                SRC,
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let body: SeonEmailResp = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        if body.success != Some(true) {
            return Ok(ModuleResult::new());
        }
        let Some(data) = body.data else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        let mut entity = target.to_entity(0.88, &ctx.scan_id);
        entity.tag("seon");

        let mut ev = Evidence::new(SRC, format!("SEON email enrichment for {email}"));
        if let Some(score) = data.score {
            ev = ev.with_attr("fraud_score", format!("{score:.1}"));
            if score >= 80.0 {
                entity.tag("high-risk");
            }
        }
        if let Some(d) = data.deliverable {
            ev = ev.with_attr("deliverable", d.to_string());
        }

        if let Some(dd) = &data.domain_details {
            if let Some(d) = dd.domain.as_deref() {
                ev = ev.with_attr("domain", d);
            }
            if dd.disposable == Some(true) {
                entity.tag("disposable");
                ev = ev.with_attr("disposable", "true");
            }
            if dd.free == Some(true) {
                entity.tag("freemail");
                ev = ev.with_attr("freemail", "true");
            }
        }

        let mut platforms: Vec<&str> = Vec::new();
        if let Some(acct) = &data.account_details {
            let checks: &[(&str, &Option<AccountPresence>)] = &[
                ("facebook", &acct.facebook),
                ("twitter", &acct.twitter),
                ("linkedin", &acct.linkedin),
                ("instagram", &acct.instagram),
                ("github", &acct.github),
                ("google", &acct.google),
                ("apple", &acct.apple),
                ("microsoft", &acct.microsoft),
                ("spotify", &acct.spotify),
                ("skype", &acct.skype),
            ];
            for (name, presence) in checks {
                if let Some(p) = presence
                    && p.registered == Some(true)
                {
                    platforms.push(name);
                }
            }
        }
        if !platforms.is_empty() {
            ev = ev.with_attr("platforms_registered", platforms.join(","));
            ev = ev.with_attr("platform_count", platforms.len().to_string());
        }

        entity.add_evidence(ev);
        result.push(entity);

        if let Some(acct) = &data.account_details {
            let named: &[(&str, &Option<AccountPresence>)] = &[
                ("facebook", &acct.facebook),
                ("twitter", &acct.twitter),
                ("linkedin", &acct.linkedin),
                ("github", &acct.github),
            ];
            for (platform, presence) in named {
                if let Some(p) = presence
                    && p.registered == Some(true)
                    && let Some(name) = p.name.as_deref()
                    && name.len() >= 3
                    && name.contains(' ')
                {
                    let mut pe = Entity::new(EntityKind::Person, name, 0.65, &ctx.scan_id);
                    pe.tag("seon");
                    pe.tag(format!("platform:{platform}"));
                    pe.add_evidence(Evidence::new(
                        SRC,
                        format!("Name from {platform} via SEON for {email}"),
                    ));
                    result.push(pe);
                    break;
                }
            }
        }

        Ok(result)
    }

    async fn phone_lookup(
        &self,
        target: &Target,
        key: &str,
        ctx: &ModuleContext,
    ) -> Result<ModuleResult> {
        let phone = target.value.trim();
        if phone.is_empty() {
            return Ok(ModuleResult::new());
        }

        let resp = ctx
            .http
            .post("https://api.seon.io/SeonRestService/phone-api/v2")
            .header("X-API-KEY", key)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "phone": phone }))
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let code = status.as_u16();
            if code == 429 || code == 401 || code == 403 {
                ctx.report_key_exhausted(SRC, key, code);
            }
            return Err(Error::module(
                SRC,
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let body: SeonPhoneResp = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        if body.success != Some(true) {
            return Ok(ModuleResult::new());
        }
        let Some(data) = body.data else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        let mut entity = target.to_entity(0.88, &ctx.scan_id);
        entity.tag("seon");

        let mut ev = Evidence::new(SRC, format!("SEON phone enrichment for {phone}"));
        if let Some(score) = data.score {
            ev = ev.with_attr("fraud_score", format!("{score:.1}"));
        }
        if let Some(v) = data.valid {
            ev = ev.with_attr("valid", v.to_string());
        }
        if let Some(c) = data.carrier.as_deref() {
            ev = ev.with_attr("carrier", c);
        }
        if let Some(c) = data.country.as_deref() {
            ev = ev.with_attr("country", c);
        }
        if let Some(cc) = data.country_code.as_deref() {
            ev = ev.with_attr("country_code", cc);
            entity.tag(format!("country:{}", cc.to_uppercase()));
        }
        if let Some(lt) = data.line_type.as_deref() {
            ev = ev.with_attr("line_type", lt);
            entity.tag(format!("line:{lt}"));
        }

        let mut msg_platforms: Vec<&str> = Vec::new();
        if let Some(acct) = &data.account_details {
            let checks: &[(&str, &Option<AccountPresence>)] = &[
                ("whatsapp", &acct.whatsapp),
                ("viber", &acct.viber),
                ("telegram", &acct.telegram),
            ];
            for (name, presence) in checks {
                if let Some(p) = presence
                    && p.registered == Some(true)
                {
                    msg_platforms.push(name);
                }
            }
        }
        if !msg_platforms.is_empty() {
            ev = ev.with_attr("messaging_platforms", msg_platforms.join(","));
        }

        entity.add_evidence(ev);
        result.push(entity);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_email_and_phone() {
        let m = Seon;
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(m.accepts(&Target::new(TargetKind::Phone, "+1234")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(Seon.cost(), ModuleCost::KeyGated));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(Seon.name(), "seon");
        assert_eq!(Seon.priority(), 95);
        assert_eq!(Seon.max_timeout_ms(), 8_000);
        assert!(!Seon.description().is_empty());
    }

    #[test]
    fn parse_email_response() {
        let raw = r#"{
            "success": true,
            "data": {
                "score": 12.5,
                "deliverable": true,
                "domain_details": {
                    "domain": "example.com",
                    "registered": true,
                    "disposable": false,
                    "free": false,
                    "custom": true
                },
                "account_details": {
                    "facebook": {"registered": true, "name": "John Doe"},
                    "twitter": {"registered": false},
                    "github": {"registered": true}
                }
            }
        }"#;
        let r: SeonEmailResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.success, Some(true));
        let data = r.data.unwrap();
        assert!((data.score.unwrap() - 12.5).abs() < 0.01);
        assert_eq!(data.deliverable, Some(true));
        let dd = data.domain_details.unwrap();
        assert_eq!(dd.disposable, Some(false));
    }
}
