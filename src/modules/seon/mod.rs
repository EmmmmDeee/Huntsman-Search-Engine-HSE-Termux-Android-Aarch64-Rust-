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
//!
//! Every registered platform that reports a profile URL becomes a `Url` entity
//! (a direct lead), not just a name in a CSV. The two response → entity mappings
//! live in the pure [`build_email_entities`] / [`build_phone_entities`] so they
//! are unit-tested without a live API; the `*_lookup` methods own only transport.

mod entity_builders;
mod types;

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

use entity_builders::{build_email_entities, build_phone_entities};
use types::{SeonEmailResp, SeonPhoneResp};

pub(crate) const KEY_ENV: &str = "HUNTSMAN_SEON_KEY";
pub(crate) const SRC: &str = "seon";

/// A fraud score at/above this (0–100) flags the identity high-risk.
pub(super) const HIGH_RISK_SCORE: f64 = 80.0;
/// Email platforms whose self-reported display name is worth a `Person` lead.
pub(super) const PERSON_PLATFORMS: &[&str] = &["facebook", "twitter", "linkedin", "github"];

pub struct Seon;

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

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // SEON detects an identity's presence across 250+ social/messaging
        // platforms (emitting profile Urls), so beyond the People default
        // (T1589.003 Employee Names + T1591.004 Identify Roles) it is Search
        // Open Websites/Domains: Social Media (T1593.001). Superset of the
        // default — coverage cannot regress.
        &["T1589.003", "T1591.004", "T1593.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Person, EntityKind::Url];
        KINDS
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

        let cache_key = email.to_ascii_lowercase();
        let cache = crate::core::api_cache::global();
        let body: SeonEmailResp = if let Some(cached) = cache.get(self.name(), &cache_key) {
            serde_json::from_str(&cached.body)
                .map_err(|e| crate::core::error::Error::module(SRC, format!("cache JSON: {e}")))?
        } else {
            let resp = ctx
                .http
                .post("https://api.seon.io/SeonRestService/email-api/v3")
                .header("X-API-KEY", key)
                .header("Content-Type", "application/json")
                .json(&serde_json::json!({ "email": email }))
                .send_tagged(SRC)
                .await?;

            let status = resp.status();
            if !status.is_success() {
                let code = status.as_u16();
                crate::util::http::note_keyed_error(code, SRC, key, ctx);
                return Err(crate::util::http::http_status_error(SRC, resp).await);
            }

            let text = resp
                .text()
                .await
                .map_err(|e| crate::core::error::Error::module(SRC, format!("body: {e}")))?;
            cache.put(
                self.name(),
                &cache_key,
                &text,
                crate::core::api_cache::ttl_secs(self.name()),
            );
            serde_json::from_str(&text)
                .map_err(|e| crate::core::error::Error::module(SRC, e.to_string()))?
        };

        if body.success != Some(true) {
            return Ok(ModuleResult::new());
        }
        let Some(data) = body.data else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.extend(build_email_entities(target, &data, &ctx.scan_id));
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

        let cache_key = format!("phone:{}", phone.to_lowercase());
        let phone_text: String =
            if let Some(cached) = crate::core::api_cache::global().get(SRC, &cache_key) {
                cached.body
            } else {
                let resp = ctx
                    .http
                    .post("https://api.seon.io/SeonRestService/phone-api/v2")
                    .header("X-API-KEY", key)
                    .header("Content-Type", "application/json")
                    .json(&serde_json::json!({ "phone": phone }))
                    .send_tagged(SRC)
                    .await?;

                let status = resp.status();
                if !status.is_success() {
                    let code = status.as_u16();
                    crate::util::http::note_keyed_error(code, SRC, key, ctx);
                    return Err(crate::util::http::http_status_error(SRC, resp).await);
                }
                let text = resp
                    .text()
                    .await
                    .map_err(|e| crate::core::error::Error::module(SRC, format!("body: {e}")))?;
                crate::core::api_cache::global().put(
                    SRC,
                    &cache_key,
                    &text,
                    crate::core::api_cache::ttl_secs(SRC),
                );
                text
            };
        let body: SeonPhoneResp = serde_json::from_str(&phone_text)
            .map_err(|e| crate::core::error::Error::module(SRC, format!("JSON: {e}")))?;

        if body.success != Some(true) {
            return Ok(ModuleResult::new());
        }
        let Some(data) = body.data else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.extend(build_phone_entities(target, &data, &ctx.scan_id));
        Ok(result)
    }
}
