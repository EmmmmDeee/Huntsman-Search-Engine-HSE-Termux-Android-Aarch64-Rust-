//! Disposable email detection via debounce.io (free, no key, unlimited).
//!
//! Endpoint: GET https://disposable.debounce.io/?email={email}
//! Auth: None.
//!
//! Tags email entities as "disposable" when they use throwaway domains
//! (mailinator, guerrillamail, etc.). Helps filter noise from expansion.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::Evidence,
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "disposable_check";

#[derive(Deserialize)]
struct Resp {
    disposable: String,
}

pub struct DisposableCheck;

#[async_trait]
impl Module for DisposableCheck {
    fn name(&self) -> &'static str {
        "disposable_check"
    }
    fn description(&self) -> &'static str {
        "Disposable/throwaway email detection via debounce.io (free, unlimited)"
    }
    fn priority(&self) -> u8 {
        97
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    fn is_passive(&self) -> bool {
        true
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let email = target.value.trim();
        if email.is_empty() || !email.contains('@') {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://disposable.debounce.io/?email={}",
            crate::util::http::urlencode(email)
        );
        let resp = ctx
            .http
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let data: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, format!("JSON: {e}")))?;

        let mut entity = target.to_entity(0.75, &ctx.scan_id);
        entity.tag("email-validated");

        if data.disposable == "true" {
            entity.tag("disposable");
            entity.confidence = 0.20;
            entity.add_evidence(
                Evidence::new(SRC, format!("{email} uses a disposable/throwaway domain"))
                    .with_attr("disposable", "true"),
            );
        } else {
            entity.add_evidence(
                Evidence::new(SRC, format!("{email} uses a legitimate email provider"))
                    .with_attr("disposable", "false"),
            );
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
    fn accepts_email_only() {
        assert!(DisposableCheck.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!DisposableCheck.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }
    #[test]
    fn cost_is_free() {
        assert!(matches!(
            DisposableCheck.cost(),
            crate::core::module::ModuleCost::Free
        ));
    }
}
