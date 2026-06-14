//! XposedOrNot breach lookup — free public email-to-breach-list service.
//!
//! Endpoint: `https://api.xposedornot.com/v1/check-email/<email>`.
//! Returns the list of named breaches the email appears in (company names
//! like "MyFitnessPal", "Quizlet", etc.) — **not credentials**. Confirms
//! breach exposure without ever transmitting a password through our process.
//!
//! Breach analytics: when the check-email endpoint returns hits, the module
//! also calls `/v1/breach-analytics` to enrich with risk metrics, exposed
//! data types, and paste exposure counts. This second call is best-effort —
//! if it fails the basic breach list is still returned.
//!
//! Why a second breach source matters: the `AU-001` correlator rule
//! (multi-source breach corroboration, severity Critical) was wired up
//! in v0.4 but had been dormant — only `hudsonrock` was registered as a
//! breach source. With this module, the rule activates whenever
//! HudsonRock and XposedOrNot both flag the same email, so
//! `hse scan --kind email --value <breached>` can surface a Critical
//! correlation without any paid keys.

use async_trait::async_trait;

use crate::core::{
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{fetch_json_or_404, urlencode};

mod types;
use types::XonResp;

mod build;
use build::{build_result, fetch_analytics};

#[cfg(test)]
mod tests;

pub struct XposedOrNot;

#[async_trait]
impl Module for XposedOrNot {
    fn name(&self) -> &'static str {
        "xposed_or_not"
    }

    fn description(&self) -> &'static str {
        "Email breach lookup with analytics enrichment"
    }

    fn priority(&self) -> u8 {
        128
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }

    fn max_timeout_ms(&self) -> u64 {
        // Up to ~3 sequential network requests, none with a per-request
        // timeout. The 3s default could not cover even one slow response,
        // let alone the chain; budget for the full sequence.
        15_000
    }

    fn produces(&self) -> &'static [crate::core::entity::EntityKind] {
        use crate::core::entity::EntityKind;
        const KINDS: &[EntityKind] = &[EntityKind::Email];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let url = format!(
            "https://api.xposedornot.com/v1/check-email/{}",
            urlencode(&target.value)
        );

        let Some(data): Option<XonResp> =
            fetch_json_or_404(&ctx.http, "xposed_or_not", &url).await?
        else {
            return Ok(ModuleResult::new());
        };

        let inner = match data.breaches.as_ref().and_then(|outer| outer.first()) {
            Some(v) if !v.is_empty() => v,
            _ => return Ok(ModuleResult::new()),
        };

        let analytics = fetch_analytics(&ctx.http, &target.value).await;

        Ok(build_result(
            inner,
            analytics.as_ref(),
            target,
            &ctx.scan_id,
        ))
    }
}
