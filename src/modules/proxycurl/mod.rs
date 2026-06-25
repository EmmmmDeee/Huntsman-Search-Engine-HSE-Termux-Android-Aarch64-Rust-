//! Proxycurl LinkedIn profile extraction. Paid (Bearer Token).
//!
//! Endpoints:
//! - username / URL → `GET …/api/v2/linkedin?url=https://linkedin.com/in/{id}`
//! - email          → `GET …/api/linkedin/profile/resolve/email?work_email=…`
//!
//! Auth: Bearer Token (`HUNTSMAN_PROXYCURL_KEY`).
//!
//! Every field the paid API returns is mapped to an entity or evidence
//! attribute — nothing harvested is discarded. The field → output mapping:
//!
//! | LinkedIn field                         | Output                              |
//! |----------------------------------------|-------------------------------------|
//! | `full_name` / `first`+`last`           | `Person` (name)                     |
//! | `headline`,`occupation`,`summary`,…    | evidence attrs on the `Person`      |
//! | `city`/`state`/`country_full_name`     | `Address` (+`country:` tag)         |
//! | `experiences[].company`/`title`/dates/`location` | `Organisation` (+attrs)   |
//! | `education[].school`/`degree`/`field`  | `education` attr on the `Person`    |
//! | `personal_emails[]`                    | `Email` + derived non-freemail `Domain` |
//! | `personal_numbers[]`                   | `Phone`                             |
//!
//! The whole field→entity mapping lives in the pure [`build::build_entities`] so
//! it is unit-tested without a live API; `process` only owns URL construction,
//! auth, transport, and error mapping.

mod build;
mod types;
mod url;

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

const KEY_ENV: &str = "HUNTSMAN_PROXYCURL_KEY";
pub(super) const SRC: &str = "proxycurl";

/// Caps on per-profile output, keeping a single dump bounded.
pub(super) const MAX_EMAILS: usize = 3;
pub(super) const MAX_PHONES: usize = 3;
pub(super) const MAX_EXPERIENCES: usize = 5;
pub(super) const MAX_LISTED: usize = 3; // companies/schools surfaced inline on the Person
/// Professional `summary` is a free-text bio; cap it before persisting.
pub(super) const SUMMARY_CAP: usize = 280;

pub struct Proxycurl;

#[async_trait]
impl Module for Proxycurl {
    fn name(&self) -> &'static str {
        "proxycurl"
    }
    fn description(&self) -> &'static str {
        "LinkedIn profile extraction — employment, education, and certifications via Proxycurl"
    }
    fn priority(&self) -> u8 {
        88
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Username | TargetKind::Url | TargetKind::Email
        )
    }
    fn max_timeout_ms(&self) -> u64 {
        15_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A LinkedIn profile yields the person's name + role (the People default
        // T1589.003 + T1591.004), their employers (T1591.002 Business
        // Relationships), and their city/state location (T1591.001 Physical
        // Locations). Superset of the default — coverage cannot regress.
        &["T1589.003", "T1591.004", "T1591.002", "T1591.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Email,
            EntityKind::Domain,
            EntityKind::Phone,
            EntityKind::Organisation,
            EntityKind::Url,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };

        let Some(api_url) = url::profile_url(target) else {
            return Ok(ModuleResult::new());
        };

        let resp = ctx
            .http
            .get(&api_url)
            .bearer_auth(key)
            .header("Accept", "application/json")
            .send_tagged(SRC)
            .await?;

        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };

        // json_scanned: LinkedIn profiles include headline and summary
        // (free-form user text) that may contain embedded API keys or tokens.
        let profile: types::LinkedInProfile = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| crate::core::error::Error::module(SRC, e))?;

        Ok(build::build_entities(&profile, target, &ctx.scan_id))
    }
}
